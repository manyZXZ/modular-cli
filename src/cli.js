import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { collectFiles } from "./core/files.js";
import { SCAN_MODULES, getScanModule } from "./core/modules.js";
import { writeMachineReports } from "./core/machine-reporter.js";
import { applyFindingPolicy, findingsAtOrAbove, loadBaseline, writeBaseline } from "./core/policy.js";
import { detectWebProject } from "./core/project.js";
import { writeScanReports } from "./core/reporter.js";
import { TerminalUI, terminalText } from "./core/ui.js";
import { parseCliArguments, usage } from "./cli/arguments.js";
import { applyProjectConfiguration } from "./cli/configuration.js";
import { runDoctor } from "./cli/doctor.js";
import { EXIT, CliError, CliInterrupt, setExitCode, throwIfInterrupted } from "./cli/errors.js";
import {
  findOtherGeneratedReportDirectories,
  isInside,
  reportDirectoryDisplay,
  validateOutputTarget,
  validateRoot,
  withReportDirectoryContext,
} from "./cli/paths.js";
import { mergeSiteAndRuntime, runRequestedRuntimeAudit } from "./cli/runtime.js";

async function packageVersion() {
  const currentFile = fileURLToPath(import.meta.url);
  const packagePath = path.resolve(path.dirname(currentFile), "..", "package.json");
  const pkg = JSON.parse(await fs.readFile(packagePath, "utf8"));
  return pkg.version;
}

async function loadScanner(mode) {
  return getScanModule(mode).load();
}

function scanModes(mode) {
  return mode === "all" ? SCAN_MODULES.map(({ id }) => id) : [mode];
}

function scanTitle(mode) {
  return getScanModule(mode).title;
}

function shouldFail(result, threshold) {
  return findingsAtOrAbove(result, threshold).length > 0;
}

export async function runCli(argv, runtime = {}) {
  const stdout = runtime.stdout ?? process.stdout;
  const stderr = runtime.stderr ?? process.stderr;
  let options;
  try {
    options = parseCliArguments(argv);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    stderr.write(`${terminalText(message)}\n${usage()}`);
    return setExitCode(error.exitCode ?? EXIT.usage, runtime);
  }

  if (options.help) {
    stdout.write(usage());
    return setExitCode(EXIT.ok, runtime);
  }
  if (options.version) {
    stdout.write(`${await packageVersion()}\n`);
    return setExitCode(EXIT.ok, runtime);
  }

  const ui = new TerminalUI({ stream: stdout, errorStream: stderr, color: options.color, quiet: options.quiet });
  const completedReportPaths = new Set();
  try {
    throwIfInterrupted(runtime.signal);
    await validateRoot(options.root);
    throwIfInterrupted(runtime.signal);
    options = await applyProjectConfiguration(options, runtime);
    throwIfInterrupted(runtime.signal);
    await validateOutputTarget(options.output);
    throwIfInterrupted(runtime.signal);
    ui.banner();
    ui.heading(options.command === "doctor"
      ? "Environment doctor"
      : options.mode === "all" ? "Complete website check" : scanTitle(options.mode), options.root);
    if (options.loadedConfig && options.command !== "doctor") ui.info(`Policy configuration: ${reportDirectoryDisplay(options.root, options.loadedConfig)}`);
    const baselineReader = runtime.loadBaseline ?? loadBaseline;
    let baseline = null;
    if (options.baseline) {
      try {
        baseline = await baselineReader(options.baseline, {
          root: options.baselineFromConfig ? options.root : null,
        });
      } catch (error) {
        throw new CliError(error instanceof Error ? error.message : String(error));
      }
      if (options.command !== "doctor") ui.info(`Baseline loaded: ${baseline.entries.length} fingerprint${baseline.entries.length === 1 ? "" : "s"}.`);
    }
    if (options.command === "doctor") return await runDoctor(options, ui, runtime, baseline);
    ui.info("Discovering repository files…");

    const collect = runtime.collectFiles ?? collectFiles;
    const inventory = await collect(options.root, {
      maxFiles: options.maxFiles,
      maxFileBytes: options.maxFileBytes,
      maxTotalBytes: options.maxTotalBytes,
      ignore: options.ignore,
      excludeDirectories: isInside(options.root, options.output) ? [options.output] : [],
      signal: runtime.signal,
    });
    throwIfInterrupted(runtime.signal);
    const otherGeneratedReportDirectories = await findOtherGeneratedReportDirectories(inventory.files, options.output);
    if (otherGeneratedReportDirectories.length > 0) {
      const examples = otherGeneratedReportDirectories
        .slice(0, 3)
        .map((directory) => reportDirectoryDisplay(options.root, directory))
        .join(", ");
      const remainder = otherGeneratedReportDirectories.length > 3
        ? ` and ${otherGeneratedReportDirectories.length - 3} more`
        : "";
      ui.warning(
        `${otherGeneratedReportDirectories.length} other Modular-generated report director${otherGeneratedReportDirectories.length === 1 ? "y was" : "ies were"} found (${examples}${remainder}). They are not updated by this run and may be stale; current output is ${reportDirectoryDisplay(options.root, options.output)}.`,
      );
    }
    if (Number(inventory.skipped?.limit ?? 0) > 0) {
      throw new CliError(
        `Repository exceeds the ${options.maxFiles}-file safety limit. Increase --max-files to run an explicit complete scan.`,
        EXIT.failed,
      );
    }
    if (Number(inventory.skipped?.totalBytes ?? 0) > 0) {
      throw new CliError(
        `Repository exceeds the ${options.maxTotalBytes}-byte total readable-source safety limit. Increase --max-total-size to run an explicit complete scan.`,
        EXIT.failed,
      );
    }
    const skippedLarge = Number(inventory.skipped?.large ?? 0);
    const inaccessible = Number(inventory.skipped?.inaccessible ?? 0);
    const skippedLinks = Number(inventory.skipped?.links ?? 0);
    if (skippedLarge > 0) {
      ui.warning(`${skippedLarge} oversized file${skippedLarge === 1 ? " was" : "s were"} inventoried but not read; coverage is recorded in the report.`);
    }
    if (inaccessible > 0) {
      ui.warning(`${inaccessible} repository entr${inaccessible === 1 ? "y was" : "ies were"} inaccessible; coverage is incomplete and recorded in the report.`);
    }
    if (skippedLinks > 0) {
      ui.warning(`${skippedLinks} symbolic link${skippedLinks === 1 ? " was" : "s were"} not followed; coverage is incomplete and recorded in the report.`);
    }
    const detect = runtime.detectWebProject ?? detectWebProject;
    const detection = await detect({ root: options.root, files: inventory.files });
    throwIfInterrupted(runtime.signal);

    if (!detection.isWebsite) {
      ui.failure("Scan stopped: this repository does not appear to be a website project.");
      if (detection.reasons?.length && !options.quiet) {
        detection.reasons.forEach((reason) => stderr.write(`  - ${terminalText(reason)}\n`));
      }
      if (!options.quiet) stderr.write("  Run the command from a frontend/static-site repository root. No report was created.\n\n");
      return setExitCode(EXIT.usage, runtime);
    }

    const confidence = Number.isFinite(detection.confidence) ? ` (${Math.round(detection.confidence * 100)}% confidence)` : "";
    ui.success(`Website project detected${detection.framework ? `: ${detection.framework}` : ""}${confidence}.`);
    const modes = scanModes(options.mode);
    const writeReports = runtime.writeScanReports ?? writeScanReports;
    const results = [];

    for (let index = 0; index < modes.length; index += 1) {
      throwIfInterrupted(runtime.signal);
      const mode = modes[index];
      if (modes.length > 1) {
        ui.heading(scanTitle(mode), `Phase ${index + 1} of ${modes.length}`);
      }
      const module = getScanModule(mode);
      const injectedRunner = runtime[module.runnerKey];
      const runner = injectedRunner ?? await loadScanner(mode);
      let result = await runner({
        root: options.root,
        files: inventory.files,
        skipped: inventory.skipped,
        onProgress: (state) => {
          throwIfInterrupted(runtime.signal);
          ui.progress({
            ...state,
            phase: modes.length > 1 ? `${index + 1}/${modes.length} ${state.phase ?? scanTitle(mode)}` : state.phase,
          });
        },
        options: {
          auditDependencies: module.capabilities.dependencyAudit && options.auditDependencies,
          ...(options.maxFindingsPerRule ? { maxFindingsPerRule: options.maxFindingsPerRule } : {}),
          webDetection: detection,
          signal: runtime.signal,
        },
      });
      throwIfInterrupted(runtime.signal);

      if (module.capabilities.runtime && options.runtimeAudit) {
        ui.heading("Runtime browser audit", options.runtimeStaticDir
          ? "Isolated existing build; repository scripts remain disabled"
          : "Explicit target; disposable browser context");
        const browserResult = await runRequestedRuntimeAudit(options, ui, runtime);
        throwIfInterrupted(runtime.signal);
        result = mergeSiteAndRuntime(result, browserResult);
        if (browserResult.status !== "completed") {
          ui.warning(`Requested runtime browser audit is ${terminalText(browserResult.status ?? "unavailable")}; reports will be preserved and the command will exit with code ${EXIT.failed}.`);
        }
      }

      result = applyFindingPolicy(result, {
        baseline,
        suppressions: options.suppressions,
      });

      result = withReportDirectoryContext(
        result,
        options.root,
        options.output,
        otherGeneratedReportDirectories,
      );

      const unreadable = Number(result.metadata?.unreadableFiles ?? result.metadata?.scope?.unreadableFiles ?? 0);
      result = { ...result, metadata: { ...result.metadata, sourceCoverage: {
        requested: options.failOnIncomplete,
        status: skippedLarge + inaccessible + skippedLinks + unreadable > 0 ? "partial" : "completed",
        skippedLarge, inaccessible, skippedLinks, unreadable,
      } } };
      if (unreadable > 0) {
        ui.warning(`${unreadable} inventoried file${unreadable === 1 ? " could" : "s could"} not be read and were excluded from content checks.`);
      }
      const suppressedCount = Object.values(result.metadata?.suppressedByRule ?? {})
        .reduce((total, value) => total + Number(value || 0), 0);
      if (suppressedCount > 0) {
        ui.warning(`${suppressedCount} additional repeated finding${suppressedCount === 1 ? " was" : "s were"} summarized after per-rule detail limits; counts are preserved in the report.`);
      }
      if (module.capabilities.dependencyAudit && options.auditDependencies && result.metadata?.dependencyAudit?.status !== "completed") {
        const status = terminalText(result.metadata?.dependencyAudit?.status ?? "unavailable");
        ui.warning(`Requested dependency advisory lookup is ${status}; reports will be preserved and the command will exit with code ${EXIT.failed}.`);
      }
      const policy = result.metadata?.policy;
      if (policy?.suppressions?.expired > 0) {
        ui.warning(`${policy.suppressions.expired} suppression${policy.suppressions.expired === 1 ? " has" : "s have"} expired and no longer affects policy.`);
      }
      if (policy?.suppressions?.matchedFindings > 0) {
        ui.info(`${policy.suppressions.matchedFindings} finding${policy.suppressions.matchedFindings === 1 ? " has" : "s have"} an accepted, auditable suppression.`);
      }
      if (baseline) {
        ui.info(`Baseline comparison: ${policy.baseline.newFindings} new, ${policy.baseline.unchangedFindings} unchanged.`);
      }
      ui.scanComplete(result);
      results.push(result);
      const machineWriter = runtime.writeMachineReports ?? writeMachineReports;
      const written = await writeReports(result, {
        outputDirectory: options.output,
        overviewResults: [...results],
        ...(options.machineFormats.length > 0 ? {
          afterReportCommit: async () => machineWriter(results, {
            outputDirectory: options.output,
            formats: options.machineFormats,
            toolVersion: runtime.toolVersion ?? await packageVersion(),
            complete: results.length === modes.length,
            expectedModes: modes,
          }),
        } : {}),
      });
      written.forEach((reportPath) => completedReportPaths.add(reportPath));
      throwIfInterrupted(runtime.signal);
    }

    ui.reportPaths([...completedReportPaths], options.root);

    const incompleteDependencyAudit = options.auditDependencies
      ? results.find((result) => getScanModule(result.mode).capabilities.dependencyAudit && result.metadata?.dependencyAudit?.status !== "completed")
      : null;
    if (incompleteDependencyAudit) {
      const status = terminalText(incompleteDependencyAudit.metadata?.dependencyAudit?.status ?? "unavailable");
      ui.failure(`Requested dependency advisory lookup did not complete (${status}).`);
      return setExitCode(EXIT.failed, runtime);
    }

    const incompleteRuntimeAudit = options.runtimeAudit
      ? results.find((result) => getScanModule(result.mode).capabilities.runtime && result.metadata?.runtime?.status !== "completed")
      : null;
    if (incompleteRuntimeAudit) {
      const status = terminalText(incompleteRuntimeAudit.metadata?.runtime?.status ?? "unavailable");
      ui.failure(`Requested runtime browser audit did not complete (${status}).`);
      return setExitCode(EXIT.failed, runtime);
    }

    if (options.failOnIncomplete && results.some((result) => result.metadata?.sourceCoverage?.status !== "completed")) {
      ui.failure("Requested complete source coverage was not achieved; reports were preserved.");
      return setExitCode(EXIT.failed, runtime);
    }
    if (options.writeBaseline) {
      const baselineWriter = runtime.writeBaseline ?? writeBaseline;
      const baselinePath = await baselineWriter(options.writeBaseline, results, {
        previous: baseline,
        toolVersion: runtime.toolVersion ?? await packageVersion(),
        root: options.root,
      });
      ui.success(`Baseline updated: ${reportDirectoryDisplay(options.root, baselinePath)}`);
    }

    if (results.some((result) => shouldFail(result, options.failOn))) {
      ui.failure(`CI threshold reached: at least one unsuppressed ${options.failOn}-or-higher finding across the completed scan${results.length === 1 ? "" : "s"}.`);
      return setExitCode(EXIT.threshold, runtime);
    }
    if (options.failOnNew !== "none" && results.some((result) => (
      findingsAtOrAbove(result, options.failOnNew, { newOnly: true }).length > 0
    ))) {
      ui.failure(`Baseline threshold reached: at least one new ${options.failOnNew}-or-higher unsuppressed finding.`);
      return setExitCode(EXIT.threshold, runtime);
    }
    if (options.failOnRegression !== "none" && results.some((result) =>
      findingsAtOrAbove(result, options.failOnRegression, { regressionsOnly: true }).length > 0)) {
      ui.failure(`Baseline regression threshold reached (${options.failOnRegression}).`);
      return setExitCode(EXIT.threshold, runtime);
    }

    throwIfInterrupted(runtime.signal);
    return setExitCode(EXIT.ok, runtime);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const partialNotice = completedReportPaths.size > 0
      ? ` Completed phase reports were preserved in ${options.output}.`
      : "";
    if (error instanceof CliInterrupt) {
      ui.failure(`${message}${partialNotice}`);
      if (completedReportPaths.size > 0) ui.reportPaths([...completedReportPaths], options.root);
      return setExitCode(error.exitCode, runtime);
    }
    ui.failure(`Scan failed: ${message}${partialNotice}`);
    if (completedReportPaths.size > 0) ui.reportPaths([...completedReportPaths], options.root);
    if (runtime.debug || process.env.MODULAR_DEBUG) {
      stderr.write(`${error instanceof Error && error.stack ? error.stack : message}\n`);
    }
    const exitCode = error instanceof CliError
      ? error.exitCode
      : error?.code === "NOT_A_WEBSITE" ? EXIT.usage : EXIT.failed;
    return setExitCode(exitCode, runtime);
  }
}

export { EXIT, CliError, parseCliArguments, shouldFail, usage };
