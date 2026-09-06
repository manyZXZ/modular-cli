import { constants as fsConstants, promises as fs } from "node:fs";
import path from "node:path";
import { collectFiles } from "../core/files.js";
import { detectWebProject } from "../core/project.js";
import { EXIT, setExitCode, throwIfInterrupted } from "./errors.js";
import { isInside, reportDirectoryDisplay } from "./paths.js";

function supportedNodeVersion(value) {
  const [major = 0, minor = 0] = String(value).split(".").map(Number);
  return major > 22 || (major === 22 && minor >= 12);
}

async function nearestExistingDirectory(target) {
  let candidate = path.resolve(target);
  for (;;) {
    try {
      const stat = await fs.stat(candidate);
      if (!stat.isDirectory()) candidate = path.dirname(candidate);
      return candidate;
    } catch (error) {
      if (error?.code !== "ENOENT" && error?.code !== "ENOTDIR") throw error;
      const parent = path.dirname(candidate);
      if (parent === candidate) throw error;
      candidate = parent;
    }
  }
}

export async function runDoctor(options, ui, runtime, baseline) {
  let healthy = true;
  const nodeVersion = runtime.nodeVersion ?? process.versions.node;
  if (supportedNodeVersion(nodeVersion)) ui.success(`Node.js ${nodeVersion} satisfies the >=22.12 runtime baseline.`);
  else {
    ui.failure(`Node.js ${nodeVersion} is unsupported; install Node.js 22.12 or later.`);
    healthy = false;
  }
  ui.success(`Repository root is accessible: ${options.root}`);
  if (options.loadedConfig) ui.success(`Configuration is valid: ${reportDirectoryDisplay(options.root, options.loadedConfig)}`);
  else ui.info(options.configDisabled ? "Project configuration discovery is disabled." : "No .modular.json configuration was found; CLI defaults apply.");
  if (baseline) ui.success(`Baseline is valid: ${baseline.entries.length} fingerprint${baseline.entries.length === 1 ? "" : "s"}.`);
  else ui.info("No baseline is configured; regression-only CI gating is unavailable.");

  try {
    const writable = await nearestExistingDirectory(options.output);
    await fs.access(writable, fsConstants.W_OK);
    ui.success(`Report target is dedicated and its nearest existing parent is writable: ${reportDirectoryDisplay(options.root, options.output)}`);
  } catch (error) {
    ui.failure(`Report target is not writable: ${error instanceof Error ? error.message : String(error)}`);
    healthy = false;
  }

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
  if (Number(inventory.skipped?.limit ?? 0) > 0 || Number(inventory.skipped?.totalBytes ?? 0) > 0) {
    ui.failure("Repository discovery exceeds the configured file or readable-byte safety budget.");
    healthy = false;
  } else {
    ui.success(`Repository discovery completed for ${inventory.files.length} inventoried file${inventory.files.length === 1 ? "" : "s"}.`);
  }
  const gaps = Number(inventory.skipped?.large ?? 0)
    + Number(inventory.skipped?.inaccessible ?? 0)
    + Number(inventory.skipped?.links ?? 0);
  if (gaps > 0) ui.warning(`${gaps} oversized, inaccessible or linked entr${gaps === 1 ? "y is" : "ies are"} recorded as coverage limitations.`);

  const detect = runtime.detectWebProject ?? detectWebProject;
  const detection = await detect({ root: options.root, files: inventory.files });
  throwIfInterrupted(runtime.signal);
  if (detection.isWebsite) {
    const confidence = Number.isFinite(detection.confidence) ? `, ${Math.round(detection.confidence * 100)}% confidence` : "";
    ui.success(`Website gate passed${detection.framework ? `: ${detection.framework}` : ""}${confidence}.`);
  } else {
    ui.failure("Website gate failed: run Modular from a supported frontend/static-site repository root.");
    healthy = false;
  }

  if (options.machineFormats.length > 0) {
    ui.success(`Machine-report policy enabled: ${options.machineFormats.join(", ")}.`);
  }
  if (options.suppressions.length > 0) {
    const today = new Date().toISOString().slice(0, 10);
    const expired = options.suppressions.filter((item) => item.expires && item.expires < today).length;
    if (expired > 0) {
      ui.warning(`${expired} configured suppression${expired === 1 ? " is" : "s are"} expired and will not apply.`);
    } else {
      ui.success(`${options.suppressions.length} suppression polic${options.suppressions.length === 1 ? "y is" : "ies are"} structurally valid.`);
    }
  }
  if (healthy) ui.success("Doctor completed: Modular is ready to scan this repository.");
  else ui.failure("Doctor found blocking readiness problems.");
  return setExitCode(healthy ? EXIT.ok : EXIT.failed, runtime);
}
