import { sanitizeEvidence } from "../../core/sanitize.js";
import { normalizeName, unique, truncate, packageLine } from "./shared.js";
import { dependencyAuditPrivacyBlockReason } from "./audit-privacy.js";
import { parseAuditPayload, isExpectedAuditTermination, auditFailureReason } from "./audit-payload.js";
import { runExecFile, resolveAuditInvocation, createAuditSandbox, isolatedAuditEnvironment } from "./audit-runtime.js";

const AUDIT_LOCKFILES_BY_MANAGER = Object.freeze({
  // npm gives shrinkwrap precedence when both files exist, so mirror the graph
  // that npm itself would install instead of relying on collector ordering.
  npm: Object.freeze(["npm-shrinkwrap.json", "package-lock.json"]),
  pnpm: Object.freeze(["pnpm-lock.yaml"]),
  yarn: Object.freeze(["yarn.lock"]),
  bun: Object.freeze(["bun.lock", "bun.lockb"]),
});

function auditCommandForManager(manager, lockfile, packageData) {
  if (manager === "npm") {
    return { manager, args: ["audit", "--json", "--ignore-scripts"], lockfile };
  }
  if (manager === "pnpm") {
    return { manager, args: ["audit", "--json", "--ignore-scripts", "--ignore-pnpmfile"], lockfile };
  }
  if (manager === "yarn") {
    const yarnVersion = String(packageData?.packageManager ?? "").match(/^yarn@(\d+)/i)?.[1];
    return {
      ...(Number(yarnVersion) >= 2
        ? { manager, args: ["npm", "audit", "--all", "--json"], lockfile }
        : { manager, args: ["audit", "--json", "--ignore-scripts"], lockfile }),
      disabledReason: "was not run because Yarn global configuration and plugin isolation cannot be guaranteed",
    };
  }
  return {
    manager: "bun",
    args: ["audit", "--json"],
    lockfile,
    disabledReason: "was not run because Bun global configuration and preload isolation cannot be guaranteed",
  };
}

function selectAuditCommand(lockfiles, packageData) {
  const candidates = [];
  for (const [manager, names] of Object.entries(AUDIT_LOCKFILES_BY_MANAGER)) {
    const lockfile = names
      .map((name) => lockfiles.find((file) => normalizeName(file) === name))
      .find(Boolean);
    if (lockfile) candidates.push({ manager, lockfile });
  }
  if (candidates.length === 0) return null;

  const packageManager = typeof packageData?.packageManager === "string"
    ? packageData.packageManager.trim()
    : "";
  const declaration = packageManager.match(/^([A-Za-z][A-Za-z0-9_-]*)@[^\s]+$/);
  if (packageManager) {
    if (!declaration) {
      return {
        manager: "package-manager",
        args: [],
        lockfile: candidates[0].lockfile,
        disabledReason: "was not run because package.json has an invalid packageManager declaration; declare a supported manager and version",
      };
    }
    const declaredManager = declaration[1].toLowerCase();
    if (!Object.hasOwn(AUDIT_LOCKFILES_BY_MANAGER, declaredManager)) {
      return {
        manager: "package-manager",
        args: [],
        lockfile: candidates[0].lockfile,
        disabledReason: "was not run because package.json declares a package manager that Modular cannot audit in isolation",
      };
    }
    const selected = candidates.find((candidate) => candidate.manager === declaredManager);
    if (!selected) {
      const expected = AUDIT_LOCKFILES_BY_MANAGER[declaredManager].join(" or ");
      return {
        manager: declaredManager,
        args: [],
        lockfile: candidates[0].lockfile,
        disabledReason: `was not run because package.json declares ${declaredManager}, but no matching ${expected} lockfile is present; refusing to audit a stale lockfile from another package manager`,
      };
    }
    return auditCommandForManager(selected.manager, selected.lockfile, packageData);
  }

  if (candidates.length > 1) {
    return {
      manager: candidates.map((candidate) => candidate.manager).join("/"),
      args: [],
      lockfile: candidates[0].lockfile,
      disabledReason: "was not run because multiple package-manager lockfiles are present and package.json does not declare which packageManager owns the dependency graph",
    };
  }
  return auditCommandForManager(candidates[0].manager, candidates[0].lockfile, packageData);
}

/** Run opted-in advisory checks and return their coverage state to the scanner. */
export async function runDependencyAudit({
  root, options, manifestRecords, dependencies, allReadableContents, inputFiles, addFinding, onProgress,
}) {
  const auditEnabled = options.auditDependencies === true
    && options.noDependencyAudit !== true
    && options.dependencyAudit !== false;
  let dependencyAudit = {
    status: auditEnabled ? "not-applicable" : "skipped",
    reason: auditEnabled ? "No supported workspace manifest and lockfile pair was found." : "disabled (opt in with auditDependencies: true)",
    isolation: "sanitized manifest and selected lockfile in a temporary directory",
  };
  const auditContexts = manifestRecords.filter((record) => (
    record.dependencies.size > 0 || (record.directory === "" && dependencies.size > 0)
  ) && record.directLockfiles.length > 0);
  const auditResults = [];
  const enabledAuditContexts = auditEnabled ? auditContexts : [];
  for (let auditIndex = 0; auditIndex < enabledAuditContexts.length; auditIndex += 1) {
    const auditContext = enabledAuditContexts[auditIndex];
    const auditCommand = selectAuditCommand(auditContext.directLockfiles, auditContext.manifest);
    if (!auditCommand) continue;
    const requestedTimeout = Number(options.dependencyAuditTimeoutMs ?? 20_000);
    const timeout = Number.isFinite(requestedTimeout)
      ? Math.max(1_000, Math.min(30_000, Math.floor(requestedTimeout)))
      : 20_000;
    if (onProgress) {
      await Promise.resolve(onProgress({
        phase: "Dependency audit",
        current: auditIndex,
        total: enabledAuditContexts.length,
        file: auditCommand.lockfile.relative,
        check: "dependency-audit",
        status: "running",
        manager: auditCommand.manager,
      }));
    }
    const auditStartedAt = Date.now();
    let sandbox = null;
    let execution;
    try {
      const privacyBlockReason = dependencyAuditPrivacyBlockReason(auditContext, allReadableContents, inputFiles);
      if (auditCommand.disabledReason) {
        execution = {
          error: Object.assign(new Error(auditCommand.disabledReason), { code: "AUDIT_MANAGER_ISOLATION_UNSUPPORTED" }),
          stdout: "",
          stderr: "",
        };
      } else if (privacyBlockReason) {
        execution = {
          error: Object.assign(new Error(privacyBlockReason), { code: "AUDIT_PRIVACY_BLOCKED" }),
          stdout: "",
          stderr: "",
        };
      } else {
        const invocation = await resolveAuditInvocation(auditCommand.manager, auditCommand.args, root);
        if (!invocation) {
          execution = {
            error: Object.assign(new Error(`${auditCommand.manager} executable could not be resolved without a shell.`), { code: "ENOENT" }),
            stdout: "",
            stderr: "",
          };
        } else {
          sandbox = await createAuditSandbox(root, auditContext, auditCommand);
          execution = await runExecFile(invocation.command, invocation.args, {
            cwd: sandbox.cwd,
            windowsHide: true,
            timeout,
            killSignal: "SIGTERM",
            maxBuffer: 512 * 1024,
            encoding: "utf8",
            env: isolatedAuditEnvironment(invocation, sandbox),
          });
        }
      }
    } catch (error) {
      execution = { error, stdout: "", stderr: "" };
    } finally {
      if (sandbox) await sandbox.cleanup().catch(() => {});
    }
    const parsed = parseAuditPayload(auditCommand.manager, execution.stdout);
    const elapsedMs = Date.now() - auditStartedAt;
    const exitCode = typeof execution.error?.code === "number" ? execution.error.code : (execution.error ? null : 0);
    const auditFailed = !parsed.recognized || !isExpectedAuditTermination(auditCommand.manager, execution.error);
    let auditResult;

    if (auditFailed) {
      const reason = auditFailureReason(auditCommand.manager, execution, parsed, timeout);
      const detail = sanitizeEvidence(
        execution.stderr
        || execution.error?.message
        || (!parsed.recognized ? execution.stdout : "")
        || "No diagnostic output was returned.",
      );
      auditResult = {
        status: "unavailable",
        manager: auditCommand.manager,
        workspace: auditContext.directory || ".",
        lockfile: auditCommand.lockfile.relative,
        isolated: true,
        durationMs: elapsedMs,
        exitCode,
        reason,
        detail,
      };
      addFinding("dependency-audit-unavailable", {
        title: "Dependency advisory audit could not run",
        category: "Supply Chain",
        severity: "info",
        confidence: "high",
        manual: true,
        description: `The ${auditCommand.manager} advisory audit ${reason}. Static repository checks still completed, but known vulnerable installed versions were not verified.`,
        recommendation: `Restore package-manager and registry access, then run ${auditCommand.manager} audit locally and rerun Modular.`,
        evidence: detail || `${auditCommand.manager} audit was unavailable.`,
        file: auditContext.entry.file.relative,
        line: 1,
        suggestedFiles: [auditContext.entry.file.relative, ...auditContext.directLockfiles.map((file) => file.relative)],
        tags: ["dependencies", "advisory", "manual-review"],
      });
    } else {
      auditResult = {
        status: "completed",
        manager: auditCommand.manager,
        workspace: auditContext.directory || ".",
        lockfile: auditCommand.lockfile.relative,
        isolated: true,
        durationMs: elapsedMs,
        exitCode,
        summary: parsed.summary ?? { total: parsed.records.length },
        advisoriesReported: parsed.records.length,
      };
      for (const advisory of parsed.records) {
        const packageName = truncate(advisory.name, 100) || "dependency";
        const affectedRange = advisory.range ? truncate(advisory.range, 100) : "reported installed range";
        let fix = "Update the dependency graph to a non-vulnerable version, regenerate the lockfile, run tests, and repeat the advisory audit.";
        if (typeof advisory.fixAvailable === "string" && advisory.fixAvailable.trim()) {
          fix = `Upgrade to a release outside the affected range (the audit reports patched versions ${truncate(advisory.fixAvailable, 80)}), regenerate the lockfile, and run tests.`;
        } else if (advisory.fixAvailable && typeof advisory.fixAvailable === "object" && advisory.fixAvailable.version) {
          fix = `Upgrade ${packageName} to ${truncate(advisory.fixAvailable.version, 40)}, regenerate the lockfile, and run tests; review breaking changes if the update is major.`;
        }
        addFinding("dependency-advisory", {
          title: `Installed dependency has a ${advisory.severity} advisory`,
          category: "Supply Chain",
          severity: advisory.severity,
          confidence: "high",
          description: `${auditCommand.manager} reports that ${packageName}${advisory.direct ? " (a direct dependency)" : ""} is affected in ${affectedRange}.`,
          recommendation: fix,
          evidence: `${packageName}: ${advisory.severity} advisory; affected range ${affectedRange}`,
          file: auditContext.entry.file.relative,
          line: packageLine(auditContext.entry.text, advisory.name),
          suggestedFiles: [auditContext.entry.file.relative, ...auditContext.directLockfiles.map((file) => file.relative)],
          tags: ["dependencies", "advisory", "supply-chain"],
        });
      }

      const reportedTotal = Number(parsed.summary?.total ?? 0);
      if (reportedTotal > 0 && parsed.records.length === 0) {
        const severity = Number(parsed.summary?.critical ?? 0) > 0
          ? "critical"
          : Number(parsed.summary?.high ?? 0) > 0 ? "high" : "medium";
        addFinding("dependency-advisory", {
          title: "Package manager reports vulnerable dependencies",
          category: "Supply Chain",
          severity,
          confidence: "high",
          description: `${auditCommand.manager} reports ${reportedTotal} vulnerable dependency entr${reportedTotal === 1 ? "y" : "ies"}, but did not provide package-level details in a recognized format.`,
          recommendation: `Run ${auditCommand.manager} audit directly, upgrade affected packages, regenerate the lockfile, run tests, and repeat the audit.`,
          evidence: `Advisory summary: critical=${Number(parsed.summary?.critical ?? 0)}, high=${Number(parsed.summary?.high ?? 0)}, moderate=${Number(parsed.summary?.moderate ?? parsed.summary?.medium ?? 0)}, low=${Number(parsed.summary?.low ?? 0)}`,
          file: auditContext.entry.file.relative,
          line: 1,
          suggestedFiles: [auditContext.entry.file.relative, ...auditContext.directLockfiles.map((file) => file.relative)],
          tags: ["dependencies", "advisory", "supply-chain"],
        });
      }
    }
    auditResults.push(auditResult);
    if (onProgress) {
      await Promise.resolve(onProgress({
        phase: "Dependency audit",
        current: auditIndex + 1,
        total: enabledAuditContexts.length,
        file: auditCommand.lockfile.relative,
        check: "dependency-audit",
        status: auditResult.status,
        manager: auditCommand.manager,
      }));
    }
  }
  if (auditEnabled && auditResults.length > 0) {
    const unavailable = auditResults.filter((result) => result.status === "unavailable").length;
    dependencyAudit = {
      status: unavailable === 0 ? "completed" : unavailable === auditResults.length ? "unavailable" : "partial",
      isolation: "sanitized manifest and selected lockfile in a temporary directory",
      audits: auditResults,
      workspacesAudited: auditResults.length,
      managers: unique(auditResults.map((result) => result.manager)),
    };
    if (auditResults.length === 1) {
      dependencyAudit.manager = auditResults[0].manager;
      dependencyAudit.workspace = auditResults[0].workspace;
      dependencyAudit.summary = auditResults[0].summary;
    }
  }

  return { dependencyAudit, auditEnabled, auditContexts };
}
