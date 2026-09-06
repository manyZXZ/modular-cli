function normalizeSeverity(value) {
  const severity = String(value ?? "").toLowerCase();
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "moderate" || severity === "medium") return "medium";
  if (severity === "low") return "low";
  return "info";
}

export function parseAuditPayload(manager, output) {
  const documents = [];
  const trimmed = output.trim();
  if (!trimmed) return { records: [], summary: null, recognized: false };
  try {
    documents.push(JSON.parse(trimmed));
  } catch {
    for (const line of trimmed.split(/\r?\n/)) {
      if (!line.trim().startsWith("{")) continue;
      try {
        documents.push(JSON.parse(line));
      } catch {
        // Some package managers mix progress messages into their JSON stream.
      }
    }
  }

  const records = [];
  let summary = null;
  let recognized = false;
  for (const document of documents) {
    if (!document || typeof document !== "object") continue;
    if (document.metadata?.vulnerabilities && typeof document.metadata.vulnerabilities === "object") {
      summary = { ...document.metadata.vulnerabilities };
      recognized = true;
    }
    if (document.vulnerabilities && typeof document.vulnerabilities === "object") {
      recognized = true;
      for (const [name, details] of Object.entries(document.vulnerabilities)) {
        if (!details || typeof details !== "object") continue;
        records.push({
          name,
          severity: normalizeSeverity(details.severity),
          range: typeof details.range === "string" ? details.range : null,
          direct: details.isDirect === true,
          fixAvailable: details.fixAvailable,
        });
      }
    }
    if (document.advisories && typeof document.advisories === "object") {
      recognized = true;
      for (const advisory of Object.values(document.advisories)) {
        if (!advisory || typeof advisory !== "object") continue;
        records.push({
          name: advisory.module_name ?? advisory.moduleName ?? "dependency",
          severity: normalizeSeverity(advisory.severity),
          range: advisory.vulnerable_versions ?? advisory.vulnerableVersions ?? null,
          direct: advisory.findings?.some?.((finding) => finding?.paths?.some?.((entry) => !String(entry).includes(">"))) === true,
          fixAvailable: advisory.patched_versions ?? advisory.patchedVersions ?? null,
        });
      }
    }
    if (document.type === "auditAdvisory" && document.data?.advisory) {
      const advisory = document.data.advisory;
      recognized = true;
      records.push({
        name: advisory.module_name ?? "dependency",
        severity: normalizeSeverity(advisory.severity),
        range: advisory.vulnerable_versions ?? null,
        direct: document.data.resolution?.path && !String(document.data.resolution.path).includes(">"),
        fixAvailable: advisory.patched_versions ?? null,
      });
    }
    if (document.type === "auditSummary" && document.data?.vulnerabilities) {
      summary = { ...document.data.vulnerabilities };
      recognized = true;
    }
  }

  const uniqueRecords = [];
  const seen = new Set();
  for (const record of records) {
    const key = `${record.name}:${record.severity}:${record.range ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    uniqueRecords.push(record);
  }
  if (!summary && uniqueRecords.length > 0) {
    summary = { critical: 0, high: 0, moderate: 0, low: 0, info: 0, total: uniqueRecords.length };
    for (const record of uniqueRecords) {
      const key = record.severity === "medium" ? "moderate" : record.severity;
      summary[key] = Number(summary[key] ?? 0) + 1;
    }
  }
  return { manager, records: uniqueRecords, summary, recognized };
}

export function isExpectedAuditTermination(manager, error) {
  if (!error) return true;
  if (error.killed || error.signal) return false;
  const expectedNonZeroExitCodes = {
    npm: new Set([1]),
    pnpm: new Set([1]),
  };
  return typeof error.code === "number" && expectedNonZeroExitCodes[manager]?.has(error.code) === true;
}

export function auditFailureReason(manager, execution, parsed, timeout) {
  const error = execution.error;
  if (error?.killed || error?.code === "ETIMEDOUT") return `timed out after ${timeout} ms`;
  if (error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return "exceeded the 512 KiB audit output limit";
  if (error?.signal) return `was terminated by signal ${error.signal}`;
  if (error?.code === "ENOENT") return `${manager} is not installed or is not on PATH`;
  if (["AUDIT_PRIVACY_BLOCKED", "AUDIT_LOCKFILE_TOO_LARGE", "AUDIT_MANAGER_ISOLATION_UNSUPPORTED"].includes(error?.code)) {
    return error.message;
  }
  if (typeof error?.code === "number") return `exited with unexpected status ${error.code}`;
  if (error) return "could not complete";
  if (!parsed.recognized) return "returned no recognized advisory report";
  return "could not complete";
}
