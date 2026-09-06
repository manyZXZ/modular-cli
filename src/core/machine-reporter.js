import { createHash, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { findingFingerprint, fingerprintFindings } from "./policy.js";
import { SCAN_MODULES } from "./modules.js";

export const MACHINE_REPORT_FILES = Object.freeze({
  json: "modular-results.json",
  sarif: "modular-results.sarif",
});
export const MACHINE_REPORT_LOCK_FILE = ".modular-machine-report.lock";

const MACHINE_REPORT_LOCK_MARKER = "modular-machine-report-lock-v1";
const DEFAULT_LOCK_TIMEOUT_MS = 10_000;
const DEFAULT_LOCK_STALE_MS = 5 * 60_000;

const MACHINE_SCHEMA_VERSION = 1;
const MAX_OWNERSHIP_CHECK_BYTES = 64 * 1024 * 1024;
const pendingWrites = new Map();

function normalizedPath(value) {
  return String(value ?? "").replaceAll("\\", "/").replace(/^\.\//, "");
}

function orderedResults(results) {
  const rank = new Map(SCAN_MODULES.map(({ id }, index) => [id, index]));
  return [...results].sort((left, right) => (rank.get(left.mode) ?? 99) - (rank.get(right.mode) ?? 99)
    || left.mode.localeCompare(right.mode));
}

function portableString(value, root) {
  if (!root || typeof value !== "string") return value;
  const normalizedRoot = path.resolve(root);
  const normalizedValue = path.resolve(value);
  if (value === normalizedRoot) return ".";
  if (value.startsWith(`${normalizedRoot}${path.sep}`)) return normalizedPath(path.relative(normalizedRoot, value));
  if (normalizedValue === normalizedRoot && /[\\/]/.test(value)) return ".";
  return value;
}

function portableValue(value, root, seen = new WeakMap()) {
  if (typeof value === "string") return portableString(value, root);
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return seen.get(value);
  if (Array.isArray(value)) {
    const output = [];
    seen.set(value, output);
    for (const item of value) output.push(portableValue(item, root, seen));
    return output;
  }
  const output = {};
  seen.set(value, output);
  for (const [key, item] of Object.entries(value)) output[key] = portableValue(item, root, seen);
  return output;
}

function portableResult(result) {
  const portable = portableValue(result, result.root);
  const fingerprints = fingerprintFindings(result.mode, result.findings);
  portable.root = ".";
  portable.findings = portable.findings.map((finding, index) => ({
    ...finding,
    fingerprint: finding.fingerprint ?? fingerprints[index],
    ...(finding.file ? { file: normalizedPath(finding.file) } : {}),
    suggestedFiles: (finding.suggestedFiles ?? []).map(normalizedPath),
  }));
  return portable;
}

function stableValue(value, seen = new WeakSet()) {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) throw new TypeError("Machine report data cannot contain cycles.");
  seen.add(value);
  const output = Array.isArray(value)
    ? value.map((item) => stableValue(item, seen))
    : Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key], seen)]));
  seen.delete(value);
  return output;
}

export function stableJson(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function runIdentifier(results, toolVersion) {
  const identity = orderedResults(results).map((result) => ({
    mode: result.mode,
    generatedAt: result.generatedAt,
    findings: fingerprintFindings(result.mode, result.findings)
      .map((fingerprint, index) => result.findings[index].fingerprint ?? fingerprint),
  }));
  return createHash("sha256").update(JSON.stringify([toolVersion, identity])).digest("hex");
}

function incompleteRequestedChecks(result) {
  return [["dependency-audit", result.metadata?.dependencyAudit], ["runtime", result.metadata?.runtime],
    ["source-coverage", result.metadata?.sourceCoverage?.requested ? result.metadata.sourceCoverage : null]]
    .filter(([, audit]) => audit && audit.status && !["completed", "skipped", "disabled"].includes(audit.status))
    .map(([id, audit]) => ({ id, status: audit.status }));
}

export function createJsonReport(results, { toolVersion = "unknown", complete = true, expectedModes = null } = {}) {
  if (!Array.isArray(results) || results.length === 0) throw new TypeError("A machine report requires at least one scan result.");
  const scans = orderedResults(results).map(portableResult);
  const generatedAt = scans.map((result) => result.generatedAt).sort().at(-1);
  return {
    schemaVersion: MACHINE_SCHEMA_VERSION,
    kind: "scan-results",
    tool: { name: "Modular", version: String(toolVersion) },
    run: {
      id: runIdentifier(results, toolVersion),
      generatedAt,
      modes: scans.map((result) => result.mode),
      complete: Boolean(complete) && results.every((result) => incompleteRequestedChecks(result).length === 0),
      modesComplete: Boolean(complete),
      expectedModes: expectedModes ?? scans.map((result) => result.mode),
    },
    results: scans,
  };
}

function sarifLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function artifactLocation(finding) {
  if (!finding.file || path.isAbsolute(finding.file)) return null;
  const relative = normalizedPath(finding.file);
  if (!relative || relative === ".." || relative.startsWith("../")) return null;
  return relative.split("/").map(encodeURIComponent).join("/");
}

function sarifRule(finding) {
  const standards = Array.isArray(finding.standards) ? finding.standards : [];
  const references = [...new Set([
    ...standards.map((standard) => standard.url).filter(Boolean),
    ...(finding.references ?? []),
  ])];
  const standardText = standards.map((standard) => standard.title
    ? `${standard.id} (${standard.title})`
    : standard.id).join(", ");
  const helpParts = [
    finding.recommendation ? `**Recommended change:** ${finding.recommendation}` : "",
    standardText ? `**Standards:** ${standardText}` : "",
    references.length ? `**References:** ${references.join(" · ")}` : "",
  ].filter(Boolean);
  return {
    id: finding.id,
    name: finding.id.replace(/[^A-Za-z0-9_]+/g, "_").replace(/^_+|_+$/g, "") || "modular_finding",
    shortDescription: { text: finding.title },
    ...(finding.description ? { fullDescription: { text: finding.description } } : {}),
    ...(helpParts.length ? {
      help: {
        text: [finding.recommendation, standardText, ...references].filter(Boolean).join(" | "),
        markdown: helpParts.join("\n\n"),
      },
    } : {}),
    ...(references[0] ? { helpUri: references[0] } : {}),
    properties: {
      category: finding.category,
      tags: [...new Set([...(finding.tags ?? []), finding.category])].sort(),
      precision: finding.confidence ?? "unknown",
      standards,
      references,
    },
  };
}

function sarifResult(mode, finding) {
  const fingerprint = finding.fingerprint ?? findingFingerprint(mode, finding);
  const uri = artifactLocation(finding);
  const region = Number.isSafeInteger(finding.line) && finding.line > 0
    ? { startLine: finding.line }
    : null;
  const message = finding.description ? `${finding.title}: ${finding.description}` : finding.title;
  return {
    ruleId: finding.id,
    level: sarifLevel(finding.severity),
    message: { text: message },
    ...(uri ? {
      locations: [{
        physicalLocation: {
          artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
          ...(region ? { region } : {}),
        },
      }],
    } : {}),
    partialFingerprints: {
      "primaryLocationLineHash/v1": fingerprint,
      "modular/v1": fingerprint,
    },
    ...(finding.baselineState ? { baselineState: finding.baselineState } : {}),
    ...(finding.suppression?.status === "accepted" ? {
      suppressions: [{
        kind: "external",
        status: "accepted",
        justification: finding.suppression.reason,
      }],
    } : {}),
    properties: {
      severity: finding.severity,
      confidence: finding.confidence ?? "unknown",
      category: finding.category,
      manualReview: finding.manual === true,
      recommendation: finding.recommendation ?? "",
      standards: finding.standards ?? [],
      references: finding.references ?? [],
      fingerprint,
      ...(finding.baselineChange ? { baselineChange: finding.baselineChange, previousSeverity: finding.previousSeverity } : {}),
      ...(finding.suppression?.expires ? { suppressionExpires: finding.suppression.expires } : {}),
    },
  };
}

function sarifRun(result, toolVersion) {
  const incomplete = incompleteRequestedChecks(result);
  const rules = [...new Map(result.findings.map((finding) => [finding.id, sarifRule(finding)])).values()]
    .sort((left, right) => left.id.localeCompare(right.id));
  return {
    tool: {
      driver: {
        name: "Modular",
        ...(/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(String(toolVersion))
          ? { semanticVersion: String(toolVersion) }
          : { version: String(toolVersion) }),
        rules,
      },
    },
    automationDetails: { id: `modular/${result.mode}/` },
    originalUriBaseIds: {
      "%SRCROOT%": { uri: "./" },
    },
    invocations: [{
      executionSuccessful: incomplete.length === 0,
      ...(incomplete.length ? { toolExecutionNotifications: incomplete.map(({ id, status }) => ({
        descriptor: { id: `modular.${id}-incomplete` }, level: "error",
        message: { text: `Requested ${id} did not complete (${status}).` },
      })) } : {}),
      endTimeUtc: result.generatedAt,
      properties: {
        mode: result.mode,
        filesScanned: result.filesScanned,
        ruleFamilies: result.checks,
        reviewScore: result.summary.score,
      },
    }],
    results: result.findings.map((finding) => sarifResult(result.mode, finding)),
    properties: {
      modularSchemaVersion: result.schemaVersion,
      summary: result.summary,
      policy: result.metadata?.policy ?? null,
    },
  };
}

export function createSarifReport(results, { toolVersion = "unknown", complete = true, expectedModes = null } = {}) {
  if (!Array.isArray(results) || results.length === 0) throw new TypeError("A SARIF report requires at least one scan result.");
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: orderedResults(results).map((result) => sarifRun(portableResult(result), toolVersion)),
    properties: {
      modularRun: {
        complete: Boolean(complete) && results.every((result) => incompleteRequestedChecks(result).length === 0),
        modesComplete: Boolean(complete),
        expectedModes: expectedModes ?? orderedResults(results).map((result) => result.mode),
      },
    },
  };
}

export async function isOwnedMachineReport(filePath, format = null) {
  let stat;
  try {
    stat = await fs.lstat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return true;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_OWNERSHIP_CHECK_BYTES) return false;
  let value;
  let handle;
  try {
    handle = await fs.open(filePath, "r");
    const opened = await handle.stat();
    if (!sameFileIdentity(stat, opened) || opened.size > MAX_OWNERSHIP_CHECK_BYTES) return false;
    value = JSON.parse(await handle.readFile("utf8"));
    const current = await fs.lstat(filePath);
    if (!sameFileIdentity(opened, current) || current.isSymbolicLink()) return false;
  } catch {
    return false;
  } finally {
    await handle?.close().catch(() => {});
  }
  const selected = format ?? (path.basename(filePath) === MACHINE_REPORT_FILES.sarif ? "sarif" : "json");
  if (selected === "sarif") {
    return value?.version === "2.1.0"
      && Array.isArray(value.runs)
      && value.runs.length > 0
      && value.runs.every((run) => run?.tool?.driver?.name === "Modular");
  }
  return value?.schemaVersion === MACHINE_SCHEMA_VERSION
    && value?.kind === "scan-results"
    && value?.tool?.name === "Modular";
}

function sameFileIdentity(left, right) {
  return Boolean(left && right) && left.dev === right.dev && left.ino === right.ino;
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return true;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
  }
}

function lockOption(value, fallback, name) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 0 || value > 120_000) {
    throw new TypeError(`${name} must be an integer from 0 through 120000.`);
  }
  return value;
}

async function readMachineLock(lockPath) {
  let stat;
  try {
    stat = await fs.lstat(lockPath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) return { stat, owner: null };
  let handle;
  try {
    handle = await fs.open(lockPath, "r");
    const opened = await handle.stat();
    if (!sameFileIdentity(stat, opened)) return { stat: opened, owner: null };
    const owner = JSON.parse(await handle.readFile("utf8"));
    const current = await fs.lstat(lockPath);
    if (!sameFileIdentity(opened, current)) return { stat: current, owner: null };
    const valid = owner?.marker === MACHINE_REPORT_LOCK_MARKER
      && typeof owner.token === "string"
      && owner.token.length >= 16
      && Number.isSafeInteger(owner.pid)
      && owner.pid > 0
      && typeof owner.hostname === "string"
      && owner.hostname.length > 0
      && Number.isFinite(owner.createdAt);
    return { stat: current, owner: valid ? owner : null };
  } catch {
    return { stat, owner: null };
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function recoverStaleMachineLock(lockPath, staleMs) {
  const observed = await readMachineLock(lockPath);
  if (!observed) return true;
  if (!observed.owner) return false;
  const age = Date.now() - Math.max(observed.owner.createdAt, observed.stat.mtimeMs);
  if (age < staleMs || observed.owner.hostname !== os.hostname() || processIsAlive(observed.owner.pid)) return false;
  const current = await readMachineLock(lockPath);
  if (!current
    || !sameFileIdentity(observed.stat, current.stat)
    || current.owner?.token !== observed.owner.token
    || processIsAlive(observed.owner.pid)) return false;
  try {
    await fs.unlink(lockPath);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return true;
    throw error;
  }
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function acquireMachineLock(outputDirectory, options) {
  const timeoutMs = lockOption(options.machineLockTimeoutMs, DEFAULT_LOCK_TIMEOUT_MS, "machineLockTimeoutMs");
  const staleMs = lockOption(options.machineLockStaleMs, DEFAULT_LOCK_STALE_MS, "machineLockStaleMs");
  const lockPath = path.join(outputDirectory, MACHINE_REPORT_LOCK_FILE);
  const deadline = Date.now() + timeoutMs;
  const owner = {
    marker: MACHINE_REPORT_LOCK_MARKER,
    token: randomUUID(),
    pid: process.pid,
    hostname: os.hostname(),
    createdAt: Date.now(),
  };
  let delay = 20;
  for (;;) {
    let handle;
    try {
      handle = await fs.open(lockPath, "wx", 0o600);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      if (await recoverStaleMachineLock(lockPath, staleMs)) continue;
      if (Date.now() >= deadline) {
        const timeout = new Error(`Timed out waiting for another Modular machine-report writer to release ${lockPath}.`);
        timeout.code = "MACHINE_REPORT_LOCK_TIMEOUT";
        throw timeout;
      }
      await wait(Math.min(delay, Math.max(1, deadline - Date.now())));
      delay = Math.min(200, Math.ceil(delay * 1.5));
      continue;
    }
    const stat = await handle.stat();
    try {
      await handle.writeFile(`${JSON.stringify(owner)}\n`, "utf8");
      await handle.sync();
      const current = await fs.lstat(lockPath);
      if (!current.isFile() || current.isSymbolicLink() || !sameFileIdentity(stat, current)) {
        throw new Error(`Machine-report lock changed while it was being acquired: ${lockPath}`);
      }
      return { handle, lockPath, owner, stat };
    } catch (error) {
      await handle.close().catch(() => {});
      const current = await fs.lstat(lockPath).catch(() => null);
      if (sameFileIdentity(stat, current)) await fs.unlink(lockPath).catch(() => {});
      throw error;
    }
  }
}

async function releaseMachineLock(lock) {
  await lock.handle.close();
  const current = await readMachineLock(lock.lockPath);
  if (!current
    || !sameFileIdentity(lock.stat, current.stat)
    || current.owner?.token !== lock.owner.token) {
    throw new Error(`Refusing to release a Modular machine-report lock whose ownership changed: ${lock.lockPath}`);
  }
  await fs.unlink(lock.lockPath);
}

async function withMachineLock(outputDirectory, options, callback) {
  const lock = await acquireMachineLock(outputDirectory, options);
  let value;
  let operationError;
  try {
    value = await callback();
  } catch (error) {
    operationError = error;
  }
  try {
    await releaseMachineLock(lock);
  } catch (releaseError) {
    if (operationError) {
      const detail = operationError instanceof Error ? operationError.message : String(operationError);
      throw new AggregateError([operationError, releaseError], `Machine-report publication failed and its lock could not be released: ${detail}`, { cause: operationError });
    }
    throw releaseError;
  }
  if (operationError) throw operationError;
  return value;
}

function pathInsideOrEqual(parent, candidate) {
  const relation = path.relative(parent, candidate);
  return relation === "" || (relation !== ".." && !relation.startsWith(`..${path.sep}`) && !path.isAbsolute(relation));
}

async function prepareOutputDirectory(root, outputDirectory) {
  const lexicalRoot = path.resolve(root);
  const lexicalOutput = path.resolve(outputDirectory);
  const enforceBoundary = pathInsideOrEqual(lexicalRoot, lexicalOutput);
  let realRoot = null;
  if (enforceBoundary) {
    realRoot = await fs.realpath(lexicalRoot);
    let existing = lexicalOutput;
    for (;;) {
      try {
        await fs.lstat(existing);
        break;
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
        const parent = path.dirname(existing);
        if (parent === existing) throw error;
        existing = parent;
      }
    }
    const realExisting = await fs.realpath(existing);
    const projected = path.resolve(realExisting, path.relative(existing, lexicalOutput));
    if (!pathInsideOrEqual(realRoot, projected)) {
      throw new Error(`Machine report output escapes the repository through a symbolic link: ${outputDirectory}`);
    }
  }
  await fs.mkdir(lexicalOutput, { recursive: true });
  const stat = await fs.lstat(outputDirectory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Machine report output must be a regular directory: ${outputDirectory}`);
  }
  if (enforceBoundary) {
    const realOutput = await fs.realpath(outputDirectory);
    if (!pathInsideOrEqual(realRoot, realOutput)) {
      throw new Error(`Machine report output escapes the repository through a symbolic link: ${outputDirectory}`);
    }
  }
}

async function stagedRecord(target, content, format) {
  if (!await isOwnedMachineReport(target, format)) {
    throw new Error(`Refusing to replace a machine-report file not generated by Modular: ${target}`);
  }
  const temporary = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${randomUUID()}.tmp`);
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(content, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  return { target, temporary, backup: null, promoted: false, format };
}

async function commitRecords(records) {
  let committed = false;
  try {
    for (const record of records) {
      try {
        await fs.lstat(record.target);
        const backup = `${record.target}.${process.pid}.${randomUUID()}.backup`;
        await fs.rename(record.target, backup);
        record.backup = backup;
        if (!await isOwnedMachineReport(record.backup, record.format)) {
          await fs.rename(record.backup, record.target);
          record.backup = null;
          throw new Error(`Machine-report ownership changed during publication: ${record.target}`);
        }
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
      await fs.rename(record.temporary, record.target);
      record.promoted = true;
    }
    committed = true;
  } catch (error) {
    const recoveryErrors = [];
    for (const record of [...records].reverse()) {
      if (record.promoted) {
        try {
          await fs.rm(record.target, { force: true });
          record.promoted = false;
        } catch (recoveryError) {
          recoveryErrors.push(recoveryError);
        }
      }
      if (record.backup) {
        try {
          await fs.rename(record.backup, record.target);
          record.backup = null;
        } catch (recoveryError) {
          recoveryErrors.push(recoveryError);
        }
      }
    }
    if (recoveryErrors.length > 0) {
      const backups = records.filter((record) => record.backup).map((record) => record.backup);
      const recoveryNotice = backups.length ? ` Recovery backup paths: ${backups.join(", ")}.` : "";
      throw new AggregateError(
        [error, ...recoveryErrors],
        `Machine-report transaction failed and could not be fully rolled back: ${error instanceof Error ? error.message : String(error)}.${recoveryNotice}`,
        { cause: error },
      );
    }
    throw error;
  } finally {
    for (const record of records) {
      await fs.rm(record.temporary, { force: true }).catch(() => {});
      // On failure the restore loop clears only backups it actually recovered.
      if (committed && record.backup) await fs.rm(record.backup, { force: true }).catch(() => {});
    }
  }
}

async function serialize(outputDirectory, callback) {
  const key = process.platform === "win32" ? path.resolve(outputDirectory).toLowerCase() : path.resolve(outputDirectory);
  const previous = pendingWrites.get(key) ?? Promise.resolve();
  const current = previous.catch(() => {}).then(callback);
  pendingWrites.set(key, current);
  try {
    return await current;
  } finally {
    if (pendingWrites.get(key) === current) pendingWrites.delete(key);
  }
}

export async function writeMachineReports(results, {
  outputDirectory,
  formats = [],
  toolVersion = "unknown",
  complete = true,
  expectedModes = null,
  machineLockTimeoutMs,
  machineLockStaleMs,
} = {}) {
  if (!Array.isArray(results) || results.length === 0) {
    throw new TypeError("Machine reports require at least one scan result.");
  }
  if (!Array.isArray(formats)) throw new TypeError("Machine report formats must be an array.");
  const selected = [...new Set(formats)].sort();
  if (selected.some((format) => !Object.hasOwn(MACHINE_REPORT_FILES, format))) {
    throw new TypeError("Machine report formats must be json or sarif.");
  }
  if (selected.length === 0) return [];
  if (!outputDirectory) throw new TypeError("Machine report outputDirectory is required.");
  const directory = path.resolve(outputDirectory);
  return serialize(directory, async () => {
    await prepareOutputDirectory(results[0]?.root, directory);
    return withMachineLock(directory, { machineLockTimeoutMs, machineLockStaleMs }, async () => {
      const content = {
        json: () => stableJson(createJsonReport(results, { toolVersion, complete, expectedModes })),
        sarif: () => stableJson(createSarifReport(results, { toolVersion, complete, expectedModes })),
      };
      const records = [];
      try {
        for (const format of selected) {
          const target = path.join(directory, MACHINE_REPORT_FILES[format]);
          records.push(await stagedRecord(target, content[format](), format));
        }
        await commitRecords(records);
      } catch (error) {
        await Promise.all(records.map((record) => fs.rm(record.temporary, { force: true }).catch(() => {})));
        throw error;
      }
      return records.map((record) => record.target);
    });
  });
}
