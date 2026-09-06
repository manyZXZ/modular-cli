import { createHash, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { redactSensitiveText } from "./sanitize.js";
import { createFinding } from "./model.js";
import { SCAN_MODULES } from "./modules.js";

export const BASELINE_SCHEMA_VERSION = 1;
export const BASELINE_KIND = "modular-baseline";

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info", "none"]);
const MODES = new Set(SCAN_MODULES.map(({ id }) => id));
const MAX_BASELINE_BYTES = 16 * 1024 * 1024;
const MAX_BASELINE_ENTRIES = 250_000;
const BASELINE_LOCK_MARKER = "modular-baseline-lock-v1";
const DEFAULT_BASELINE_LOCK_TIMEOUT_MS = 10_000;
const DEFAULT_BASELINE_LOCK_STALE_MS = 5 * 60_000;
const MAX_LOCK_BYTES = 4096;

function normalizedPath(value) {
  return String(value ?? "")
    .replaceAll("\\", "/")
    .replace(/^\.\//, "")
    .replace(/\/{2,}/g, "/");
}

function normalizedFingerprintText(value) {
  return String(value ?? "")
    .normalize("NFKC")
    .replace(/\r\n?/g, "\n")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * A stable identity for review findings. Line numbers are intentionally omitted
 * so harmless edits above a finding do not make it appear new. Evidence keeps
 * distinct signals from the same rule and file separate whenever it is present.
 */
export function findingFingerprint(mode, finding) {
  const identity = [
    "modular-finding-v1",
    String(mode ?? ""),
    String(finding?.id ?? ""),
    normalizedPath(finding?.file),
    normalizedFingerprintText(finding?.evidence || finding?.title),
  ];
  return createHash("sha256").update(JSON.stringify(identity)).digest("hex");
}

/** Assigns stable occurrence suffixes when the same semantic signal repeats. */
export function fingerprintFindings(mode, findings) {
  const occurrences = new Map();
  return findings.map((finding) => {
    const base = findingFingerprint(mode, finding);
    const occurrence = (occurrences.get(base) ?? 0) + 1;
    occurrences.set(base, occurrence);
    if (occurrence === 1) return base;
    return createHash("sha256")
      .update(JSON.stringify(["modular-finding-occurrence-v1", base, occurrence]))
      .digest("hex");
  });
}

/** Compact, complete policy identities; detail caps never discard CI inputs. */
export function createFindingIndex(mode) {
  const entries = [];
  const seen = new Map();
  const occurrences = new Map();
  return {
    entries,
    record(finding) {
      const base = findingFingerprint(mode, finding);
      const location = `${base}:${finding.line ?? ""}`;
      if (seen.has(location)) {
        finding.fingerprint = seen.get(location);
        return;
      }
      if (entries.length >= MAX_BASELINE_ENTRIES) {
        throw new RangeError(`Scan exceeded ${MAX_BASELINE_ENTRIES} policy observations; narrow the scan root.`);
      }
      const occurrence = (occurrences.get(base) ?? 0) + 1;
      occurrences.set(base, occurrence);
      const fingerprint = occurrence === 1 ? base : createHash("sha256")
        .update(JSON.stringify(["modular-finding-occurrence-v1", base, occurrence])).digest("hex");
      finding.fingerprint = fingerprint;
      seen.set(location, fingerprint);
      const { id, title, category, severity, confidence, manual, file, line, ruleFamily, scoreFamily } = finding;
      entries.push({ id, title, category, severity, confidence, manual, file, line, fingerprint,
        ...(ruleFamily ? { ruleFamily } : {}), ...(scoreFamily ? { scoreFamily } : {}) });
    },
  };
}

function policyCandidates(result) {
  const fingerprints = fingerprintFindings(result.mode, result.findings);
  const retained = result.findings.map((finding, index) => ({
    ...finding, fingerprint: finding.fingerprint ?? fingerprints[index],
  }));
  const candidates = new Map((result.metadata?.findingIndex ?? []).map((entry) => [entry.fingerprint,
    createFinding({ ...entry, detailOmitted: true }),
  ]));
  for (const finding of retained) candidates.set(finding.fingerprint, finding);
  return [...candidates.values()];
}

function baselineEntryKey(mode, fingerprint) {
  return `${mode}:${fingerprint}`;
}

function baselineModes(value) {
  return [...new Set([
    ...(Array.isArray(value?.modes) ? value.modes : []),
    ...(value?.entries ?? []).map((entry) => entry.mode),
  ])].sort();
}

function validateBaselineDocument(value, source = "baseline") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${source} must contain a JSON object.`);
  }
  if (value.kind !== BASELINE_KIND || value.tool?.name !== "Modular") {
    throw new TypeError(`${source} is not a Modular baseline.`);
  }
  if (value.schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new TypeError(`${source} uses unsupported baseline schema version ${String(value.schemaVersion)}.`);
  }
  if (!Array.isArray(value.entries) || value.entries.length > MAX_BASELINE_ENTRIES) {
    throw new TypeError(`${source} must contain no more than ${MAX_BASELINE_ENTRIES} entries.`);
  }

  const entries = [];
  const seen = new Set();
  for (const [index, entry] of value.entries.entries()) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError(`${source} entry ${index + 1} must be an object.`);
    }
    const mode = String(entry.mode ?? "");
    const fingerprint = String(entry.fingerprint ?? "").toLowerCase();
    if (!MODES.has(mode) || !/^[a-f0-9]{64}$/.test(fingerprint)) {
      throw new TypeError(`${source} entry ${index + 1} has an invalid mode or fingerprint.`);
    }
    const key = baselineEntryKey(mode, fingerprint);
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push({
      mode,
      fingerprint,
      ruleId: String(entry.ruleId ?? ""),
      severity: String(entry.severity ?? ""),
      file: entry.file ? normalizedPath(entry.file) : null,
      title: String(entry.title ?? ""),
    });
  }
  entries.sort((left, right) => left.mode.localeCompare(right.mode)
    || left.fingerprint.localeCompare(right.fingerprint));
  const inferredModes = [...new Set(entries.map((entry) => entry.mode))].sort();
  let modes = inferredModes;
  if (value.modes !== undefined) {
    if (!Array.isArray(value.modes) || value.modes.length > MODES.size) {
      throw new TypeError(`${source} modes must be an array containing security and/or mysite.`);
    }
    modes = [];
    const seenModes = new Set();
    for (const mode of value.modes) {
      if (typeof mode !== "string" || !MODES.has(mode) || seenModes.has(mode)) {
        throw new TypeError(`${source} modes must contain unique security and/or mysite values.`);
      }
      seenModes.add(mode);
      modes.push(mode);
    }
    if (inferredModes.some((mode) => !seenModes.has(mode))) {
      throw new TypeError(`${source} modes must include every mode represented by its entries.`);
    }
    modes.sort();
  }
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    kind: BASELINE_KIND,
    tool: { name: "Modular", version: String(value.tool.version ?? "unknown") },
    generatedAt: typeof value.generatedAt === "string" ? value.generatedAt : null,
    modes,
    entries,
    keys: new Set(entries.map((entry) => baselineEntryKey(entry.mode, entry.fingerprint))),
  };
}

function sameFileIdentity(left, right) {
  return Boolean(left && right) && left.dev === right.dev && left.ino === right.ino;
}

async function readRegularJsonRecord(filePath, maximumBytes, label) {
  let stat;
  try {
    stat = await fs.lstat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      const missing = new Error(`${label} does not exist: ${filePath}`);
      missing.code = "ENOENT";
      throw missing;
    }
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TypeError(`${label} must be a regular file and cannot be a symbolic link: ${filePath}`);
  }
  if (stat.size > maximumBytes) throw new TypeError(`${label} exceeds the ${maximumBytes}-byte safety limit.`);
  let handle;
  let opened;
  let text;
  try {
    handle = await fs.open(filePath, "r");
    opened = await handle.stat();
    if (!opened.isFile() || !sameFileIdentity(stat, opened)) {
      throw new TypeError(`${label} changed while it was being opened: ${filePath}`);
    }
    if (opened.size > maximumBytes) throw new TypeError(`${label} exceeds the ${maximumBytes}-byte safety limit.`);
    text = await handle.readFile("utf8");
    if (Buffer.byteLength(text, "utf8") > maximumBytes) {
      throw new TypeError(`${label} exceeds the ${maximumBytes}-byte safety limit.`);
    }
    const current = await fs.lstat(filePath);
    if (!current.isFile() || current.isSymbolicLink() || !sameFileIdentity(opened, current)) {
      throw new TypeError(`${label} changed while it was being read: ${filePath}`);
    }
    stat = current;
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new TypeError(`${label} changed while it was being read: ${filePath}`);
    }
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new TypeError(`${label} is not valid JSON: ${error.message}`);
  }
  return { value, stat, text };
}

async function readRegularJson(filePath, maximumBytes, label) {
  return (await readRegularJsonRecord(filePath, maximumBytes, label)).value;
}

function pathInsideOrEqual(parent, candidate) {
  const relation = path.relative(parent, candidate);
  return relation === "" || (relation !== ".." && !relation.startsWith(`..${path.sep}`) && !path.isAbsolute(relation));
}

async function nearestExistingPath(target) {
  let candidate = path.resolve(target);
  for (;;) {
    try {
      await fs.lstat(candidate);
      return candidate;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      const parent = path.dirname(candidate);
      if (parent === candidate) throw error;
      candidate = parent;
    }
  }
}

async function assertProjectedInsideRoot(root, target, label) {
  const lexicalRoot = path.resolve(root);
  const lexicalTarget = path.resolve(target);
  if (!pathInsideOrEqual(lexicalRoot, lexicalTarget)) return;
  const [realRoot, existing] = await Promise.all([fs.realpath(lexicalRoot), nearestExistingPath(lexicalTarget)]);
  const realExisting = await fs.realpath(existing);
  const projected = path.resolve(realExisting, path.relative(existing, lexicalTarget));
  if (!pathInsideOrEqual(realRoot, projected)) {
    throw new TypeError(`${label} escapes the repository through a symbolic link or junction: ${lexicalTarget}`);
  }
}

export async function loadBaseline(filePath, options = {}) {
  const resolved = path.resolve(filePath);
  if (options.root) await assertProjectedInsideRoot(options.root, resolved, "Baseline");
  const value = await readRegularJson(resolved, MAX_BASELINE_BYTES, "Baseline");
  return { ...validateBaselineDocument(value, "Baseline"), path: resolved };
}

async function loadBaselineRecord(filePath, options = {}) {
  const resolved = path.resolve(filePath);
  if (options.root) await assertProjectedInsideRoot(options.root, resolved, "Baseline");
  const record = await readRegularJsonRecord(resolved, MAX_BASELINE_BYTES, "Baseline");
  return {
    baseline: { ...validateBaselineDocument(record.value, "Baseline"), path: resolved },
    stat: record.stat,
    text: record.text,
  };
}

function globExpression(pattern) {
  const value = normalizedPath(pattern);
  let source = "^";
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    const next = value[index + 1];
    if (char === "*" && next === "*") {
      if (value[index + 2] === "/") {
        source += "(?:.*/)?";
        index += 2;
      } else {
        source += ".*";
        index += 1;
      }
    } else if (char === "*") {
      source += "[^/]*";
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += char.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
    }
  }
  return new RegExp(`${source}$`);
}

function compiledSuppressions(suppressions) {
  return suppressions.map((suppression) => ({
    ...suppression,
    ruleMatcher: globExpression(suppression.rule),
    pathMatcher: suppression.path ? globExpression(suppression.path) : null,
  }));
}

function suppressionFor(finding, suppressions, today) {
  const rule = String(finding.id ?? "");
  const file = finding.file ? normalizedPath(finding.file) : null;
  for (const suppression of suppressions) {
    if (suppression.expires && suppression.expires < today) continue;
    if (!suppression.ruleMatcher.test(rule)) continue;
    if (suppression.pathMatcher && (!file || !suppression.pathMatcher.test(file))) continue;
    return {
      status: "accepted",
      reason: redactSensitiveText(suppression.reason),
      ...(suppression.expires ? { expires: suppression.expires } : {}),
      rule: suppression.rule,
      ...(suppression.path ? { path: suppression.path } : {}),
    };
  }
  return null;
}

export function applyFindingPolicy(result, {
  baseline = null,
  suppressions = [],
  now = new Date(),
} = {}) {
  const today = now.toISOString().slice(0, 10);
  const compiled = compiledSuppressions(suppressions);
  const expired = suppressions.filter((item) => item.expires && item.expires < today);
  let newFindings = 0;
  let unchangedFindings = 0;
  let suppressedFindings = 0;
  let escalatedFindings = 0;
  const baselineEntriesByKey = new Map((baseline?.entries ?? []).map((entry) => [baselineEntryKey(entry.mode, entry.fingerprint), entry]));
  const severityRank = ["critical", "high", "medium", "low", "info"];
  const evaluated = policyCandidates(result).map((finding) => {
    const fingerprint = finding.fingerprint;
    const previous = baselineEntriesByKey.get(baselineEntryKey(result.mode, fingerprint));
    const increased = previous && severityRank.includes(previous.severity)
      && severityRank.indexOf(finding.severity) < severityRank.indexOf(previous.severity);
    if (increased) escalatedFindings += 1;
    const baselineState = baseline
      ? (baseline.keys.has(baselineEntryKey(result.mode, fingerprint)) ? "unchanged" : "new")
      : null;
    if (baselineState === "new") newFindings += 1;
    if (baselineState === "unchanged") unchangedFindings += 1;
    const suppression = suppressionFor(finding, compiled, today);
    if (suppression) suppressedFindings += 1;
    const { suppression: oldSuppression, baselineState: oldState, baselineChange: oldChange,
      previousSeverity: oldSeverity, ...clean } = finding;
    return {
      ...clean,
      fingerprint,
      ...(increased ? { baselineChange: "severity-increased", previousSeverity: previous.severity } : {}),
      ...(baselineState ? { baselineState } : {}),
      ...(suppression ? { suppression } : {}),
    };
  });
  const evaluatedByFingerprint = new Map(evaluated.map((finding) => [finding.fingerprint, finding]));
  const retainedFingerprints = fingerprintFindings(result.mode, result.findings);
  const findings = result.findings.map((finding, index) =>
    evaluatedByFingerprint.get(finding.fingerprint ?? retainedFingerprints[index]));

  return {
    ...result,
    findings,
    metadata: {
      ...(result.metadata ?? {}),
      ...(result.metadata?.findingIndex ? { findingIndex: evaluated.map(({ evidence, description, recommendation,
        suggestedFiles, standards, references, tags, ...entry }) => entry) } : {}),
      policy: {
        baseline: {
          loaded: Boolean(baseline),
          entries: baseline?.entries.length ?? 0,
          newFindings,
          unchangedFindings,
          escalatedFindings,
        },
        suppressions: {
          configured: suppressions.length,
          active: suppressions.length - expired.length,
          expired: expired.length,
          matchedFindings: suppressedFindings,
          expiredRules: expired.map((item) => item.rule).sort(),
        },
        activeFindings: evaluated.length - suppressedFindings,
      },
    },
  };
}

export function findingsAtOrAbove(result, threshold, { newOnly = false, regressionsOnly = false } = {}) {
  if (threshold === "none") return [];
  if (!SEVERITIES.has(threshold)) throw new TypeError(`Unknown threshold severity: ${threshold}`);
  const order = ["critical", "high", "medium", "low", "info"];
  const accepted = new Set(order.slice(0, order.indexOf(threshold) + 1));
  return policyCandidates(result).filter((finding) => accepted.has(finding.severity)
    && finding.suppression?.status !== "accepted"
    && (!newOnly || finding.baselineState === "new")
    && (!regressionsOnly || finding.baselineState === "new" || finding.baselineChange === "severity-increased"));
}

function baselineEntries(results, previous = null) {
  const scannedModes = new Set(results.map((result) => result.mode));
  for (const mode of scannedModes) {
    if (!MODES.has(mode)) throw new TypeError(`A baseline cannot contain the scan mode ${String(mode)}.`);
  }
  const retained = (previous?.entries ?? []).filter((entry) => !scannedModes.has(entry.mode));
  const current = results.flatMap((result) => {
    return policyCandidates(result).map((finding) => ({
      mode: result.mode,
      fingerprint: finding.fingerprint,
      ruleId: finding.id,
      severity: finding.severity,
      file: finding.file ? normalizedPath(finding.file) : null,
      title: finding.title,
    }));
  });
  return [...new Map([...retained, ...current]
    .map((entry) => [baselineEntryKey(entry.mode, entry.fingerprint), entry])).values()]
    .sort((left, right) => left.mode.localeCompare(right.mode)
      || left.fingerprint.localeCompare(right.fingerprint));
}

export function createBaselineDocument(results, { previous = null, toolVersion = "unknown", generatedAt } = {}) {
  if (!Array.isArray(results) || results.length === 0) throw new TypeError("A baseline requires at least one scan result.");
  const modes = [...new Set([
    ...baselineModes(previous),
    ...results.map((result) => result.mode),
  ])].sort();
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    kind: BASELINE_KIND,
    tool: { name: "Modular", version: String(toolVersion) },
    generatedAt: generatedAt ?? new Date().toISOString(),
    modes,
    entries: baselineEntries(results, previous),
  };
}

async function existingBaselineRecordOrNull(filePath, options = {}) {
  try {
    return await loadBaselineRecord(filePath, options);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function mergePreviousBaselines(previous, current) {
  if (!previous) return current ?? null;
  if (!current) return previous;
  const currentModes = new Set(baselineModes(current));
  const entries = [
    ...(previous.entries ?? []).filter((entry) => !currentModes.has(entry.mode)),
    ...(current.entries ?? []),
  ];
  return {
    modes: [...new Set([...baselineModes(previous), ...baselineModes(current)])].sort(),
    entries: [...new Map(entries.map((entry) => [baselineEntryKey(entry.mode, entry.fingerprint), entry])).values()],
  };
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

function baselineLockOption(value, fallback, name) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 0 || value > 120_000) {
    throw new TypeError(`${name} must be an integer from 0 through 120000.`);
  }
  return value;
}

function baselineLockPath(target) {
  return path.join(path.dirname(target), `${path.basename(target)}.modular-baseline.lock`);
}

async function readBaselineLock(lockPath) {
  let stat;
  try {
    stat = await fs.lstat(lockPath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_LOCK_BYTES) return { stat, owner: null };
  let handle;
  try {
    handle = await fs.open(lockPath, "r");
    const opened = await handle.stat();
    if (!sameFileIdentity(stat, opened) || opened.size > MAX_LOCK_BYTES) return { stat: opened, owner: null };
    const owner = JSON.parse(await handle.readFile("utf8"));
    const current = await fs.lstat(lockPath);
    if (!current.isFile() || current.isSymbolicLink() || !sameFileIdentity(opened, current)) {
      return { stat: current, owner: null };
    }
    const valid = owner?.marker === BASELINE_LOCK_MARKER
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

async function recoverStaleBaselineLock(lockPath, staleMs) {
  const observed = await readBaselineLock(lockPath);
  if (!observed) return true;
  if (!observed.owner) return false;
  const age = Date.now() - Math.max(observed.owner.createdAt, observed.stat.mtimeMs);
  if (age < staleMs || observed.owner.hostname !== os.hostname() || processIsAlive(observed.owner.pid)) return false;
  const current = await readBaselineLock(lockPath);
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

async function acquireBaselineLock(target, options) {
  const timeoutMs = baselineLockOption(
    options.baselineLockTimeoutMs,
    DEFAULT_BASELINE_LOCK_TIMEOUT_MS,
    "baselineLockTimeoutMs",
  );
  const staleMs = baselineLockOption(
    options.baselineLockStaleMs,
    DEFAULT_BASELINE_LOCK_STALE_MS,
    "baselineLockStaleMs",
  );
  const lockPath = baselineLockPath(target);
  const deadline = Date.now() + timeoutMs;
  const owner = {
    marker: BASELINE_LOCK_MARKER,
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
      if (await recoverStaleBaselineLock(lockPath, staleMs)) continue;
      if (Date.now() >= deadline) {
        const timeout = new Error(`Timed out waiting for another Modular baseline writer to release ${lockPath}.`);
        timeout.code = "BASELINE_LOCK_TIMEOUT";
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
        throw new Error(`Baseline lock changed while it was being acquired: ${lockPath}`);
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

async function releaseBaselineLock(lock) {
  await lock.handle.close();
  const current = await readBaselineLock(lock.lockPath);
  if (!current
    || !sameFileIdentity(lock.stat, current.stat)
    || current.owner?.token !== lock.owner.token) {
    throw new Error(`Refusing to release a Modular baseline lock whose ownership changed: ${lock.lockPath}`);
  }
  await fs.unlink(lock.lockPath);
}

async function withBaselineLock(target, options, callback) {
  const lock = await acquireBaselineLock(target, options);
  let value;
  let operationError;
  try {
    value = await callback();
  } catch (error) {
    operationError = error;
  }
  try {
    await releaseBaselineLock(lock);
  } catch (releaseError) {
    if (operationError) {
      throw new AggregateError(
        [operationError, releaseError],
        "Baseline update failed and its writer lock could not be released.",
        { cause: operationError },
      );
    }
    throw releaseError;
  }
  if (operationError) throw operationError;
  return value;
}

async function assertMissing(filePath, label) {
  try {
    await fs.lstat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${label} changed while a Modular baseline transaction was being prepared: ${filePath}`);
}

async function assertRecordIdentity(filePath, expected, label = "Baseline target") {
  const current = await loadBaselineRecord(filePath);
  if (!sameFileIdentity(expected.stat, current.stat) || expected.text !== current.text) {
    throw new Error(`${label} changed while a Modular baseline transaction was being prepared: ${filePath}`);
  }
  return current;
}

async function removeIfIdentity(filePath, expectedStat) {
  if (!filePath) return;
  let current;
  try {
    current = await fs.lstat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (!current.isFile() || current.isSymbolicLink() || !sameFileIdentity(current, expectedStat)) {
    throw new Error(`Refusing to remove a baseline transaction artifact whose identity changed: ${filePath}`);
  }
  await fs.unlink(filePath);
}

async function commitBaseline(target, content, currentRecord) {
  const directory = path.dirname(target);
  const transactionId = randomUUID();
  let temporary = path.join(directory, `.${path.basename(target)}.${process.pid}.${transactionId}.tmp`);
  let backup = null;
  let backupStat = null;
  let temporaryStat;
  let promoted = false;
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    temporaryStat = await handle.stat();
    await handle.writeFile(content, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;

    if (currentRecord) {
      await assertRecordIdentity(target, currentRecord);
      backup = path.join(directory, `.${path.basename(target)}.${process.pid}.${transactionId}.bak`);
      await fs.rename(target, backup);
      backupStat = currentRecord.stat;
      await assertRecordIdentity(backup, currentRecord, "Baseline transaction backup");
    } else {
      await assertMissing(target, "Baseline target");
    }

    // A hard link gives the promotion create-new semantics: even an uncooperative
    // writer cannot make Modular overwrite a file inserted into the promotion gap.
    await fs.link(temporary, target);
    promoted = true;
    const promotedRecord = await loadBaselineRecord(target);
    if (!sameFileIdentity(temporaryStat, promotedRecord.stat) || promotedRecord.text !== content) {
      throw new Error(`Promoted baseline changed before transaction completion: ${target}`);
    }
    await removeIfIdentity(temporary, temporaryStat);
    temporary = null;
    if (backup) {
      await removeIfIdentity(backup, backupStat);
      backup = null;
      backupStat = null;
    }
  } catch (error) {
    await handle?.close().catch(() => {});
    const recoveryErrors = [];
    if (promoted) {
      try {
        await removeIfIdentity(target, temporaryStat);
        promoted = false;
      } catch (recoveryError) {
        recoveryErrors.push(recoveryError);
      }
    }
    if (backupStat) {
      try {
        const currentBackup = await fs.lstat(backup);
        if (!currentBackup.isFile() || currentBackup.isSymbolicLink()
          || !sameFileIdentity(backupStat, currentBackup)) {
          throw new Error(`Refusing to restore a baseline transaction backup whose identity changed: ${backup}`);
        }
        await assertMissing(target, "Baseline rollback target");
        await fs.rename(backup, target);
        backup = null;
        backupStat = null;
      } catch (recoveryError) {
        recoveryErrors.push(recoveryError);
      }
    }
    if (temporary) {
      try {
        await removeIfIdentity(temporary, temporaryStat);
        temporary = null;
      } catch (recoveryError) {
        recoveryErrors.push(recoveryError);
      }
    }
    if (recoveryErrors.length > 0) {
      throw new AggregateError(
        [error, ...recoveryErrors],
        `Baseline transaction failed and could not be fully rolled back: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error },
      );
    }
    throw error;
  }
}

async function prepareBaselineDirectory(target, options) {
  if (options.root) await assertProjectedInsideRoot(options.root, target, "Baseline output");
  const directory = path.dirname(target);
  await fs.mkdir(directory, { recursive: true });
  const stat = await fs.stat(directory);
  if (!stat.isDirectory()) throw new TypeError(`Baseline output parent must be a directory: ${directory}`);
  if (options.root) await assertProjectedInsideRoot(options.root, target, "Baseline output");
}

export async function writeBaseline(filePath, results, options = {}) {
  const target = path.resolve(filePath);
  await prepareBaselineDirectory(target, options);
  return withBaselineLock(target, options, async () => {
    if (options.root) await assertProjectedInsideRoot(options.root, target, "Baseline output");
    const currentRecord = await existingBaselineRecordOrNull(target, { root: options.root });
    const previous = mergePreviousBaselines(options.previous ?? null, currentRecord?.baseline ?? null);
    const document = createBaselineDocument(results, { ...options, previous });
    const content = `${JSON.stringify(document, null, 2)}\n`;
    await commitBaseline(target, content, currentRecord);
    return target;
  });
}
