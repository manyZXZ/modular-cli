import { constants as fsConstants, promises as fs } from "node:fs";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { readPathIdentity, sameFilesystemIdentity as sameFileIdentity } from "../file-identity.js";
import {
  DEFAULT_REPORT_LOCK_STALE_MS,
  DEFAULT_REPORT_LOCK_TIMEOUT_MS,
  REPORT_LOCK_FILE,
  REPORT_LOCK_MARKER,
  REPORT_MARKER,
} from "./constants.js";

// Shared by every report writer in this process; cross-process locking follows.
const pendingReportSets = new Map();

function pathInsideOrEqual(parent, candidate) {
  const relation = path.relative(parent, candidate);
  return relation === "" || (relation !== ".." && !relation.startsWith(`..${path.sep}`) && !path.isAbsolute(relation));
}

function unsafeOutputError(outputDirectory) {
  const error = new Error(`Report output path escapes the repository through a symbolic link or junction: ${outputDirectory}`);
  error.code = "UNSAFE_OUTPUT_PATH";
  return error;
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

export async function prepareOutputDirectory(repositoryRoot, outputDirectory) {
  const lexicalRoot = path.resolve(repositoryRoot);
  const lexicalOutput = path.resolve(outputDirectory);
  const enforceRepositoryBoundary = pathInsideOrEqual(lexicalRoot, lexicalOutput);
  let realRoot = null;

  if (enforceRepositoryBoundary) {
    realRoot = await fs.realpath(lexicalRoot);
    const existing = await nearestExistingPath(lexicalOutput);
    let realExisting;
    try {
      realExisting = await fs.realpath(existing);
    } catch {
      throw unsafeOutputError(lexicalOutput);
    }
    const projectedOutput = path.resolve(realExisting, path.relative(existing, lexicalOutput));
    if (!pathInsideOrEqual(realRoot, projectedOutput)) throw unsafeOutputError(lexicalOutput);
  }

  await fs.mkdir(lexicalOutput, { recursive: true });
  const baselineRealOutput = await fs.realpath(lexicalOutput);
  if (enforceRepositoryBoundary && !pathInsideOrEqual(realRoot, baselineRealOutput)) {
    throw unsafeOutputError(lexicalOutput);
  }
  const baseline = await fs.stat(lexicalOutput, { bigint: true });
  if (!baseline.isDirectory()) throw new Error(`Report output path is not a directory: ${lexicalOutput}`);

  return async function validateOutputDirectory(candidateFile = null) {
    let currentRealOutput;
    let current;
    try {
      currentRealOutput = await fs.realpath(lexicalOutput);
      current = await fs.stat(lexicalOutput, { bigint: true });
    } catch {
      throw unsafeOutputError(lexicalOutput);
    }
    if (!current.isDirectory()
      || path.relative(baselineRealOutput, currentRealOutput) !== ""
      || !sameFileIdentity(current, baseline)
      || (enforceRepositoryBoundary && !pathInsideOrEqual(realRoot, currentRealOutput))) {
      throw unsafeOutputError(lexicalOutput);
    }
    if (candidateFile) {
      let realCandidate;
      try {
        realCandidate = await fs.realpath(candidateFile);
      } catch {
        throw unsafeOutputError(lexicalOutput);
      }
      if (path.relative(currentRealOutput, path.dirname(realCandidate)) !== "") {
        throw unsafeOutputError(lexicalOutput);
      }
    }
  };
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function reportLockOption(value, fallback, name, minimum, maximum) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    // EPERM means the process exists but cannot be signalled. Unknown failures
    // also fail closed: a lock is never reaped unless its owner is proven dead.
    return true;
  }
}

async function readReportLock(lockPath) {
  let stat;
  try {
    stat = await readPathIdentity(lockPath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    // A writer may still be filling its exclusively created lock. An unstable
    // snapshot is an existing, unverified lock: wait, never reap it as stale.
    if (error?.code === "FILE_IDENTITY_CHANGED") return { stat: null, owner: null };
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) return { stat, owner: null };
  try {
    const owner = JSON.parse(await fs.readFile(lockPath, "utf8"));
    const valid = owner?.marker === REPORT_LOCK_MARKER
      && typeof owner.token === "string"
      && owner.token.length >= 16
      && Number.isSafeInteger(owner.pid)
      && owner.pid > 0
      && typeof owner.hostname === "string"
      && owner.hostname.length > 0
      && Number.isFinite(owner.createdAt);
    return { stat, owner: valid ? owner : null };
  } catch {
    // Another process may be between exclusive creation and its durable owner
    // write. Never interpret incomplete or foreign content as stale.
    return { stat, owner: null };
  }
}

async function recoverStaleReportLock(lockPath, validateOutput, staleMs) {
  const observed = await readReportLock(lockPath);
  if (!observed) return true;
  if (!observed.owner) return false;
  const owner = observed.owner;
  const age = Date.now() - Math.max(owner.createdAt, Number(observed.stat.mtimeMs));
  if (age < staleMs || owner.hostname !== os.hostname() || processIsAlive(owner.pid) !== false) return false;

  // Re-read immediately before unlinking so a changed owner or inode is never
  // removed based on stale metadata. PID reuse is deliberately conservative.
  const current = await readReportLock(lockPath);
  if (!current) return true;
  if (!sameFileIdentity(observed.stat, current.stat)
    || current.owner?.token !== owner.token
    || processIsAlive(owner.pid) !== false) return false;
  await validateOutput(lockPath);
  try {
    await fs.unlink(lockPath);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return true;
    throw error;
  }
}

async function acquireReportLock(outputDirectory, validateOutput, options) {
  const timeoutMs = reportLockOption(options.reportLockTimeoutMs, DEFAULT_REPORT_LOCK_TIMEOUT_MS, "reportLockTimeoutMs", 25, 120_000);
  const staleMs = reportLockOption(options.reportLockStaleMs, DEFAULT_REPORT_LOCK_STALE_MS, "reportLockStaleMs", 0, 86_400_000);
  const lockPath = path.join(outputDirectory, REPORT_LOCK_FILE);
  const deadline = Date.now() + timeoutMs;
  const owner = {
    marker: REPORT_LOCK_MARKER,
    token: randomUUID(),
    pid: process.pid,
    hostname: os.hostname(),
    createdAt: Date.now(),
  };
  let delayMs = 20;

  for (;;) {
    await validateOutput();
    let handle;
    try {
      handle = await fs.open(lockPath, "wx", 0o600);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      if (await recoverStaleReportLock(lockPath, validateOutput, staleMs)) continue;
      if (Date.now() >= deadline) {
        const timeout = new Error(`Timed out waiting for another Modular report writer to release ${lockPath}.`);
        timeout.code = "REPORT_LOCK_TIMEOUT";
        throw timeout;
      }
      await wait(Math.min(delayMs, Math.max(1, deadline - Date.now())));
      delayMs = Math.min(200, Math.ceil(delayMs * 1.5));
      continue;
    }

    const acquiredStat = await handle.stat({ bigint: true });
    try {
      await handle.writeFile(`${JSON.stringify(owner)}\n`, "utf8");
      await handle.sync();
      await validateOutput(lockPath);
      const current = await readPathIdentity(lockPath);
      if (!current.isFile() || current.isSymbolicLink() || !sameFileIdentity(acquiredStat, current)) {
        throw new Error(`Modular report lock changed while it was being acquired: ${lockPath}`);
      }
      return { handle, lockPath, owner, stat: acquiredStat };
    } catch (error) {
      await handle.close().catch(() => {});
      const current = await readPathIdentity(lockPath).catch(() => null);
      if (sameFileIdentity(acquiredStat, current)) await fs.unlink(lockPath).catch(() => {});
      throw error;
    }
  }
}

async function releaseReportLock(lock, validateOutput) {
  await lock.handle.close();
  const current = await readReportLock(lock.lockPath);
  if (!current
    || !sameFileIdentity(lock.stat, current.stat)
    || current.owner?.token !== lock.owner.token) {
    throw new Error(`Refusing to release a Modular report lock whose ownership changed: ${lock.lockPath}`);
  }
  await validateOutput(lock.lockPath);
  await fs.unlink(lock.lockPath);
}

export async function withReportLock(outputDirectory, validateOutput, options, callback) {
  const lock = await acquireReportLock(outputDirectory, validateOutput, options);
  let result;
  let operationError;
  try {
    result = await callback();
  } catch (error) {
    operationError = error;
  }

  try {
    await releaseReportLock(lock, validateOutput);
  } catch (releaseError) {
    if (operationError) {
      const detail = operationError instanceof Error ? operationError.message : String(operationError);
      throw new AggregateError([operationError, releaseError], `Report generation failed and its writer lock could not be released: ${detail}`, { cause: operationError });
    }
    throw releaseError;
  }
  if (operationError) throw operationError;
  return result;
}

async function renameWithRetry(source, destination) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await fs.rename(source, destination);
      return;
    } catch (error) {
      const retryable = process.platform === "win32" && ["EACCES", "EBUSY", "EPERM"].includes(error?.code);
      if (!retryable || attempt >= 5) throw error;
      await wait(10 * (attempt + 1));
    }
  }
}

export async function assertOwnedOrMissing(filePath) {
  let stat;
  try {
    stat = await fs.lstat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Refusing to replace a report-shaped path that is not a regular Modular-generated file: ${filePath}`);
  }
  const expectedBytes = Buffer.byteLength(REPORT_MARKER);
  const buffer = Buffer.alloc(expectedBytes);
  let handle;
  try {
    handle = await fs.open(filePath, "r");
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
  try {
    const { bytesRead } = await handle.read(buffer, 0, expectedBytes, 0);
    if (bytesRead !== expectedBytes || buffer.toString("utf8") !== REPORT_MARKER) {
      throw new Error(`Refusing to replace a report-shaped file not generated by Modular: ${filePath}`);
    }
  } finally {
    await handle.close();
  }
  return true;
}

function transactionArtifactPath(filePath, transactionId, suffix) {
  return path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${transactionId}.${suffix}`);
}

async function writeExclusiveFile(filePath, content, validateOutput) {
  let handle;
  try {
    await validateOutput();
    handle = await fs.open(filePath, "wx", 0o600);
    await validateOutput(filePath);
    await handle.writeFile(content, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    await validateOutput(filePath);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    throw error;
  }
}

async function safelyRemoveTransactionArtifact(filePath, validateOutput) {
  if (!filePath) return;
  try {
    const stat = await fs.lstat(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) throw unsafeOutputError(path.dirname(filePath));
    await validateOutput(filePath);
    // copyFile preserves a read-only source mode on some platforms. These are
    // transaction-owned artifacts, so make them removable before cleanup.
    await fs.chmod(filePath, 0o600);
    await fs.rm(filePath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function snapshotReport(record, validateOutput, transactionId) {
  record.existed = await assertOwnedOrMissing(record.target);
  if (!record.existed) return;
  record.backup = transactionArtifactPath(record.target, transactionId, "bak");
  await validateOutput();
  await fs.copyFile(record.target, record.backup, fsConstants.COPYFILE_EXCL);
  await validateOutput(record.backup);
  if (!await filesEqual(record.target, record.backup)) {
    throw new Error(`Report target changed while a Modular report transaction was being prepared: ${record.target}`);
  }
}

async function assertSnapshotUnchanged(record) {
  const existsNow = await assertOwnedOrMissing(record.target);
  if (existsNow !== record.existed) {
    throw new Error(`Report target changed while a Modular report transaction was being prepared: ${record.target}`);
  }
  if (!existsNow) return;
  if (!await assertOwnedOrMissing(record.backup)) {
    throw new Error(`Report transaction backup disappeared before promotion: ${record.backup}`);
  }
  if (!await filesEqual(record.target, record.backup)) {
    throw new Error(`Report target changed while a Modular report transaction was being prepared: ${record.target}`);
  }
}

async function filesEqual(leftPath, rightPath) {
  let left;
  let right;
  const chunkSize = 64 * 1024;
  const leftBuffer = Buffer.allocUnsafe(chunkSize);
  const rightBuffer = Buffer.allocUnsafe(chunkSize);
  try {
    left = await fs.open(leftPath, "r");
    right = await fs.open(rightPath, "r");
    const [leftStat, rightStat] = await Promise.all([left.stat(), right.stat()]);
    if (leftStat.size !== rightStat.size) return false;
    let position = 0;
    while (position < leftStat.size) {
      const length = Math.min(chunkSize, leftStat.size - position);
      const [leftRead, rightRead] = await Promise.all([
        left.read(leftBuffer, 0, length, position),
        right.read(rightBuffer, 0, length, position),
      ]);
      if (leftRead.bytesRead !== length || rightRead.bytesRead !== length) return false;
      if (!leftBuffer.subarray(0, length).equals(rightBuffer.subarray(0, length))) return false;
      position += length;
    }
    return true;
  } finally {
    await Promise.all([left?.close(), right?.close()]);
  }
}

async function rollbackReportSet(records, validateOutput) {
  const errors = [];
  for (const record of [...records].reverse()) {
    if (!record.promoted) continue;
    try {
      await validateOutput();
      const targetExists = await assertOwnedOrMissing(record.target);
      if (!targetExists) throw new Error(`Promoted report disappeared before rollback: ${record.target}`);
      if (record.existed) {
        if (!await assertOwnedOrMissing(record.backup)) {
          throw new Error(`Report transaction backup disappeared before rollback: ${record.backup}`);
        }
        await validateOutput(record.backup);
        await renameWithRetry(record.backup, record.target);
        record.backup = null;
      } else {
        await fs.rm(record.target);
      }
      record.promoted = false;
      await validateOutput();
    } catch (error) {
      errors.push(error);
    }
  }
  return errors;
}

async function cleanupReportTransaction(records, validateOutput, { preserveRecoveryBackups = false } = {}) {
  const errors = [];
  for (const record of records) {
    for (const field of ["staged", "backup"]) {
      if (!record[field]) continue;
      // A failed rollback may leave the backup as the only copy of the old report.
      if (field === "backup" && preserveRecoveryBackups && record.promoted) continue;
      try {
        await safelyRemoveTransactionArtifact(record[field], validateOutput);
        record[field] = null;
      } catch (error) {
        errors.push(error);
      }
    }
  }
  return errors;
}

export async function commitReportSet(entries, validateOutput) {
  // Filesystems do not provide a portable atomic rename for a set of files.
  // Prepare every replacement first, retain marker-owned snapshots during the
  // promote window, and roll the whole set back on every catchable failure.
  // A process/OS interruption can still leave hidden .tmp/.bak evidence; .bak
  // files are intentionally not accepted as ordinary report-directory content.
  const transactionId = randomUUID();
  const records = entries.map((entry) => ({
    ...entry,
    staged: transactionArtifactPath(entry.target, transactionId, "tmp"),
    backup: null,
    existed: false,
    promoted: false,
  }));

  try {
    await validateOutput();
    for (const record of records) {
      await writeExclusiveFile(record.staged, record.content, validateOutput);
    }
    for (const record of records) {
      await snapshotReport(record, validateOutput, transactionId);
    }
    await validateOutput();

    for (const record of records) {
      await validateOutput();
      await assertSnapshotUnchanged(record);
      if (!await assertOwnedOrMissing(record.staged)) {
        throw new Error(`Staged report disappeared before promotion: ${record.staged}`);
      }
      await validateOutput(record.staged);
      await renameWithRetry(record.staged, record.target);
      record.staged = null;
      record.promoted = true;
      await validateOutput();
      if (!await assertOwnedOrMissing(record.target)) {
        throw new Error(`Promoted report disappeared before transaction completion: ${record.target}`);
      }
    }
  } catch (error) {
    const rollbackErrors = await rollbackReportSet(records, validateOutput);
    const cleanupErrors = await cleanupReportTransaction(records, validateOutput, { preserveRecoveryBackups: true });
    const recoveryErrors = [...rollbackErrors, ...cleanupErrors];
    if (recoveryErrors.length > 0) {
      const backups = records.filter((record) => record.backup).map((record) => record.backup);
      const recoveryNotice = backups.length ? ` Recovery backup paths: ${backups.join(", ")}.` : "";
      throw new AggregateError(
        [error, ...recoveryErrors],
        `Modular report transaction failed and could not be fully rolled back: ${error instanceof Error ? error.message : String(error)}.${recoveryNotice}`,
        { cause: error },
      );
    }
    throw error;
  }

  const cleanupErrors = await cleanupReportTransaction(records, validateOutput);
  if (cleanupErrors.length > 0) {
    throw new AggregateError(cleanupErrors, "Modular reports were committed, but transaction backup cleanup failed.");
  }
}

export async function serializeReportSet(outputDirectory, callback) {
  const resolved = path.resolve(outputDirectory);
  const key = process.platform === "win32" ? resolved.toLowerCase() : resolved;
  const previous = pendingReportSets.get(key) ?? Promise.resolve();
  const current = previous.catch(() => {}).then(callback);
  pendingReportSets.set(key, current);
  try {
    return await current;
  } finally {
    if (pendingReportSets.get(key) === current) pendingReportSets.delete(key);
  }
}
