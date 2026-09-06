import { constants as fsConstants, promises as fs } from "node:fs";

function identityInteger(value) {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  }
  if (typeof value === "string" && /^(?:0|[1-9]\d*)$/.test(value)) {
    return BigInt(value);
  }
  return null;
}

export function fileDeviceKey(value, platform = process.platform) {
  const device = identityInteger(value);
  if (device === null) return null;
  // Older libuv releases expose a 64-bit Windows volume serial through
  // lstat, but only its low 32 bits through fstat. Match libuv >= 1.51's
  // representation without weakening device comparisons on other platforms.
  // Callers must request bigint stats: rounding an unsafe Number is irreversible.
  return (platform === "win32" ? BigInt.asUintN(32, device) : device).toString();
}

export function sameFilesystemIdentity(left, right, platform = process.platform) {
  if (!left || !right) return false;
  const leftDevice = fileDeviceKey(left.dev, platform);
  const rightDevice = fileDeviceKey(right.dev, platform);
  const leftInode = identityInteger(left.ino);
  const rightInode = identityInteger(right.ino);
  return leftDevice !== null
    && rightDevice !== null
    && leftInode !== null
    && rightInode !== null
    && leftDevice === rightDevice
    && leftInode === rightInode;
}

function samePathSnapshot(left, right) {
  return left.isFile() && right.isFile()
    && !left.isSymbolicLink() && !right.isSymbolicLink()
    && ["ino", "size", "mtimeNs", "ctimeNs"].every((key) => (
      typeof left[key] === "bigint" && left[key] === right[key]
    ));
}

function changedIdentityError(candidate) {
  const error = new Error(`File identity changed while it was being verified: ${candidate}`);
  error.code = "FILE_IDENTITY_CHANGED";
  return error;
}

export async function readPathIdentity(candidate, { followLinks = false } = {}) {
  const readStat = () => followLinks
    ? fs.stat(candidate, { bigint: true })
    : fs.lstat(candidate, { bigint: true });
  const initial = await readStat();
  if (process.platform !== "win32" || initial.dev !== 0n || !initial.isFile()) return initial;

  // libuv 1.49's Windows fast-stat structure can report a missing device (0).
  // Never make 0 a wildcard. Obtain a real handle identity instead, requiring
  // the surrounding pathname snapshots and canonical target to remain stable.
  const canonical = await fs.realpath(candidate);
  const lexicalBefore = await fs.lstat(candidate, { bigint: true });
  if (lexicalBefore.isSymbolicLink() || !samePathSnapshot(initial, lexicalBefore)) {
    throw changedIdentityError(candidate);
  }
  let handle;
  try {
    handle = await fs.open(candidate, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat({ bigint: true });
    const current = await readStat();
    const lexicalAfter = await fs.lstat(candidate, { bigint: true });
    const finalCanonical = await fs.realpath(candidate);
    const after = await handle.stat({ bigint: true });
    if (canonical !== finalCanonical
      || !samePathSnapshot(initial, opened)
      || !samePathSnapshot(initial, current)
      || !samePathSnapshot(initial, lexicalAfter)
      || !samePathSnapshot(opened, after)
      || !sameFilesystemIdentity(initial, current)
      || !sameFilesystemIdentity(initial, lexicalBefore)
      || !sameFilesystemIdentity(initial, lexicalAfter)
      || !sameFilesystemIdentity(opened, after)) {
      throw changedIdentityError(candidate);
    }
    return after;
  } finally {
    await handle?.close();
  }
}
