import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileDeviceKey, readPathIdentity, sameFilesystemIdentity } from "../src/core/file-identity.js";
import { collectFiles, readTextFile, verifyFileMetadata } from "../src/core/files.js";
import { detectWebProject } from "../src/core/project.js";

const VOLUME = 0x89abcdefn;
const WIDE_VOLUME = 0xfedcba9800000000n | VOLUME;

async function fixture(t) {
  const temporaryParent = path.resolve(os.tmpdir());
  const root = await fs.mkdtemp(path.join(temporaryParent, "modular-file-identity-"));
  t.after(async () => {
    assert.equal(path.dirname(path.resolve(root)), temporaryParent);
    assert.ok(path.basename(root).startsWith("modular-file-identity-"));
    await fs.rm(root, { recursive: true, force: true });
  });
  const source = "<!doctype html><html lang=\"en\"><head><title>Example</title></head><body><main>Example</main></body></html>";
  await fs.writeFile(path.join(root, "index.html"), source);
  return { root, source };
}

function windowsIdentityStats(t, {
  pathDevice = WIDE_VOLUME,
  handleDevice = VOLUME,
  handleInodeDelta = 0n,
  mutatePathStat = () => {},
  mutateHandleStat = () => {},
} = {}) {
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { ...platformDescriptor, value: "win32" });
  t.after(() => Object.defineProperty(process, "platform", platformDescriptor));
  const originalLstat = fs.lstat.bind(fs);
  const originalOpen = fs.open.bind(fs);
  let regularPathReads = 0;
  t.mock.method(fs, "lstat", async (...args) => {
    const stat = await originalLstat(...args);
    stat.dev = typeof stat.dev === "bigint" ? pathDevice : Number(pathDevice);
    if (stat.isFile()) mutatePathStat(stat, ++regularPathReads);
    return stat;
  });
  t.mock.method(fs, "open", async (...args) => {
    const handle = await originalOpen(...args);
    const originalStat = handle.stat.bind(handle);
    let handleReads = 0;
    handle.stat = async (...statArgs) => {
      const stat = await originalStat(...statArgs);
      stat.dev = typeof stat.dev === "bigint" ? handleDevice : Number(handleDevice);
      stat.ino = typeof stat.ino === "bigint"
        ? stat.ino + handleInodeDelta
        : stat.ino + Number(handleInodeDelta);
      mutateHandleStat(stat, ++handleReads);
      return stat;
    };
    return handle;
  });
}

test("filesystem identity normalizes Windows volume serials without discarding inode precision", () => {
  const inode = 0x123456789abcdef0n;
  assert.equal(fileDeviceKey(WIDE_VOLUME, "win32"), String(VOLUME));
  assert.equal(fileDeviceKey(String(WIDE_VOLUME), "win32"), String(VOLUME));
  assert.equal(sameFilesystemIdentity({ dev: WIDE_VOLUME, ino: inode }, { dev: VOLUME, ino: inode }, "win32"), true);
  assert.equal(sameFilesystemIdentity({ dev: WIDE_VOLUME, ino: inode }, { dev: VOLUME + 1n, ino: inode }, "win32"), false);
  assert.equal(sameFilesystemIdentity({ dev: WIDE_VOLUME, ino: inode }, { dev: VOLUME, ino: inode + 1n }, "win32"), false);
  assert.equal(sameFilesystemIdentity({ dev: 0n, ino: inode }, { dev: VOLUME, ino: inode }, "win32"), false);
  for (const platform of ["linux", "darwin"]) {
    assert.equal(fileDeviceKey(WIDE_VOLUME, platform), String(WIDE_VOLUME));
    assert.equal(sameFilesystemIdentity({ dev: WIDE_VOLUME, ino: inode }, { dev: VOLUME, ino: inode }, platform), false);
  }
  for (const invalid of [undefined, null, NaN, Infinity, -1, 1.5, true, "", "1.5", Number(WIDE_VOLUME)]) {
    assert.equal(fileDeviceKey(invalid, "win32"), null);
    assert.equal(sameFilesystemIdentity({ dev: invalid, ino: inode }, { dev: invalid, ino: inode }, "win32"), false);
    assert.equal(sameFilesystemIdentity({ dev: VOLUME, ino: invalid }, { dev: VOLUME, ino: invalid }, "win32"), false);
  }
});

for (const [label, pathDevice] of [["wide", WIDE_VOLUME], ["zero", 0n]]) {
test(`discovery, website detection and safe reads support Windows ${label} path volume serials`, async (t) => {
  const { root, source } = await fixture(t);
  await fs.writeFile(path.join(root, "hero.png"), Buffer.from([137, 80, 78, 71]));
  windowsIdentityStats(t, { pathDevice });

  const inventory = await collectFiles(root);
  assert.equal(inventory.skipped.inaccessible, 0);
  assert.deepEqual(inventory.files.map((file) => file.relative), ["hero.png", "index.html"]);
  const document = inventory.files.find((file) => file.relative === "index.html");
  assert.equal(document.identity.dev, String(VOLUME));
  assert.equal(await readTextFile(document, { root }), source);
  assert.equal((await detectWebProject({ root, files: inventory.files })).isWebsite, true);
  const asset = inventory.files.find((file) => file.relative === "hero.png");
  assert.equal((await verifyFileMetadata(asset, { root })).relative, "hero.png");

  for (const field of ["ino", "size", "mtimeNs", "ctimeNs"]) {
    const changed = field === "size" ? document.identity[field] + 1 : String(BigInt(document.identity[field]) + 1n);
    assert.equal(await readTextFile({ ...document, identity: { ...document.identity, [field]: changed } }, { root }), null);
  }
  assert.equal(await readTextFile({ ...document, digest: "0".repeat(64) }, { root }), null);
  assert.equal(await readTextFile({ ...document, identity: { ...document.identity, dev: String(VOLUME + 1n) } }, { root }), null);
  assert.equal(await verifyFileMetadata({ ...asset, identity: { ...asset.identity, dev: String(VOLUME + 1n) } }, { root }), null);
});
}

for (const field of ["ino", "size", "mtimeNs", "ctimeNs"]) {
  test(`Windows zero-device fallback rejects pathname ${field} changes`, async (t) => {
    const { root } = await fixture(t);
    windowsIdentityStats(t, {
      pathDevice: 0n,
      mutatePathStat: (stat, reads) => {
        if (reads >= 3) stat[field] += 1n;
      },
    });
    await assert.rejects(readPathIdentity(path.join(root, "index.html")), { code: "FILE_IDENTITY_CHANGED" });
  });
}

test("Windows zero-device fallback rejects changed handle identity", async (t) => {
  const { root } = await fixture(t);
  windowsIdentityStats(t, {
    pathDevice: 0n,
    mutateHandleStat: (stat, reads) => {
      if (reads >= 2) stat.dev += 1n;
    },
  });
  await assert.rejects(readPathIdentity(path.join(root, "index.html")), { code: "FILE_IDENTITY_CHANGED" });
});

test("Windows zero-device fallback rejects a newly linked pathname", async (t) => {
  const { root } = await fixture(t);
  windowsIdentityStats(t, {
    pathDevice: 0n,
    mutatePathStat: (stat, reads) => {
      if (reads >= 3) stat.isSymbolicLink = () => true;
    },
  });
  await assert.rejects(readPathIdentity(path.join(root, "index.html")), { code: "FILE_IDENTITY_CHANGED" });
});

test("Windows zero-device fallback rejects a changed canonical target", async (t) => {
  const { root } = await fixture(t);
  windowsIdentityStats(t, { pathDevice: 0n });
  const originalRealpath = fs.realpath.bind(fs);
  let reads = 0;
  t.mock.method(fs, "realpath", async (...args) => {
    const canonical = await originalRealpath(...args);
    return ++reads > 1 ? `${canonical}.replaced` : canonical;
  });
  await assert.rejects(readPathIdentity(path.join(root, "index.html")), { code: "FILE_IDENTITY_CHANGED" });
});

for (const [label, statOptions] of [
  ["a genuinely different device", { handleDevice: VOLUME + 1n }],
  ["a different inode", { handleInodeDelta: 1n }],
]) {
  test(`discovery and direct reads still reject ${label} on Windows`, async (t) => {
    const { root } = await fixture(t);
    windowsIdentityStats(t, statOptions);
    const inventory = await collectFiles(root);
    assert.equal(inventory.files.length, 0);
    assert.equal(inventory.skipped.inaccessible, 1);
    assert.equal(await readTextFile({ absolute: path.join(root, "index.html") }, { root }), null);
  });
}
