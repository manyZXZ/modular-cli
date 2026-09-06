import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildScanResult } from "../src/core/model.js";
import { loadBaseline, writeBaseline } from "../src/core/policy.js";
import { REPORT_FILES, REPORT_LOCK_FILE, REPORT_LOCK_MARKER, writeScanReports } from "../src/core/reporter.js";
import {
  isOwnedMachineReport,
  MACHINE_REPORT_FILES,
  MACHINE_REPORT_LOCK_FILE,
  writeMachineReports,
} from "../src/core/machine-reporter.js";
import { startRuntimeStaticServer } from "../src/runtime/static-server.js";

async function fixture(t) {
  const parent = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(parent, "modular-windows-io-"));
  t.after(async () => {
    const realRoot = await fs.realpath(root);
    assert.equal(path.dirname(realRoot).toLowerCase(), parent.toLowerCase());
    assert.ok(path.basename(realRoot).startsWith("modular-windows-io-"));
    await fs.rm(realRoot, { recursive: true, force: true });
  });
  return { root, outputDirectory: path.join(root, "Modular") };
}

function scan(root, title) {
  return buildScanResult({ mode: "security", root, title, findings: [], checks: 1, filesScanned: 1 });
}

// Older Windows libuv versions can return the full volume device value for a
// pathname but only its low 32 bits for the same opened handle. Deliberately use
// IDs above Number.MAX_SAFE_INTEGER so these tests also exercise bigint stats.
function simulateWindowsStats(t, root, pathnameDevice = "high32") {
  const platform = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { ...platform, value: "win32" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  const state = { mismatchPath: null, mismatchField: null, bigintPathStats: 0, bigintHandleStats: 0 };
  const lowDevice = 0x89abcdefn;
  const highDevice = 0x1234567800000000n;
  const applies = (file) => {
    if (typeof file !== "string") return false;
    const relative = path.relative(root, file);
    return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
  };
  const transform = (stat, file, opened) => {
    if (!applies(file)) return stat;
    const bigint = typeof stat.ino === "bigint";
    let dev = opened ? lowDevice : pathnameDevice === "zero" && stat.isFile() ? 0n : highDevice | lowDevice;
    // Retain a stable per-file identity, with every value beyond safe Number precision.
    let ino = (1n << 54n) + 2n * BigInt(stat.ino);
    if (opened && file === state.mismatchPath) {
      if (state.mismatchField === "dev") dev += 1n;
      if (state.mismatchField === "ino") ino += 1n;
    }
    if (bigint) state[opened ? "bigintHandleStats" : "bigintPathStats"] += 1;
    // Mutate only identity fields on the fresh Stats object. Sizes, timestamps,
    // type predicates and every other field retain their real native values.
    stat.dev = bigint ? dev : Number(dev);
    stat.ino = bigint ? ino : Number(ino);
    return stat;
  };
  for (const method of ["stat", "lstat"]) {
    const original = fs[method].bind(fs);
    t.mock.method(fs, method, async (file, ...args) => transform(await original(file, ...args), file, false));
  }
  const open = fs.open.bind(fs);
  t.mock.method(fs, "open", async (file, ...args) => {
    const handle = await open(file, ...args);
    if (applies(file)) {
      const stat = handle.stat.bind(handle);
      t.mock.method(handle, "stat", async (...options) => transform(await stat(...options), file, true));
    }
    return handle;
  });
  return state;
}

function request(url) {
  return new Promise((resolve, reject) => {
    const message = http.get(url, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("error", reject);
      response.on("aborted", () => reject(Object.assign(new Error("HTTP response aborted"), { code: "ECONNRESET" })));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    message.on("error", reject);
    message.setTimeout(2_000, () => message.destroy(Object.assign(new Error("HTTP request timed out"), { code: "REQUEST_TIMEOUT" })));
  });
}

for (const pathnameDevice of ["high32", "zero"]) {
  test(`Markdown report locks tolerate Windows ${pathnameDevice} pathname-device differences without losing precision`, async (t) => {
    const { root, outputDirectory } = await fixture(t);
    const stats = simulateWindowsStats(t, root, pathnameDevice);
    await writeScanReports(scan(root, "Original report"), { outputDirectory });
    await writeScanReports(scan(root, "Replacement report"), { outputDirectory });
    assert.deepEqual((await fs.readdir(outputDirectory)).sort(), [REPORT_FILES.overview, ...REPORT_FILES.security].sort());
    assert.match(await fs.readFile(path.join(outputDirectory, REPORT_FILES.security[0]), "utf8"), /Replacement report/);
    assert.ok(stats.bigintPathStats > 0);
    assert.ok(stats.bigintHandleStats > 0);
  });

  test(`JSON/SARIF ownership and repeated publication tolerate Windows ${pathnameDevice} pathname-device differences`, async (t) => {
    const { root, outputDirectory } = await fixture(t);
    const stats = simulateWindowsStats(t, root, pathnameDevice);
    const options = { outputDirectory, formats: ["json", "sarif"] };
    await writeMachineReports([scan(root, "Original report")], options);
    await writeMachineReports([scan(root, "Replacement report")], options);
    for (const format of options.formats) {
      assert.equal(await isOwnedMachineReport(path.join(outputDirectory, MACHINE_REPORT_FILES[format]), format), true);
    }
    const json = JSON.parse(await fs.readFile(path.join(outputDirectory, MACHINE_REPORT_FILES.json), "utf8"));
    assert.equal(json.results[0].title, "Replacement report");
    assert.deepEqual((await fs.readdir(outputDirectory)).sort(), Object.values(MACHINE_REPORT_FILES).sort());
    assert.ok(stats.bigintPathStats > 0);
    assert.ok(stats.bigintHandleStats > 0);
  });

  test(`Baseline read/write and lock cleanup tolerate Windows ${pathnameDevice} pathname-device differences`, async (t) => {
    const { root } = await fixture(t);
    const target = path.join(root, ".modular-baseline.json");
    const stats = simulateWindowsStats(t, root, pathnameDevice);
    await writeBaseline(target, [scan(root, "Original baseline")], { root, toolVersion: "1.0.0" });
    const original = await loadBaseline(target);
    assert.equal(original.tool.version, "1.0.0");
    await writeBaseline(target, [scan(root, "Replacement baseline")], { root, previous: original, toolVersion: "1.1.0" });
    const replacement = await loadBaseline(target);
    assert.equal(replacement.tool.version, "1.1.0");
    assert.deepEqual(replacement.modes, ["security"]);
    assert.deepEqual(await fs.readdir(root), [path.basename(target)]);
    assert.ok(stats.bigintPathStats > 0);
    assert.ok(stats.bigintHandleStats > 0);
  });
}

for (const field of ["dev", "ino"]) {
  test(`Markdown lock acquisition still rejects a changed ${field === "dev" ? "low-32 device" : "exact inode"}`, async (t) => {
    const { root, outputDirectory } = await fixture(t);
    const state = simulateWindowsStats(t, root);
    state.mismatchPath = path.join(outputDirectory, REPORT_LOCK_FILE);
    state.mismatchField = field;
    await assert.rejects(writeScanReports(scan(root, "Must not publish"), { outputDirectory }), /lock changed while it was being acquired/);
    // The apparently foreign lock is not ours to delete, and no reports are published.
    assert.deepEqual(await fs.readdir(outputDirectory), [REPORT_LOCK_FILE]);
  });

  test(`Machine-report ownership still rejects a changed ${field === "dev" ? "low-32 device" : "exact inode"}`, async (t) => {
    const { root, outputDirectory } = await fixture(t);
    const state = simulateWindowsStats(t, root);
    const options = { outputDirectory, formats: ["json", "sarif"] };
    await writeMachineReports([scan(root, "Original report")], options);
    const json = path.join(outputDirectory, MACHINE_REPORT_FILES.json);
    const original = await fs.readFile(json);
    state.mismatchPath = json;
    state.mismatchField = field;
    assert.equal(await isOwnedMachineReport(json, "json"), false);
    await assert.rejects(writeMachineReports([scan(root, "Must not publish")], options), /not generated by Modular/);
    assert.deepEqual(await fs.readFile(json), original);
    assert.equal((await fs.readdir(outputDirectory)).includes(MACHINE_REPORT_LOCK_FILE), false);
  });
}

for (const kind of ["Markdown", "machine", "baseline"]) {
  test(`${kind} writer treats an unstable active lock as busy and never reaps it`, async (t) => {
    const { root, outputDirectory } = await fixture(t);
    const baselineTarget = path.join(root, ".modular-baseline.json");
    const directory = kind === "baseline" ? root : outputDirectory;
    await fs.mkdir(directory, { recursive: true });
    const lockName = kind === "Markdown" ? REPORT_LOCK_FILE
      : kind === "machine" ? MACHINE_REPORT_LOCK_FILE
        : `${path.basename(baselineTarget)}.modular-baseline.lock`;
    const lockPath = path.join(directory, lockName);
    const marker = kind === "Markdown" ? REPORT_LOCK_MARKER
      : kind === "machine" ? "modular-machine-report-lock-v1" : "modular-baseline-lock-v1";
    const content = `${JSON.stringify({
      marker,
      token: "active-writer-token-must-be-preserved",
      pid: process.pid,
      hostname: os.hostname(),
      createdAt: Date.now() - 60_000,
    })}\n`;
    await fs.writeFile(lockPath, content);

    const lstat = fs.lstat.bind(fs);
    let unstableReads = 0;
    t.mock.method(fs, "lstat", async (target, ...options) => {
      if (target === lockPath && unstableReads === 0) {
        unstableReads += 1;
        throw Object.assign(new Error("Lock owner is still writing its durable record"), { code: "FILE_IDENTITY_CHANGED" });
      }
      return lstat(target, ...options);
    });
    const unlink = fs.unlink.bind(fs);
    let lockDeletes = 0;
    t.mock.method(fs, "unlink", async (target, ...options) => {
      if (target === lockPath) lockDeletes += 1;
      return unlink(target, ...options);
    });

    const result = scan(root, "Blocked writer must not publish");
    const pending = kind === "Markdown"
      ? writeScanReports(result, { outputDirectory, reportLockTimeoutMs: 50, reportLockStaleMs: 0 })
      : kind === "machine"
        ? writeMachineReports([result], { outputDirectory, formats: ["json"], machineLockTimeoutMs: 50, machineLockStaleMs: 0 })
        : writeBaseline(baselineTarget, [result], { root, baselineLockTimeoutMs: 50, baselineLockStaleMs: 0 });
    const expected = kind === "Markdown" ? "REPORT_LOCK_TIMEOUT"
      : kind === "machine" ? "MACHINE_REPORT_LOCK_TIMEOUT" : "BASELINE_LOCK_TIMEOUT";
    await assert.rejects(pending, (error) => error.code === expected);
    assert.equal(unstableReads, 1, "the unverified-lock branch must be exercised");
    assert.equal(lockDeletes, 0, "a transient identity error cannot authorize reaping an active lock");
    assert.equal(await fs.readFile(lockPath, "utf8"), content);
    assert.deepEqual(await fs.readdir(directory), [lockName]);
  });
}

for (const pathnameDevice of ["high32", "zero"]) {
  test(`Runtime assets remain readable with Windows ${pathnameDevice} pathname-device and high-precision inode values`, async (t) => {
    const { root } = await fixture(t);
    await fs.mkdir(path.join(root, "dist"));
    const content = "<!doctype html><title>Windows build</title><main>Readable</main>";
    await fs.writeFile(path.join(root, "dist", "index.html"), content);
    const stats = simulateWindowsStats(t, root, pathnameDevice);
    const server = await startRuntimeStaticServer({ enabled: true, root, directory: "dist" });
    try {
      const response = await request(server.url);
      assert.equal(response.status, 200);
      assert.equal(response.body, content);
      assert.equal(Number(response.headers["content-length"]), Buffer.byteLength(content));
      assert.ok(stats.bigintPathStats > 0);
      assert.ok(stats.bigintHandleStats > 0);
    } finally {
      await server.close();
    }
  });
}

for (const field of ["dev", "ino"]) {
  test(`Runtime assets still reject a changed ${field === "dev" ? "low-32 device" : "exact inode"}`, async (t) => {
    const { root } = await fixture(t);
    await fs.mkdir(path.join(root, "dist"));
    const target = path.join(root, "dist", "index.html");
    await fs.writeFile(target, "<!doctype html><title>Do not serve changed file</title>");
    const state = simulateWindowsStats(t, root);
    state.mismatchPath = target;
    state.mismatchField = field;
    const server = await startRuntimeStaticServer({ enabled: true, root, directory: "dist" });
    try {
      const response = await request(server.url).catch((error) => {
        assert.equal(error.code, "ECONNRESET", "an aborted response must reject promptly, not hang until timeout");
        return null;
      });
      if (response) {
        assert.equal(response.status, 500);
        assert.doesNotMatch(response.body, /Do not serve changed file/);
      }
    } finally {
      await server.close();
    }
  });
}
