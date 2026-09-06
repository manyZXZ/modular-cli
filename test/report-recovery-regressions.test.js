import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildScanResult } from "../src/core/model.js";
import { REPORT_FILES, REPORT_LOCK_FILE, writeScanReports } from "../src/core/reporter.js";
import { MACHINE_REPORT_FILES, MACHINE_REPORT_LOCK_FILE, writeMachineReports } from "../src/core/machine-reporter.js";

async function fixture(t) {
  const parent = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(parent, "modular-report-recovery-"));
  t.after(async () => {
    const realRoot = await fs.realpath(root);
    assert.equal(path.dirname(realRoot).toLowerCase(), parent.toLowerCase());
    assert.ok(path.basename(realRoot).startsWith("modular-report-recovery-"));
    await fs.rm(realRoot, { recursive: true, force: true });
  });
  return { root, outputDirectory: path.join(root, "Modular") };
}

function scan(root, title) {
  return buildScanResult({ mode: "security", root, title, findings: [], checks: 1, filesScanned: 1 });
}

function ioError(message) {
  return Object.assign(new Error(message), { code: "EIO" });
}

test("Markdown recovery keeps the original backup when rollback also fails", async (t) => {
  const { root, outputDirectory } = await fixture(t);
  await writeScanReports(scan(root, "Original Markdown report"), { outputDirectory });
  const names = [REPORT_FILES.overview, ...REPORT_FILES.security];
  const before = new Map(await Promise.all(names.map(async (name) => [name, await fs.readFile(path.join(outputDirectory, name))])));
  const detail = path.join(outputDirectory, REPORT_FILES.security[0]);
  const overview = path.join(outputDirectory, REPORT_FILES.overview);
  const rename = fs.rename.bind(fs);
  t.mock.method(fs, "rename", async (source, target) => {
    if (source.endsWith(".tmp") && target === overview) throw ioError("injected Markdown promotion failure");
    if (source.endsWith(".bak") && target === detail) throw ioError("injected Markdown rollback failure");
    return rename(source, target);
  });

  let failure;
  await assert.rejects(writeScanReports(scan(root, "Replacement Markdown report"), { outputDirectory }), (error) => {
    failure = error;
    return error instanceof AggregateError;
  });
  const files = await fs.readdir(outputDirectory);
  const backups = files.filter((name) => name.endsWith(".bak"));
  assert.equal(backups.length, 1, "the only surviving copy of the original report must be kept");
  const backupPath = path.join(outputDirectory, backups[0]);
  assert.deepEqual(await fs.readFile(backupPath), before.get(REPORT_FILES.security[0]));
  assert.ok(failure.message.includes(backupPath), "the error must identify the recovery copy");
  for (const name of [REPORT_FILES.overview, REPORT_FILES.security[1]]) {
    assert.deepEqual(await fs.readFile(path.join(outputDirectory, name)), before.get(name));
  }
  assert.equal(files.includes(REPORT_LOCK_FILE), false);
  assert.equal(files.some((name) => name.endsWith(".tmp")), false);
});

for (const failRollback of [false, true]) {
  test(`JSON/SARIF recovery ${failRollback ? "retains backups after a failed restore" : "restores both formats after a failed promotion"}`, async (t) => {
    const { root, outputDirectory } = await fixture(t);
    const options = { outputDirectory, formats: ["json", "sarif"] };
    await writeMachineReports([scan(root, "Original machine report")], options);
    const json = path.join(outputDirectory, MACHINE_REPORT_FILES.json);
    const sarif = path.join(outputDirectory, MACHINE_REPORT_FILES.sarif);
    const beforeJson = await fs.readFile(json);
    const beforeSarif = await fs.readFile(sarif);
    const rename = fs.rename.bind(fs);
    t.mock.method(fs, "rename", async (source, target) => {
      if (source.endsWith(".tmp") && target === sarif) throw ioError("injected machine promotion failure");
      if (failRollback && source.endsWith(".backup") && target === json) throw ioError("injected machine rollback failure");
      return rename(source, target);
    });

    let failure;
    await assert.rejects(writeMachineReports([scan(root, "Replacement machine report")], options), (error) => {
      failure = error;
      return /injected machine promotion failure/.test(error.message);
    });
    const files = await fs.readdir(outputDirectory);
    const backups = files.filter((name) => name.endsWith(".backup"));
    if (failRollback) {
      assert.equal(backups.length, 1, "the previous JSON must remain recoverable");
      const backupPath = path.join(outputDirectory, backups[0]);
      assert.deepEqual(await fs.readFile(backupPath), beforeJson);
      assert.ok(failure instanceof AggregateError);
      assert.ok(failure.errors.some((error) => /injected machine rollback failure/.test(error.message)));
      assert.ok(failure.message.includes(backupPath));
    } else {
      assert.equal(backups.length, 0);
      assert.deepEqual(await fs.readFile(json), beforeJson);
    }
    assert.deepEqual(await fs.readFile(sarif), beforeSarif);
    assert.equal(files.includes(MACHINE_REPORT_LOCK_FILE), false);
    assert.equal(files.some((name) => name.endsWith(".tmp")), false);
  });
}

for (const format of ["Markdown", "JSON/SARIF"]) {
  test(`${format} exposes recovery paths even when lock release also fails`, async (t) => {
    const { root, outputDirectory } = await fixture(t);
    const markdown = format === "Markdown";
    const publish = (title) => markdown
      ? writeScanReports(scan(root, title), { outputDirectory })
      : writeMachineReports([scan(root, title)], { outputDirectory, formats: ["json", "sarif"] });
    await publish("Original report");
    const original = path.join(outputDirectory, markdown ? REPORT_FILES.security[0] : MACHINE_REPORT_FILES.json);
    const promotionTarget = path.join(outputDirectory, markdown ? REPORT_FILES.overview : MACHINE_REPORT_FILES.sarif);
    const lockPath = path.join(outputDirectory, markdown ? REPORT_LOCK_FILE : MACHINE_REPORT_LOCK_FILE);
    const extension = markdown ? ".bak" : ".backup";
    const before = await fs.readFile(original);
    const rename = fs.rename.bind(fs);
    const unlink = fs.unlink.bind(fs);
    t.mock.method(fs, "rename", async (source, target) => {
      if (source.endsWith(".tmp") && target === promotionTarget) throw ioError("injected promotion failure");
      if (source.endsWith(extension) && target === original) throw ioError("injected rollback failure");
      return rename(source, target);
    });
    t.mock.method(fs, "unlink", async (target) => {
      if (target === lockPath) throw ioError("injected lock release failure");
      return unlink(target);
    });

    let failure;
    await assert.rejects(publish("Replacement report"), (error) => {
      failure = error;
      return error instanceof AggregateError;
    });
    const backups = (await fs.readdir(outputDirectory)).filter((name) => name.endsWith(extension));
    assert.equal(backups.length, 1);
    const backupPath = path.join(outputDirectory, backups[0]);
    assert.deepEqual(await fs.readFile(backupPath), before);
    assert.ok(failure.message.includes(backupPath), "CLI-visible error must preserve the recovery path through lock failures");
    assert.match(failure.message, /injected promotion failure/);
    assert.ok(failure.errors.some((error) => /injected lock release failure/.test(error.message)));
  });
}
