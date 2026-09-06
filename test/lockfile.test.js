import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { collectFiles, readTextFile } from "../src/core/files.js";
import { detectWebProject } from "../src/core/project.js";
import { runSecurityScan } from "../src/scanners/security.js";

test("oversized lockfiles remain visible to security checks without being loaded", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-large-lock-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, "index.html"), "<!doctype html><html><body><main>Site</main></body></html>");
  await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ dependencies: { react: "1.0.0" } }));
  await fs.writeFile(path.join(root, "package-lock.json"), " ".repeat(1_500_001));

  const inventory = await collectFiles(root, { maxFileBytes: 1_500_000 });
  const lockfile = inventory.files.find((file) => file.name === "package-lock.json");
  assert.ok(lockfile, "lockfile presence must survive the text-size limit");
  assert.equal(lockfile.contentReadable, false);
  assert.equal(lockfile.skippedReason, "large");
  assert.equal(await readTextFile(lockfile), null);

  const webDetection = await detectWebProject({ root, files: inventory.files });
  const result = await runSecurityScan({
    root,
    files: inventory.files,
    skipped: inventory.skipped,
    options: { webDetection, auditDependencies: false },
  });
  assert.equal(result.findings.some((finding) => finding.id === "security.lockfile" && /missing/i.test(finding.title)), false);
});

test("binary bun.lockb is retained as a metadata-only dependency lockfile", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-bun-lock-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, "bun.lockb"), Buffer.from([0, 1, 2, 3]));

  const inventory = await collectFiles(root);
  const lockfile = inventory.files.find((file) => file.name === "bun.lockb");
  assert.ok(lockfile);
  assert.equal(lockfile.contentReadable, false);
  assert.equal(lockfile.skippedReason, "binary");
});
