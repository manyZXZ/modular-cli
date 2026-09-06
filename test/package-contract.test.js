import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const root = path.resolve(".");

async function readJson(relative) {
  return JSON.parse(await readFile(path.join(root, relative), "utf8"));
}

test("npm manifest exposes a public, supported, zero-runtime-dependency package", async () => {
  const manifest = await readJson("package.json");

  assert.equal(manifest.name, "modular-check");
  assert.match(manifest.version, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  assert.equal(manifest.private, undefined);
  assert.equal(manifest.license, "MIT");
  assert.equal(manifest.engines.node, ">=22.12.0");
  assert.deepEqual(manifest.dependencies, undefined);
  assert.deepEqual(manifest.optionalDependencies, undefined);
  assert.equal(manifest.publishConfig.access, "public");
  assert.equal(manifest.publishConfig.provenance, true);
  assert.equal(manifest.bin.modular, "bin/modular.js");
  assert.equal(manifest.exports["."], "./src/index.js");
  assert.equal(manifest.types, "./src/index.d.ts");
});

test("every explicitly packed path and public entry point exists", async () => {
  const manifest = await readJson("package.json");
  const requiredFiles = [
    ...manifest.files,
    manifest.main,
    manifest.types,
    ...Object.values(manifest.bin),
    ...Object.values(manifest.exports),
  ];

  await Promise.all(requiredFiles.map(async (relative) => {
    const cleaned = relative.replace(/^\.\//, "");
    await access(path.join(root, cleaned));
  }));
});

test("CLI entry has a portable Node shebang and release policies are present", async () => {
  const entry = await readFile(path.join(root, "bin/modular.js"), "utf8");
  assert.equal(entry.split(/\r?\n/, 1)[0], "#!/usr/bin/env node");

  await Promise.all([
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "RELEASING.md",
    "docs/README.tr.md",
    "docs/GITHUB.md",
    "examples/README.md",
    "scripts/verify-package.js",
  ].map((relative) => access(path.join(root, relative))));
});

test("local Markdown links resolve inside the repository", async () => {
  const documents = [
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "RELEASING.md",
  ];

  for (const relative of documents) {
    const content = await readFile(path.join(root, relative), "utf8");
    const links = content.matchAll(/!?\[[^\]]*\]\(([^)\s]+)(?:\s+["'][^)]*["'])?\)/g);
    for (const [, target] of links) {
      if (/^(?:[a-z]+:|#)/i.test(target)) continue;
      const decoded = decodeURIComponent(target.split("#", 1)[0]);
      const resolved = path.resolve(root, path.dirname(relative), decoded);
      assert.ok(
        resolved === root || resolved.startsWith(`${root}${path.sep}`),
        `${relative} contains an out-of-repository link: ${target}`,
      );
      await access(resolved);
    }
  }
});
