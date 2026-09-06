import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  throw new Error("Run this verifier through `npm run package:check` so the active npm CLI is known.");
}

const tempRoot = await realpath(os.tmpdir());
const cacheDirectory = await mkdtemp(path.join(tempRoot, "modular-package-check-"));
let packed;
try {
  packed = spawnSync(
    process.execPath,
    [npmCli, "pack", "--dry-run", "--json", "--ignore-scripts", "--cache", cacheDirectory],
    {
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
      shell: false,
    },
  );
} finally {
  const realCache = await realpath(cacheDirectory);
  if (path.dirname(realCache).toLowerCase() !== tempRoot.toLowerCase() || !path.basename(realCache).startsWith("modular-package-check-")) throw new Error("Refusing cleanup outside the package fixture.");
  await rm(realCache, { recursive: true, force: true });
}

if (packed.error) throw packed.error;
if (packed.status !== 0) {
  process.stderr.write(packed.stderr || packed.stdout);
  process.exit(packed.status ?? 1);
}

let result;
try {
  [result] = JSON.parse(packed.stdout);
} catch (error) {
  throw new Error(`npm returned an unreadable package inventory: ${error.message}`);
}

if (!result || result.name !== "modular-check" || !Array.isArray(result.files)) {
  throw new Error("npm package inventory does not describe modular-check.");
}

const paths = result.files.map(({ path }) => String(path).replaceAll("\\", "/"));
// Internal modules are packaged individually; retain a bounded inventory after extraction.
const MAX_PACKAGE_FILES = 96;
const required = [
  "README.md",
  "LICENSE",
  "modular.schema.json",
  "SECURITY.md",
  "CHANGELOG.md",
  "assets/modular-logo.png",
  "bin/modular.js",
  "package.json",
  "src/index.js",
  "src/index.d.ts",
  "src/cli.d.ts",
  "src/runtime/index.d.ts",
  "docs/README.tr.md",
  "docs/GITHUB.md",
  "docs/README.md",
  "docs/getting-started.md",
  "docs/cli.md",
  "docs/configuration.md",
  "docs/reports.md",
  "docs/coverage.md",
  "docs/runtime.md",
  "docs/ci.md",
  "docs/troubleshooting.md",
  "docs/api.md",
  "docs/architecture.md",
  "examples/README.md",
  "examples/basic-site/index.html",
];
for (const expected of required) {
  if (!paths.includes(expected)) throw new Error(`Required package file is missing: ${expected}`);
}

const allowedTopLevel = new Set([
  "CHANGELOG.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "LICENSE",
  "modular.schema.json",
  "README.md",
  "RELEASING.md",
  "SECURITY.md",
  "assets",
  "docs",
  "examples",
  "bin",
  "package.json",
  "scripts",
  "src",
]);
const forbidden = /(?:^|\/)(?:audit|\.env(?:\..*)?|\.git|node_modules|test|tests|coverage|Modular)(?:\/|$)|\.(?:key|pem|p12|pfx|tgz|log)$/i;

for (const entry of paths) {
  const topLevel = entry.split("/", 1)[0];
  if (!allowedTopLevel.has(topLevel)) throw new Error(`Unexpected top-level package path: ${entry}`);
  if (forbidden.test(entry)) throw new Error(`Sensitive or development-only package path: ${entry}`);
}

const packedPaths = new Set(paths);
for (const entry of paths.filter(file => file.endsWith(".md"))) {
  const markdown = await readFile(entry, "utf8");
  for (const [, target] of markdown.matchAll(/!?\[[^\]]*\]\(([^)\s]+)(?:\s+["'][^)]*["'])?\)/g)) {
    if (/^(?:[a-z]+:|#)/i.test(target)) continue;
    const decoded = decodeURIComponent(target.split("#", 1)[0]);
    const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(entry), decoded));
    if (!packedPaths.has(resolved)) throw new Error(`Packaged Markdown link points outside the archive: ${entry} -> ${target}`);
  }
}

if (new Set(paths).size !== paths.length) throw new Error("npm package inventory contains duplicate paths.");
if (result.entryCount !== paths.length) throw new Error("npm package entry count does not match its inventory.");
if (paths.length > MAX_PACKAGE_FILES) throw new Error(`Package contains unexpectedly many files: ${paths.length}`);
if (Number(result.unpackedSize) > 2 * 1024 * 1024) {
  throw new Error(`Unpacked package exceeds the 2 MiB release budget: ${result.unpackedSize} bytes`);
}

const kib = (Number(result.size) / 1024).toFixed(1);
process.stdout.write(`Package contract OK: ${paths.length} files, ${kib} KiB archive.\n`);
