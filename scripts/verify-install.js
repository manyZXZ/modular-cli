import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run this verifier through npm run package:smoke.");
const parent = await fs.realpath(os.tmpdir());
const fixture = await fs.mkdtemp(path.join(parent, "modular-installed-"));
const install = path.join(fixture, "clean install");
const cache = path.join(fixture, "cache");
function run(command, args, cwd, expected = 0) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", shell: false, timeout: 60_000, maxBuffer: 8 * 1024 * 1024 });
  if (result.error) throw result.error;
  if (result.status !== expected) throw new Error(`Command failed (expected ${expected}, got ${result.status}):\n${result.stderr || result.stdout}`);
  return result.stdout;
}
const npm = (args, cwd = root) => run(process.execPath, [npmCli, ...args, "--cache", cache], cwd);
try {
  const [archive] = JSON.parse(npm(["pack", "--json", "--ignore-scripts", "--pack-destination", fixture]));
  assert.equal(path.basename(archive.filename), archive.filename);
  const tarball = path.join(fixture, archive.filename);
  await fs.mkdir(install);
  await fs.writeFile(path.join(install, "package.json"), JSON.stringify({ name: "modular-install-verification", private: true }));
  npm(["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", tarball], install);
  const pkgRoot = path.join(install, "node_modules", "modular-check");
  const installed = JSON.parse(await fs.readFile(path.join(pkgRoot, "package.json"), "utf8"));
  const shim = path.join(install, "node_modules", ".bin", process.platform === "win32" ? "modular.cmd" : "modular");
  await fs.access(shim);
  // npm executes its generated local shim on both POSIX and Windows.
  const version = run(process.execPath, [npmCli, "exec", "--offline", "--no", "--cache", cache, "--", "modular", "--version"], install);
  assert.ok(version.includes(installed.version));
  const cli = path.join(pkgRoot, "bin", "modular.js");
  run(process.execPath, [cli, "--help"], install);
  run(process.execPath, ["--input-type=module", "--eval", "const api = await import('modular-check'); if (typeof api.runSecurityScan !== 'function' || typeof api.runSiteScan !== 'function') process.exit(1);"], install);
  const site = path.join(fixture, "sample site");
  await fs.cp(path.join(pkgRoot, "examples", "basic-site"), site, { recursive: true });
  const output = path.join(fixture, "scan reports");
  const args = [cli, "check", "all", "--root", site, "--output", output, "--json", "--sarif", "--no-color"];
  run(process.execPath, args, install);
  const result = JSON.parse(await fs.readFile(path.join(output, "modular-results.json"), "utf8"));
  assert.equal(result.run.complete, true);
  assert.deepEqual(result.results.map(r => r.mode).sort(), ["mysite", "security"]);
  assert.ok(result.results.some(r => r.findings.some(f => f.severity === "high")));
  assert.equal(JSON.parse(await fs.readFile(path.join(output, "modular-results.sarif"), "utf8")).version, "2.1.0");
  run(process.execPath, [...args, "--fail-on", "high"], install, 3);
  console.log(`Installed package OK: ${installed.name}@${installed.version}; local CLI shim, library import, two scans, JSON/SARIF and exit-code gate verified offline.`);
} finally {
  const real = await fs.realpath(fixture);
  if (path.dirname(real).toLowerCase() !== parent.toLowerCase() || !path.basename(real).startsWith("modular-installed-")) throw new Error("Refusing cleanup outside the install fixture.");
  await fs.rm(real, { recursive: true, force: true });
}
