import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execute = promisify(execFile);
const bin = path.resolve("bin/modular.js");

test("package manifest uses npm's canonical executable bin path", async () => {
  const manifest = JSON.parse(await fs.readFile(path.resolve("package.json"), "utf8"));
  const source = await fs.readFile(bin, "utf8");

  assert.equal(manifest.bin?.modular, "bin/modular.js");
  assert.match(source, /^#!\/usr\/bin\/env node(?:\r?\n)/);
});

async function makeWebsite(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-bin-site-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, "src"));
  await fs.writeFile(path.join(root, "package.json"), JSON.stringify({
    private: true,
    scripts: { dev: "vite" },
    dependencies: { react: "latest", "react-dom": "latest" },
    devDependencies: { vite: "latest" },
  }));
  await fs.writeFile(
    path.join(root, "index.html"),
    "<!doctype html><html><head></head><body><main id=\"root\"></main></body></html>",
  );
  await fs.writeFile(
    path.join(root, "src", "App.jsx"),
    "export function App({ html }) { return <main dangerouslySetInnerHTML={{__html: html}} />; }",
  );
  return root;
}

test("published bin shape runs all documented commands and leaves at most five reports", async (t) => {
  const root = await makeWebsite(t);
  const common = { cwd: root, windowsHide: true, timeout: 15_000, encoding: "utf8" };

  const security = await execute(process.execPath, [bin, "check", "security", "--no-color"], common);
  assert.match(security.stdout, /M O D U L A R/);
  assert.match(security.stdout, /Website project detected/);
  assert.match(security.stdout, /Scan complete/);
  assert.match(security.stdout, /src\/App\.jsx/);

  const site = await execute(process.execPath, [bin, "check", "mysite", "--no-color"], common);
  assert.match(site.stdout, /Website check/);
  assert.match(site.stdout, /100%/);

  const all = await execute(process.execPath, [bin, "check", "all", "--no-color"], common);
  assert.match(all.stdout, /Complete website check/);
  assert.match(all.stdout, /Phase 1 of 2/);
  assert.match(all.stdout, /Phase 2 of 2/);

  const reports = (await fs.readdir(path.join(root, "Modular"))).filter((name) => name.endsWith(".md"));
  assert.equal(reports.length, 5);
  assert.ok(reports.includes("01-security-report.md"));
  assert.ok(reports.includes("03-site-report.md"));
});

test("published bin shape exits 2 and creates no reports for a non-website", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-bin-cli-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ bin: { sample: "cli.js" } }));
  await fs.writeFile(path.join(root, "cli.js"), "console.log('not a website');");

  await assert.rejects(
    execute(process.execPath, [bin, "check", "mysite", "--no-color"], {
      cwd: root,
      windowsHide: true,
      timeout: 15_000,
      encoding: "utf8",
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /does not appear to be a website project/);
      return true;
    },
  );
  await assert.rejects(fs.access(path.join(root, "Modular")));
});

test("a closed stdout pipe does not crash an otherwise successful scan", async (t) => {
  const root = await makeWebsite(t);
  await Promise.all(Array.from({ length: 200 }, (_value, index) => (
    fs.writeFile(path.join(root, "src", `module-${index}.js`), `export const value${index} = ${index};\n`)
  )));

  const child = spawn(process.execPath, [bin, "check", "security", "--no-color"], {
    cwd: root,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.stdout.once("data", () => child.stdout.destroy());

  const outcome = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });

  assert.deepEqual(outcome, { code: 0, signal: null });
  assert.doesNotMatch(stderr, /EPIPE|unhandled/i);
  await fs.access(path.join(root, "Modular", "01-security-report.md"));
});

test("SIGTERM requests a deterministic graceful exit before reports are published", {
  skip: process.platform === "win32"
    ? "Windows child.kill uses forced process termination rather than a console SIGTERM event"
    : false,
}, async (t) => {
  const root = await makeWebsite(t);
  await Promise.all(Array.from({ length: 400 }, (_value, index) => (
    fs.writeFile(path.join(root, "src", `signal-${index}.js`), `export const signalValue${index} = ${index};\n`)
  )));

  const child = spawn(process.execPath, [bin, "check", "security", "--no-color"], {
    cwd: root,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.stdout.once("data", () => child.kill("SIGTERM"));

  const outcome = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });

  assert.deepEqual(outcome, { code: 143, signal: null });
  assert.match(stderr, /interrupted by SIGTERM/i);
  await assert.rejects(fs.access(path.join(root, "Modular")));
});
