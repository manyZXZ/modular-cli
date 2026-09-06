import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { serverDataFlowSignals } from "../src/scanners/security-dataflow.js";
import { lockfilePrivacyBlockReason } from "../src/scanners/security/audit-privacy.js";
import { resolveAuditInvocation } from "../src/scanners/security/audit-runtime.js";

const serverFile = { relative: "src/server/proxy.js" };
const ssrf = (source) => serverDataFlowSignals(serverFile, source).filter(({ ruleId }) => ruleId === "server-ssrf");
const handler = (body) => `export async function handler(req) {\n${body}\n}`;
const declaration = "let target = new URL(req.query.url);";
const guard = "if (target.hostname !== 'safe.example') return;";

test("Unicode code points preserve source-to-sink offsets and guarded controls", () => {
  for (const prefix of ["", "const icon = '🔍';\n", "// 🔍\n", "/* 🔍 🧪 */\n", "const label = `🔍`;\n"]) {
    const source = prefix + handler(`${declaration}\nreturn fetch(target);`);
    const signals = ssrf(source);
    assert.equal(signals.length, 1, prefix);
    assert.equal(signals[0].index, source.indexOf("fetch(target)"), prefix);
    assert.equal(ssrf(prefix + handler(`${declaration}\n${guard}\nreturn fetch(target);`)).length, 0, prefix);
    assert.equal(ssrf(prefix + handler("return fetch('https://safe.example/');")).length, 0, prefix);
  }
});

test("URL guards apply only to the current value on every path to the sink", () => {
  const unsafe = [
    `${guard}\ntarget = new URL(req.query.other);`,
    `${guard}\nif (req.query.other) target = new URL(req.query.other);`,
    `${guard}\ntarget.hostname = req.query.host;`,
    `${guard}\ntarget['hostname'] = req.query.host;`,
    `${guard}\n({ target } = req.body);`,
    `if (ENFORCE) { ${guard} }`,
    `if (ENFORCE)\n  ${guard}`,
    `if (check(')'))\n  ${guard}`,
    `while (ENFORCE) ${guard}`,
    `for (const item of items) ${guard}`,
    `for await (const item of items) ${guard}`,
    `function validate() { ${guard} }`,
    "if (target.hostname !== 'safe.example') { if (ENFORCE) return; }",
    `switch (mode) { case 'check': ${guard} case 'skip': return fetch(target); }`,
  ];
  for (const body of unsafe) {
    const source = handler(`${declaration}\n${body}\nreturn fetch(target);`);
    assert.ok(ssrf(source).length > 0, body);
  }
  const safe = [
    `${guard}\nreturn fetch(target);`,
    "if (!allowedHosts.has(target.hostname)) throw new Error('blocked');\nreturn fetch(target);",
    "if (!ALLOWED_ORIGINS.includes(target.origin)) { return; }\nreturn fetch(target);",
    `${guard}\nif (ENABLED) { return fetch(target); }`,
    `if (ENABLED) { ${guard}\nreturn fetch(target); }`,
    `target = new URL(req.query.other);\n${guard}\nreturn fetch(target);`,
    `${guard}\nconst same = target.hostname === 'safe.example';\nreturn fetch(target);`,
    `${guard}\n// target = new URL(req.query.other);\nreturn fetch(target);`,
    `${guard}\nconst message = 'target = req.query.other';\nreturn fetch(target);`,
    `recordCheck()\n${guard}\nreturn fetch(target);`,
    "if (target.hostname !== 'safe.example') return\nreturn fetch(target)",
    "if (target.hostname !== 'safe.example') return reject()\nreturn fetch(target)",
  ];
  for (const body of safe) assert.equal(ssrf(handler(`${declaration}\n${body}`)).length, 0, body);
  for (const body of [
    "if (target.hostname !== 'safe.example') return fetch(target);",
    "if (target.hostname !== 'safe.example') { return fetch(target); }",
    "if (target.hostname !== 'safe.example') return reject(fetch(target));",
  ]) assert.equal(ssrf(handler(`${declaration}\n${body}`)).length, 1, body);
});

test("valid registry integrity digests containing slashes are not dependency sources", () => {
  const integrity = `sha512-${createHash("sha512").update("fixture 71").digest("base64")}`;
  assert.ok(integrity.includes("//"), "fixture must exercise the protocol-relative false positive");
  const artifact = "https://registry.npmjs.org/example/-/example-1.0.0.tgz";
  for (const lockfile of [
    JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/example": { version: "1.0.0", resolved: artifact, integrity } } }),
    `lockfileVersion: '9.0'\npackages:\n  example@1.0.0:\n    resolution: {integrity: ${integrity}}\n`,
    `example@1.0.0:\n  version "1.0.0"\n  resolved "${artifact}"\n  integrity ${integrity}\n`,
    `integrity: "${integrity} sha256-${createHash("sha256").update("example").digest("base64")}"`,
    `integrity: ${integrity.replace(/=+$/, "")}`,
  ]) assert.equal(lockfilePrivacyBlockReason(lockfile), null, lockfile);

  for (const value of ["//packages.private.example/example.tgz", integrity, `sha512-${"A".repeat(10)}//evil`]) {
    assert.ok(lockfilePrivacyBlockReason(JSON.stringify({ resolved: value })), value);
  }
  assert.match(lockfilePrivacyBlockReason(`integrity: ${integrity}\nresolution: //private.example/package.tgz`), /protocol-relative/);
  assert.match(lockfilePrivacyBlockReason(`integrity: sha512-${"A".repeat(10)}//evil`), /protocol-relative/);
  assert.ok(lockfilePrivacyBlockReason(`integrity: "${integrity} https://private.example/package.tgz"`));
});

test("Windows audit resolution supports proven npm pnpm shims without executing them", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-audit-shims-"));
  const platform = Object.getOwnPropertyDescriptor(process, "platform");
  const originalPath = process.env.PATH;
  const originalExtensions = process.env.PATHEXT;
  t.after(async () => {
    Object.defineProperty(process, "platform", platform);
    if (originalPath === undefined) delete process.env.PATH; else process.env.PATH = originalPath;
    if (originalExtensions === undefined) delete process.env.PATHEXT; else process.env.PATHEXT = originalExtensions;
    assert.equal(path.dirname(root), os.tmpdir());
    assert.match(path.basename(root), /^modular-audit-shims-/);
    await fs.rm(root, { recursive: true, force: true });
  });
  Object.defineProperty(process, "platform", { ...platform, value: "win32" });
  const workspace = path.join(root, "repo");
  await fs.mkdir(workspace);
  await fs.writeFile(path.join(workspace, "pnpm.cjs"), "throw new Error('Repository code must never run');");
  process.env.PATHEXT = ".CMD";
  const scriptSuffix = ["node_modules", "pnpm", "bin", "pnpm.cjs"].join(path.sep);
  const fixtures = [
    ["npm-cmd", "cmd", `@ECHO off\nGOTO start\n:find_dp0\nSET dp0=%~dp0\nEXIT /b\n:start\nSETLOCAL\nCALL :find_dp0\n"%_prog%" "%dp0%${path.sep}${scriptSuffix}" %*`, true],
    ["npm-ps1", "ps1", '#!/usr/bin/env pwsh\n$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent\n& "node$exe" "$basedir/node_modules/pnpm/bin/pnpm.cjs" $args', true],
    ["legacy-cmd", "cmd", `"node" "%~dp0${scriptSuffix}" %*`, true],
    ["quoted-cmd-assignment", "cmd", `SET "dp0=%~dp0"\n"node" "%dp0%${path.sep}${scriptSuffix}" %*`, true],
    ["legacy-ps1", "ps1", '& "node" "$PSScriptRoot/node_modules/pnpm/bin/pnpm.cjs" $args', true],
    ["unknown-cmd-variable", "cmd", `"node" "%dp0%${path.sep}${scriptSuffix}" %*`, false],
    ["dynamic-cmd-variable", "cmd", `SET dp0=%EXTERNAL_TOOL_ROOT%\n"node" "%dp0%${path.sep}${scriptSuffix}" %*`, false],
    ["reassigned-cmd-variable", "cmd", `SET dp0=%~dp0\nSET dp0=elsewhere\n"node" "%dp0%${path.sep}${scriptSuffix}" %*`, false],
    ["unknown-ps1-variable", "ps1", '& "node" "$basedir/node_modules/pnpm/bin/pnpm.cjs" $args', false],
    ["dynamic-ps1-variable", "ps1", '$basedir=$env:EXTERNAL_TOOL_ROOT\n& "node" "$basedir/node_modules/pnpm/bin/pnpm.cjs" $args', false],
    ["reassigned-ps1-variable", "ps1", '$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent\n$basedir += "/other"\n& "node" "$basedir/node_modules/pnpm/bin/pnpm.cjs" $args', false],
    ["repository-script", "cmd", 'SET dp0=%~dp0\n"node" "%dp0%/../repo/pnpm.cjs" %*', false],
  ];
  for (const [name, extension, shim, expected] of fixtures) {
    const directory = path.join(root, name);
    const script = path.join(directory, scriptSuffix);
    await fs.mkdir(path.dirname(script), { recursive: true });
    await fs.writeFile(script, "throw new Error('Audit resolution must not execute this fixture');");
    await fs.writeFile(path.join(directory, `pnpm.${extension}`), shim);
    process.env.PATH = directory;
    const result = await resolveAuditInvocation("pnpm", ["audit", "--json"], workspace);
    if (!expected) assert.equal(result, null, name);
    else {
      assert.equal(result?.command, process.execPath, name);
      assert.deepEqual(result.args, [script, "audit", "--json"], name);
    }
    assert.equal(await resolveAuditInvocation("pnpm", ["audit"], directory), null, `${name}: workspace exclusion`);
  }
});
