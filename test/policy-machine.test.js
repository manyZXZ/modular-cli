import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { parseCliArguments, runCli } from "../src/cli.js";
import { loadProjectConfiguration, validateProjectConfiguration } from "../src/core/config.js";
import {
  MACHINE_REPORT_FILES,
  MACHINE_REPORT_LOCK_FILE,
  createJsonReport,
  createSarifReport,
  stableJson,
  writeMachineReports,
} from "../src/core/machine-reporter.js";
import { buildScanResult, createFinding } from "../src/core/model.js";
import {
  applyFindingPolicy,
  createBaselineDocument,
  findingFingerprint,
  fingerprintFindings,
  findingsAtOrAbove,
  loadBaseline,
  writeBaseline,
} from "../src/core/policy.js";

async function temporaryDirectory(t, prefix = "modular-policy-") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

function finding(overrides = {}) {
  return createFinding({
    id: "security.example",
    title: "Example security signal",
    category: "Security",
    severity: "high",
    confidence: "high",
    description: "A concrete review signal was found.",
    recommendation: "Replace the unsafe behavior and add a regression test.",
    evidence: "dangerousCall(userInput)",
    file: "src/app.js",
    line: 10,
    suggestedFiles: ["src/app.js"],
    tags: ["cwe-79"],
    ...overrides,
  });
}

function scan(root, findings, mode = "security") {
  return buildScanResult({
    mode,
    title: mode === "security" ? "Security report" : "Site report",
    root,
    findings,
    checks: 3,
    filesScanned: 2,
    startedAt: Date.now() - 5,
  });
}

function captureStream() {
  let output = "";
  return { isTTY: false, write(value) { output += String(value); }, text() { return output; } };
}

function runMachineWriterChild(root, outputDirectory, version, readyDirectory) {
  const source = `
import { promises as fs } from "node:fs";
import path from "node:path";
import { buildScanResult, createFinding } from "./src/core/model.js";
import { applyFindingPolicy } from "./src/core/policy.js";
import { writeMachineReports } from "./src/core/machine-reporter.js";
const [root, outputDirectory, version, readyDirectory] = process.argv.slice(1);
const signal = path.join(readyDirectory, version + ".ready");
await fs.writeFile(signal, "ready");
while (true) {
  try { await fs.access(path.join(readyDirectory, "go")); break; }
  catch { await new Promise((resolve) => setTimeout(resolve, 5)); }
}
const result = buildScanResult({
  mode: "security", title: "Child " + version, root,
  findings: [createFinding({ id: "security.child", title: "Child " + version, category: "Security", severity: "high" })],
  checks: 1, filesScanned: 1, startedAt: Date.now() - 1,
});
await writeMachineReports([applyFindingPolicy(result)], {
  outputDirectory, formats: ["json", "sarif"], toolVersion: version,
});
`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", source, root, outputDirectory, version, readyDirectory], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve() : reject(new Error(`machine writer child exited ${code}: ${stderr}`)));
  });
}

function runBaselineWriterChild(root, target, mode, version, readyDirectory) {
  const source = `
import { promises as fs } from "node:fs";
import path from "node:path";
import { buildScanResult, createFinding } from "./src/core/model.js";
import { loadBaseline, writeBaseline } from "./src/core/policy.js";
const [root, target, mode, version, readyDirectory] = process.argv.slice(1);
const previous = await loadBaseline(target);
await fs.writeFile(path.join(readyDirectory, mode + ".ready"), "ready");
while (true) {
  try { await fs.access(path.join(readyDirectory, "go")); break; }
  catch { await new Promise((resolve) => setTimeout(resolve, 5)); }
}
const result = buildScanResult({
  mode, title: "Child " + mode, root,
  findings: [createFinding({
    id: mode + ".child", title: "Child " + mode, category: mode === "security" ? "Security" : "SEO",
    severity: "high", evidence: "child-" + mode,
  })],
  checks: 1, filesScanned: 1, startedAt: Date.now() - 1,
});
await writeBaseline(target, [result], {
  root, previous, toolVersion: version, baselineLockTimeoutMs: 10_000,
});
`;
  const child = spawn(
    process.execPath,
    ["--input-type=module", "-e", source, root, target, mode, version, readyDirectory],
    { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
  );
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => code === 0
      ? resolve()
      : reject(new Error(`baseline writer child exited ${code}: ${stderr}`)));
  });
}

test("finding fingerprints survive line movement but distinguish changed evidence", () => {
  const first = finding({ line: 10 });
  const moved = finding({ line: 500 });
  const changed = finding({ line: 10, evidence: "differentCall(userInput)" });

  assert.equal(findingFingerprint("security", first), findingFingerprint("security", moved));
  assert.notEqual(findingFingerprint("security", first), findingFingerprint("security", changed));
  assert.notEqual(findingFingerprint("security", first), findingFingerprint("mysite", first));
  const repeated = fingerprintFindings("security", [first, moved]);
  assert.equal(new Set(repeated).size, 2);
  assert.equal(repeated[0], findingFingerprint("security", first));
});

test("configuration is strict, repository-scoped and supports auditable suppression policy", async (t) => {
  const root = await temporaryDirectory(t);
  const configPath = path.join(root, ".modular.json");
  await fs.writeFile(configPath, JSON.stringify({
    "$schema": "./node_modules/modular-check/modular.schema.json",
    failOn: "high",
    failOnNew: "medium",
    baseline: ".modular-baseline.json",
    ignore: ["generated"],
    outputFormats: ["sarif", "json"],
    suppressions: [{
      rule: "security.example",
      path: "src/**",
      reason: "Reviewed test fixture with no production reachability.",
      expires: "2099-12-31",
    }],
  }));

  const loaded = await loadProjectConfiguration({ root });
  assert.equal(loaded.path, configPath);
  assert.equal(loaded.config.baseline, path.join(root, ".modular-baseline.json"));
  assert.deepEqual(loaded.config.outputFormats, ["sarif", "json"]);
  assert.equal(loaded.config.suppressions[0].path, "src/**");

  assert.throws(
    () => validateProjectConfiguration({ failon: "high" }, root),
    /unknown field.*failon/i,
  );
  assert.throws(
    () => validateProjectConfiguration({ $schema: { url: "not-a-string" } }, root),
    /\$schema must be a non-empty string/i,
  );
  assert.throws(
    () => validateProjectConfiguration({ baseline: "../outside.json" }, root),
    /must stay inside/i,
  );
  assert.throws(
    () => validateProjectConfiguration({ suppressions: [{ rule: "x", reason: "short" }] }, root),
    /8.1000 characters/i,
  );
});

test("baseline and suppression policy remain visible while CI thresholds ignore accepted risk", () => {
  const root = path.resolve("fixture");
  const existing = finding();
  const added = finding({
    id: "security.second",
    title: "Second issue",
    evidence: "secondDanger()",
    file: "src/second.js",
    severity: "medium",
  });
  const previous = createBaselineDocument([scan(root, [existing])], {
    toolVersion: "1.0.0",
    generatedAt: "2026-01-01T00:00:00.000Z",
  });
  const baseline = {
    ...previous,
    keys: new Set(previous.entries.map((entry) => `${entry.mode}:${entry.fingerprint}`)),
  };
  const result = applyFindingPolicy(scan(root, [existing, added]), {
    baseline,
    now: new Date("2026-06-01T00:00:00.000Z"),
    suppressions: [
      { rule: "security.example", reason: "Reviewed and accepted until remediation.", expires: "2026-12-31" },
      { rule: "security.second", reason: "Expired risk acceptance must not apply.", expires: "2026-01-01" },
    ],
  });

  assert.equal(result.findings.find((item) => item.id === "security.example").baselineState, "unchanged");
  assert.equal(result.findings.find((item) => item.id === "security.second").baselineState, "new");
  assert.equal(result.metadata.policy.suppressions.matchedFindings, 1);
  assert.equal(result.metadata.policy.suppressions.expired, 1);
  assert.deepEqual(findingsAtOrAbove(result, "high"), []);
  assert.deepEqual(findingsAtOrAbove(result, "medium", { newOnly: true }).map((item) => item.id), ["security.second"]);
});

test("baseline detects an added duplicate occurrence without depending on absolute line numbers", () => {
  const root = path.resolve("fixture");
  const first = finding({ line: 10 });
  const previous = createBaselineDocument([scan(root, [first])]);
  const baseline = {
    ...previous,
    keys: new Set(previous.entries.map((entry) => `${entry.mode}:${entry.fingerprint}`)),
  };
  const current = applyFindingPolicy(scan(root, [
    finding({ line: 100 }),
    finding({ line: 200 }),
  ]), { baseline });

  assert.equal(current.metadata.policy.baseline.unchangedFindings, 1);
  assert.equal(current.metadata.policy.baseline.newFindings, 1);
  assert.equal(new Set(current.findings.map((item) => item.fingerprint)).size, 2);
});

test("baseline writer validates ownership, replaces safely and preserves unscanned modes", async (t) => {
  const root = await temporaryDirectory(t);
  const target = path.join(root, ".modular-baseline.json");
  const security = applyFindingPolicy(scan(root, [finding()]), {});
  const site = applyFindingPolicy(scan(root, [finding({ id: "site.title", category: "SEO" })], "mysite"), {});

  await writeBaseline(target, [security, site], { toolVersion: "1.0.0" });
  const first = await loadBaseline(target);
  assert.deepEqual(first.entries.map((entry) => entry.mode), ["mysite", "security"]);

  const replacement = applyFindingPolicy(scan(root, [finding({ id: "security.replacement" })]), {});
  await writeBaseline(target, [replacement], { previous: first, toolVersion: "1.1.0" });
  const second = await loadBaseline(target);
  assert.deepEqual(second.entries.map((entry) => entry.mode), ["mysite", "security"]);
  assert.equal(second.entries.some((entry) => entry.ruleId === "site.title"), true);
  assert.equal(second.entries.some((entry) => entry.ruleId === "security.example"), false);
  assert.deepEqual((await fs.readdir(root)).filter((name) => name.endsWith(".tmp")), []);

  await fs.writeFile(target, JSON.stringify({ user: "owned" }));
  await assert.rejects(writeBaseline(target, [security], { previous: first }), /not a Modular baseline/i);
});

test("separate processes merge concurrent baseline updates without losing an unscanned mode", async (t) => {
  const root = await temporaryDirectory(t, "modular-baseline-process-");
  const target = path.join(root, ".modular-baseline.json");
  const readyDirectory = path.join(root, "coordination");
  await fs.mkdir(readyDirectory);
  await writeBaseline(target, [
    scan(root, [finding({ id: "security.seed", evidence: "security-seed" })]),
    scan(root, [finding({ id: "mysite.seed", category: "SEO", evidence: "mysite-seed" })], "mysite"),
  ], { root, toolVersion: "1.0.0" });
  const children = [
    runBaselineWriterChild(root, target, "security", "1.0.1", readyDirectory),
    runBaselineWriterChild(root, target, "mysite", "1.0.2", readyDirectory),
  ];
  const deadline = Date.now() + 5_000;
  while ((await fs.readdir(readyDirectory)).filter((name) => name.endsWith(".ready")).length < children.length) {
    if (Date.now() >= deadline) throw new Error("baseline writer children did not reach the coordination barrier");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  await fs.writeFile(path.join(readyDirectory, "go"), "go");
  await Promise.all(children);

  const baseline = await loadBaseline(target);
  assert.deepEqual(baseline.modes, ["mysite", "security"]);
  assert.deepEqual(baseline.entries.map((entry) => entry.mode), ["mysite", "security"]);
  assert.deepEqual(
    baseline.entries.map((entry) => entry.ruleId).sort(),
    ["mysite.child", "security.child"],
  );
  assert.deepEqual(
    (await fs.readdir(root)).filter((name) => /modular-baseline\.lock$|\.tmp$|\.bak$/.test(name)),
    [],
  );
});

test("JSON and SARIF reports are portable, deterministic and preserve policy metadata", () => {
  const root = path.resolve("private", "project");
  const baselineDocument = createBaselineDocument([scan(root, [finding()])]);
  const baseline = {
    ...baselineDocument,
    keys: new Set(baselineDocument.entries.map((entry) => `${entry.mode}:${entry.fingerprint}`)),
  };
  const result = applyFindingPolicy(scan(root, [finding()]), {
    baseline,
    suppressions: [{ rule: "security.*", reason: "Reviewed and accepted for this fixture." }],
  });
  result.generatedAt = "2026-01-02T03:04:05.000Z";

  const json = createJsonReport([result], { toolVersion: "1.2.3" });
  assert.equal(json.results[0].root, ".");
  assert.equal(JSON.stringify(json).includes(root), false);
  assert.equal(json.results[0].findings[0].baselineState, "unchanged");
  assert.equal(stableJson(json), stableJson(createJsonReport([result], { toolVersion: "1.2.3" })));

  const sarif = createSarifReport([result], { toolVersion: "1.2.3" });
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.name, "Modular");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "src/app.js");
  assert.equal(sarif.runs[0].results[0].baselineState, "unchanged");
  assert.equal(sarif.runs[0].results[0].suppressions[0].status, "accepted");
  assert.match(sarif.runs[0].results[0].partialFingerprints["modular/v1"], /^[a-f0-9]{64}$/);
  assert.equal(
    sarif.runs[0].results[0].partialFingerprints["primaryLocationLineHash/v1"],
    sarif.runs[0].results[0].partialFingerprints["modular/v1"],
  );
});

test("machine writer commits both formats and refuses user-owned collisions", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  const result = applyFindingPolicy(scan(root, [finding()]), {});

  const paths = await writeMachineReports([result], {
    outputDirectory,
    formats: ["sarif", "json"],
    toolVersion: "1.2.3",
  });
  assert.deepEqual(paths.map((item) => path.basename(item)).sort(), Object.values(MACHINE_REPORT_FILES).sort());
  assert.equal(JSON.parse(await fs.readFile(path.join(outputDirectory, MACHINE_REPORT_FILES.json))).tool.name, "Modular");
  assert.equal(JSON.parse(await fs.readFile(path.join(outputDirectory, MACHINE_REPORT_FILES.sarif))).version, "2.1.0");
  assert.deepEqual((await fs.readdir(outputDirectory)).filter((name) => /\.tmp$|\.backup$/.test(name)), []);

  await writeMachineReports([result], {
    outputDirectory,
    formats: ["json", "sarif"],
    toolVersion: "1.2.4",
    complete: false,
    expectedModes: ["security", "mysite"],
  });
  const replacement = JSON.parse(await fs.readFile(path.join(outputDirectory, MACHINE_REPORT_FILES.json)));
  assert.equal(replacement.tool.version, "1.2.4");
  assert.equal(replacement.run.complete, false);
  assert.deepEqual(replacement.run.expectedModes, ["security", "mysite"]);

  await fs.writeFile(path.join(outputDirectory, MACHINE_REPORT_FILES.json), JSON.stringify({ user: "owned" }));
  await assert.rejects(
    writeMachineReports([result], { outputDirectory, formats: ["json"] }),
    /not generated by Modular/i,
  );
});

test("separate CLI processes cannot publish a mixed JSON and SARIF pair", async (t) => {
  const root = await temporaryDirectory(t, "modular-machine-process-");
  const outputDirectory = path.join(root, "Modular");
  const readyDirectory = path.join(root, "coordination");
  await fs.mkdir(readyDirectory);
  const children = ["1.0.1", "1.0.2", "1.0.3"].map((version) => (
    runMachineWriterChild(root, outputDirectory, version, readyDirectory)
  ));
  const deadline = Date.now() + 5_000;
  while ((await fs.readdir(readyDirectory)).filter((name) => name.endsWith(".ready")).length < children.length) {
    if (Date.now() >= deadline) throw new Error("machine writer children did not reach the coordination barrier");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  await fs.writeFile(path.join(readyDirectory, "go"), "go");
  await Promise.all(children);

  const json = JSON.parse(await fs.readFile(path.join(outputDirectory, MACHINE_REPORT_FILES.json)));
  const sarif = JSON.parse(await fs.readFile(path.join(outputDirectory, MACHINE_REPORT_FILES.sarif)));
  assert.equal(json.tool.version, sarif.runs[0].tool.driver.semanticVersion);
  assert.equal(json.results[0].title, sarif.runs[0].results[0].message.text);
  assert.equal((await fs.readdir(outputDirectory)).includes(MACHINE_REPORT_LOCK_FILE), false);
});

test("CLI auto-loads policy, writes machine artifacts and gates only baseline-new findings", async (t) => {
  const root = await temporaryDirectory(t, "modular-policy-cli-");
  const known = finding();
  const novel = finding({ id: "security.novel", file: "src/new.js", evidence: "novelDanger()" });
  const initial = applyFindingPolicy(scan(root, [known]), {});
  await writeBaseline(path.join(root, ".modular-baseline.json"), [initial], { toolVersion: "1.0.0" });
  await fs.writeFile(path.join(root, ".modular.json"), JSON.stringify({
    baseline: ".modular-baseline.json",
    failOnNew: "high",
    outputFormats: ["json", "sarif"],
  }));
  const stdout = captureStream();
  const stderr = captureStream();

  const code = await runCli(["check", "security", "--root", root, "--quiet"], {
    stdout,
    stderr,
    toolVersion: "1.0.0",
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSecurityScan: async () => scan(root, [known, novel]),
    setExitCode() {},
  });

  assert.equal(code, 3);
  const json = JSON.parse(await fs.readFile(path.join(root, "Modular", MACHINE_REPORT_FILES.json)));
  assert.equal(json.results[0].metadata.policy.baseline.newFindings, 1);
  assert.equal(json.results[0].metadata.policy.baseline.unchangedFindings, 1);
  assert.match(stderr.text(), /baseline threshold reached/i);
  assert.equal((await fs.readdir(path.join(root, "Modular"))).filter((name) => name.endsWith(".md")).length, 3);

  const parsed = parseCliArguments([
    "check", "mysite", "--runtime", "--url", "http://localhost:3000", "--runtime-viewport", "desktop",
  ]);
  assert.equal(parsed.runtimeViewport, "desktop");
  assert.throws(
    () => parseCliArguments(["check", "mysite", "--runtime", "--url", "http://localhost", "--runtime-viewport", "watch"]),
    /mobile or desktop/i,
  );
});

test("doctor is read-only and returns health status for the runtime, policy and website gate", async (t) => {
  const root = await temporaryDirectory(t, "modular-doctor-");
  const stdout = captureStream();
  const stderr = captureStream();
  let detectorWebsite = true;
  const runtime = {
    stdout,
    stderr,
    nodeVersion: "24.1.0",
    collectFiles: async () => ({ files: [{ relative: "index.html" }], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: detectorWebsite, framework: "Static HTML", confidence: 1 }),
    setExitCode() {},
  };

  assert.equal(await runCli(["doctor", "--root", root, "--no-color"], runtime), 0);
  assert.match(stdout.text(), /Doctor completed.*ready to scan/i);
  await assert.rejects(fs.access(path.join(root, "Modular")));

  detectorWebsite = false;
  assert.equal(await runCli(["doctor", "--root", root, "--no-color"], runtime), 1);
  assert.match(stderr.text(), /Website gate failed/i);

  assert.throws(
    () => parseCliArguments(["doctor", "--dependency-audit"]),
    /Unknown doctor option/i,
  );
});
