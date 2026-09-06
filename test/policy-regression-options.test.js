import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildScanResult, createBaselineDocument, applyFindingPolicy, findingsAtOrAbove,
  collectFiles, runSiteScan, runCli, validateProjectConfiguration } from "../src/index.js";

test("severity increases are optional regressions and reapplying policy clears old suppressions", () => {
  const scan = (severity) => buildScanResult({ mode: "security", title: "Test", root: process.cwd(),
    findings: [{ id: "security.example", title: "Stable finding", category: "Security", severity, file: "a.js" }], checks: 1, filesScanned: 1 });
  const baseline = createBaselineDocument([scan("low")]);
  baseline.keys = new Set(baseline.entries.map((entry) => `${entry.mode}:${entry.fingerprint}`));
  const result = applyFindingPolicy(scan("critical"), { baseline });
  assert.equal(result.findings[0].baselineState, "unchanged");
  assert.equal(result.findings[0].baselineChange, "severity-increased");
  assert.equal(findingsAtOrAbove(result, "high", { newOnly: true }).length, 0);
  assert.equal(findingsAtOrAbove(result, "high", { regressionsOnly: true }).length, 1);
  const suppressed = applyFindingPolicy(result, { suppressions: [{ rule: "*", reason: "Reviewed during regression test" }] });
  assert.equal(findingsAtOrAbove(suppressed, "high").length, 0);
  assert.equal(findingsAtOrAbove(applyFindingPolicy(suppressed), "high").length, 1);
  assert.deepEqual(validateProjectConfiguration({ failOnRegression: "high", failOnIncomplete: true }, process.cwd()),
    { failOnRegression: "high", failOnIncomplete: true });
  assert.throws(() => validateProjectConfiguration({ failOnIncomplete: "true" }, process.cwd()), /boolean/);
});

test("explicit incomplete-coverage policy preserves reports but fails the CLI", async () => {
  const temp = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(temp, "modular-completeness-"));
  const stream = { write() {} };
  const run = (args) => runCli(["check", "security", "--root", root, "--quiet", ...args],
    { stdout: stream, stderr: stream, setExitCode() {} });
  try {
    await fs.writeFile(path.join(root, "index.html"), "<!doctype html><html lang=\"en\"><head><title>Site</title></head><body><main>Site</main></body></html>");
    await fs.writeFile(path.join(root, "oversized.js"), "a".repeat(1024));
    assert.equal(await run(["--max-file-size", "512"]), 0);
    assert.equal(await run(["--max-file-size", "512", "--fail-on-incomplete", "--json", "--sarif"]), 1);
    await fs.access(path.join(root, "Modular", "01-security-report.md"));
    const json = JSON.parse(await fs.readFile(path.join(root, "Modular", "modular-results.json"), "utf8"));
    const sarif = JSON.parse(await fs.readFile(path.join(root, "Modular", "modular-results.sarif"), "utf8"));
    assert.equal(json.run.complete, false);
    assert.equal(json.run.modesComplete, true);
    assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
    assert.equal(await run(["--fail-on-regression", "high"]), 2);
  } finally {
    const real = await fs.realpath(root);
    assert.equal(path.dirname(real).toLowerCase(), temp.toLowerCase());
    assert.ok(path.basename(real).startsWith("modular-completeness-"));
    await fs.rm(real, { recursive: true, force: true });
  }
});

test("CLI regression gate detects severity increases and honors accepted suppressions", async () => {
  const temp = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(temp, "modular-regression-gate-"));
  const stream = { write() {} };
  let severity = "low";
  const run = (args) => runCli(["check", "security", "--root", root, "--quiet", ...args], {
    stdout: stream, stderr: stream, setExitCode() {},
    runSecurityScan: async () => buildScanResult({ mode: "security", title: "Test", root,
      findings: [{ id: "security.example", title: "Stable finding", category: "Security", severity, file: "a.js" }],
      checks: 1, filesScanned: 1 }),
  });
  try {
    await fs.writeFile(path.join(root, "index.html"), '<!doctype html><html lang="en"><head><title>Site</title></head><body><main>Site</main></body></html>');
    assert.equal(await run(["--write-baseline", "baseline.json"]), 0);
    severity = "critical";
    assert.equal(await run(["--baseline", "baseline.json", "--fail-on-new", "high"]), 0);
    assert.equal(await run(["--baseline", "baseline.json", "--fail-on-regression", "high", "--json"]), 3);
    const json = JSON.parse(await fs.readFile(path.join(root, "Modular", "modular-results.json"), "utf8"));
    assert.equal(json.results[0].findings[0].baselineChange, "severity-increased");
    await fs.writeFile(path.join(root, ".modular.json"), JSON.stringify({
      suppressions: [{ rule: "security.example", reason: "Reviewed local regression fixture" }],
    }));
    assert.equal(await run(["--baseline", "baseline.json", "--fail-on-regression", "high"]), 0);
  } finally {
    const real = await fs.realpath(root);
    assert.equal(path.dirname(real).toLowerCase(), temp.toLowerCase());
    assert.ok(path.basename(real).startsWith("modular-regression-gate-"));
    await fs.rm(real, { recursive: true, force: true });
  }
});

test("site detail caps preserve all baseline identities and path-specific policy decisions", async () => {
  const temp = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(temp, "modular-site-policy-"));
  const page = (name) => `<!doctype html><html lang="en"><head><title>${name}</title></head><body><main><h1>${name}</h1><img src="${name}.png" width="20" height="20"></main></body></html>`;
  const scan = async () => runSiteScan({ root, ...await collectFiles(root), options: { maxFindingsPerRule: 1 } });
  try {
    await fs.writeFile(path.join(root, "index.html"), page("Home"));
    const first = await scan();
    const baseline = createBaselineDocument([first]);
    baseline.keys = new Set(baseline.entries.map((entry) => `${entry.mode}:${entry.fingerprint}`));
    await fs.writeFile(path.join(root, "z.html"), page("Contact"));
    const result = applyFindingPolicy(await scan(), { baseline,
      suppressions: [{ rule: "a11y-image-alt", path: "index.html", reason: "Reviewed old image fixture" }] });
    assert.equal(result.findings.filter(({ id }) => id === "a11y-image-alt").length, 1);
    const active = findingsAtOrAbove(result, "high", { newOnly: true }).filter(({ id }) => id === "a11y-image-alt");
    assert.equal(active.length, 1);
    assert.equal(active[0].file, "z.html");
    assert.equal(active[0].detailOmitted, true);
    assert.equal(createBaselineDocument([result]).entries.filter(({ ruleId }) => ruleId === "a11y-image-alt").length, 2);
  } finally {
    const real = await fs.realpath(root);
    assert.equal(path.dirname(real).toLowerCase(), temp.toLowerCase());
    assert.ok(path.basename(real).startsWith("modular-site-policy-"));
    await fs.rm(real, { recursive: true, force: true });
  }
});
