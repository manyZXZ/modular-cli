import test from "node:test";
// Read-only source audit. Creates only disposable fixtures under os.tmpdir().
// Run from any directory: node audit/2026-09-05/core-repro.mjs
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  applyFindingPolicy,
  buildScanResult,
  createBaselineDocument,
  findingsAtOrAbove,
  loadBaseline,
  runCli,
} from "../src/index.js";

test("policy gates use all findings and machine reports preserve incomplete requests", async () => {
const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "modular-core-audit-"));
const output = { audit: "CLI, policy, and machine-report reproducibility", cases: {} };
const quietStream = { write() {} };
const run = (root, args) => runCli([
  "check", "security", "--root", root, "--no-color", "--quiet", ...args,
], { stdout: quietStream, stderr: quietStream, setExitCode() {} });
const fixture = async (name) => {
  const root = path.join(temporaryRoot, name);
  await fs.mkdir(root);
  await fs.writeFile(path.join(root, "index.html"), '<!doctype html><html lang="en"><head><title>Home</title></head><body><main>Hello</main></body></html>');
  return root;
};
const readJson = async (file) => JSON.parse(await fs.readFile(file, "utf8"));

try {
  const root = await fixture("cap-policy");
  await fs.writeFile(path.join(root, "a.js"), "const a = import.meta.env.VITE_CLIENT_SECRET;");
  assert.equal(await run(root, ["--max-findings-per-rule", "1", "--write-baseline", "baseline.json"]), 0);
  await fs.writeFile(path.join(root, "z.js"), "const z = import.meta.env.VITE_OTHER_SECRET;");

  const capBaseline = [];
  for (const cap of [1, 50]) {
    const exitCode = await run(root, ["--max-findings-per-rule", String(cap), "--baseline", "baseline.json", "--fail-on-new", "high", "--json"]);
    const result = (await readJson(path.join(root, "Modular", "modular-results.json"))).results[0];
    capBaseline.push({
      cap, exitCode,
      retained: result.findings.filter((item) => item.id === "security.public-env-secrets").map(({ file, severity, baselineState }) => ({ file, severity, baselineState })),
      omitted: result.metadata.suppressedByRule["public-env-secrets"] ?? 0,
    });
  }
  assert.deepEqual(capBaseline.map(({ exitCode }) => exitCode), [3, 3]);
  output.cases.capHidesBaselineRegression = capBaseline;

  await fs.writeFile(path.join(root, ".modular.json"), JSON.stringify({
    suppressions: [{ rule: "security.public-env-secrets", path: "a.js", reason: "Accepted legacy fixture for audit reproduction." }],
  }));
  const capSuppression = [];
  for (const cap of [1, 50]) {
    const exitCode = await run(root, ["--max-findings-per-rule", String(cap), "--fail-on", "high", "--json"]);
    const result = (await readJson(path.join(root, "Modular", "modular-results.json"))).results[0];
    capSuppression.push({
      cap, exitCode,
      activeHigh: findingsAtOrAbove(result, "high").map(({ id, file }) => ({ id, file })),
      omitted: result.metadata.suppressedByRule["public-env-secrets"] ?? 0,
    });
  }
  assert.deepEqual(capSuppression.map(({ exitCode }) => exitCode), [3, 3]);
  output.cases.capHidesUnsuppressedFinding = capSuppression;

  const defaultCapRoot = await fixture("default-cap-policy");
  await fs.writeFile(path.join(defaultCapRoot, "a.js"), Array.from({ length: 50 }, (_, index) => `const old${index} = import.meta.env.VITE_OLD_SECRET_${index};`).join("\n"));
  assert.equal(await run(defaultCapRoot, ["--write-baseline", "baseline.json"]), 0);
  await fs.writeFile(path.join(defaultCapRoot, "z.js"), "const newSignal = import.meta.env.VITE_NEW_SECRET;");
  const defaultCapBaseline = [];
  for (const cap of [null, 51]) {
    const exitCode = await run(defaultCapRoot, [
      ...(cap === null ? [] : ["--max-findings-per-rule", String(cap)]),
      "--baseline", "baseline.json", "--fail-on-new", "high", "--json",
    ]);
    const result = (await readJson(path.join(defaultCapRoot, "Modular", "modular-results.json"))).results[0];
    defaultCapBaseline.push({
      cap: cap === null ? "default (50)" : cap, exitCode,
      retained: result.findings.filter((item) => item.id === "security.public-env-secrets").length,
      omitted: result.metadata.suppressedByRule["public-env-secrets"] ?? 0,
      newHigh: findingsAtOrAbove(result, "high", { newOnly: true }).map(({ id, file }) => ({ id, file })),
    });
  }
  assert.deepEqual(defaultCapBaseline.map(({ exitCode }) => exitCode), [3, 3]);
  output.cases.defaultCapHidesFiftyFirstFinding = defaultCapBaseline;

  const severityRoot = await fixture("severity-update");
  const signal = { id: "security.example-rule", title: "Example signal", category: "Example", file: "index.html", line: 1, evidence: "Stable semantic signal" };
  const makeResult = (severity) => buildScanResult({ mode: "security", title: "Example result", root: severityRoot, findings: [{ ...signal, severity }], checks: 1, filesScanned: 1 });
  const baselinePath = path.join(severityRoot, "baseline.json");
  await fs.writeFile(baselinePath, JSON.stringify(createBaselineDocument([makeResult("low")])));
  const severityBaseline = await loadBaseline(baselinePath);
  const escalated = applyFindingPolicy(makeResult("critical"), { baseline: severityBaseline });
  output.cases.severityEscalationIsNotNew = {
    classification: "Design gap: --fail-on-new is documented as fingerprint absence, not severity regression.",
    before: "low", after: "critical", baselineState: escalated.findings[0].baselineState,
    highGateMatches: findingsAtOrAbove(escalated, "high", { newOnly: true }).length,
  };
  assert.equal(escalated.findings[0].baselineState, "unchanged");

  const yarnRoot = await fixture("unavailable-audit");
  await fs.writeFile(path.join(yarnRoot, "package.json"), JSON.stringify({ name: "site", private: true, packageManager: "yarn@4.0.0", dependencies: { react: "18.3.1" } }));
  await fs.writeFile(path.join(yarnRoot, "yarn.lock"), "# yarn lockfile v1\n");
  // Yarn is rejected locally by the scanner's isolation policy. No manager or network call runs.
  const exitCode = await run(yarnRoot, ["--dependency-audit", "--json", "--sarif"]);
  const json = await readJson(path.join(yarnRoot, "Modular", "modular-results.json"));
  const sarif = await readJson(path.join(yarnRoot, "Modular", "modular-results.sarif"));
  output.cases.failedAuditReportedAsSuccessfulInvocation = {
    exitCode,
    dependencyStatus: json.results[0].metadata.dependencyAudit.status,
    jsonRunComplete: json.run.complete,
    sarifRunComplete: sarif.properties.modularRun.complete,
    sarifExecutionSuccessful: sarif.runs[0].invocations[0].executionSuccessful,
    auditReason: json.results[0].metadata.dependencyAudit.audits[0].reason,
  };
  assert.equal(exitCode, 1);
  assert.equal(output.cases.failedAuditReportedAsSuccessfulInvocation.dependencyStatus, "unavailable");
  assert.equal(output.cases.failedAuditReportedAsSuccessfulInvocation.sarifExecutionSuccessful, false);

} finally {
  const relation = path.relative(path.resolve(os.tmpdir()), path.resolve(temporaryRoot));
  if (!relation || relation === ".." || relation.startsWith(`..${path.sep}`) || path.isAbsolute(relation)) {
    throw new Error("Refusing cleanup outside the temporary fixture directory.");
  }
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

});
