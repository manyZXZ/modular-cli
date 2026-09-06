import assert from "node:assert/strict";
import test from "node:test";

import {
  buildScanResult,
  createFinding,
  summarizeFindings,
  summarizeRuleFamilies,
} from "../src/core/model.js";
import { renderActionPlan, renderDetailedReport } from "../src/core/reporter.js";
import { TerminalUI } from "../src/core/ui.js";

function finding(overrides = {}) {
  return createFinding({
    id: "unsafe-navigation",
    title: "Unsafe navigation",
    category: "Browser security",
    severity: "high",
    confidence: "high",
    file: "src/page.js",
    ...overrides,
  });
}

function result(findings, metadata = {}) {
  return buildScanResult({
    mode: "mysite",
    title: "Website check",
    root: "C:\\repo",
    findings,
    checks: 4,
    filesScanned: 25,
    startedAt: Date.now() - 12,
    metadata,
  });
}

test("static review score groups repeated locations by rule family", () => {
  const once = summarizeFindings([finding()]);
  const repeated = summarizeFindings(Array.from({ length: 100 }, (_, index) => finding({
    file: `src/page-${index}.js`,
  })));
  const separateFamilies = summarizeFindings([
    finding(),
    finding({ id: "unsafe-html", file: "src/card.js" }),
  ]);

  assert.equal(once.score, 67);
  assert.equal(repeated.score, once.score);
  assert.equal(repeated.risk.repeatedSignalsExcluded, 99);
  assert.equal(repeated.risk.scoredRuleFamilies, 1);
  assert.equal(separateFamilies.score, 50);
});

test("different runtime signals in one declared family contribute only once", () => {
  const summary = summarizeFindings([
    finding({ id: "runtime.document-title", ruleFamily: "runtime-rendered-document", severity: "medium" }),
    finding({ id: "runtime.document-language", ruleFamily: "runtime-rendered-document", severity: "low" }),
    finding({ id: "runtime.missing-landmark", ruleFamily: "runtime-rendered-document", severity: "high" }),
  ]);

  assert.equal(summary.risk.scoredRuleFamilies, 1);
  assert.equal(summary.risk.contributions[0].id, "runtime-rendered-document");
  assert.equal(summary.risk.contributions[0].signalId, "runtime.missing-landmark");
  assert.equal(summary.risk.repeatedSignalsExcluded, 2);
});

test("static review score scales signals by confidence and manual validation", () => {
  const certain = summarizeFindings([finding()]);
  const lowConfidence = summarizeFindings([finding({ confidence: "low" })]);
  const manual = summarizeFindings([finding({ confidence: "medium", manual: true })]);
  const manyFamilies = summarizeFindings(Array.from({ length: 500 }, (_, index) => finding({
    id: `critical-${index}`,
    severity: "critical",
  })));

  assert.ok(lowConfidence.score > certain.score);
  assert.ok(manual.score > certain.score);
  assert.equal(manual.risk.manualReviewItems, 1);
  assert.equal(manyFamilies.score, 1);
  assert.equal(manyFamilies.risk.riskScore, 99);
});

test("rule-family assessment reports only applicability the scanner declares", () => {
  const assessment = summarizeRuleFamilies(4, {
    checks: [
      { id: "automated", status: "completed" },
      { id: "human", kind: "manual", status: "not-applicable" },
      { id: "disabled", status: "skipped" },
    ],
    dependencyAudit: { status: "skipped" },
  }, [finding(), finding({ id: "human-note", manual: true, severity: "info" })]);

  assert.deepEqual(assessment.ruleFamilies, {
    configured: 4,
    described: 3,
    automated: 2,
    manual: 1,
    unclassified: 1,
    applicable: 1,
    notApplicable: 1,
    skipped: 1,
    applicabilityUnknown: 1,
    optionalChecksSkipped: 1,
  });
  assert.deepEqual(assessment.findingSignals, { automated: 1, manualReview: 1 });
});

test("assessment counts scanner rule ids before metadata redaction", () => {
  const scan = result([], {
    checks: [
      "core-web-vitals-readiness",
      "navigation-information-architecture",
      "cross-platform-compatibility",
      "experimentation-ab-testing",
    ],
  });

  assert.equal(scan.metadata.assessment.ruleFamilies.configured, 4);
  assert.equal(scan.metadata.assessment.ruleFamilies.described, 4);
  assert.equal(scan.metadata.assessment.ruleFamilies.unclassified, 0);
  assert.deepEqual(scan.metadata.checks, [
    "core-web-vitals-readiness",
    "navigation-information-architecture",
    "cross-platform-compatibility",
    "experimentation-ab-testing",
  ]);
});

test("reports label rule families, scoring limits and manual validation honestly", () => {
  const scan = result([
    finding(),
    finding({
      id: "manual-browser-review",
      title: "Validate browser behavior",
      severity: "high",
      manual: true,
      confidence: "medium",
    }),
  ], {
    checks: ["one", "two", "three", "four"],
  });
  const detailed = renderDetailedReport(scan);
  const action = renderActionPlan(scan);

  assert.match(detailed, /static triage indicator, not a security, accessibility, SEO, UX, performance, or compliance guarantee/i);
  assert.match(detailed, /4 rule families/i);
  assert.match(detailed, /legacy `checks` field refers to rule families/i);
  assert.match(detailed, /risk=floor\(100\*rawPoints\/\(rawPoints\+60\)\)/);
  assert.match(detailed, /critical 75, high 30, medium 12, low 4, info 0/i);
  assert.match(detailed, /applicability.*4 unreported/i);
  assert.match(detailed, /1 automated, 1 requiring manual validation/i);
  assert.match(detailed, /Recorded scanner duration.*exclude repository discovery and report writing/i);
  assert.match(detailed, /score is not a fix count or effort estimate/i);
  assert.match(detailed, /detail cap.*more locations without changing the score/i);
  assert.match(action, /Validate — human or browser review[\s\S]*Validate browser behavior/);
  assert.match(action, /review signals, not confirmed defects/i);
  assert.match(action, /before editing source, rotating credentials, or changing security controls/i);
  const releaseBlockers = action.match(/Now — triage potential release blockers([\s\S]*?)(?:\n## |$)/)?.[1] ?? "";
  assert.doesNotMatch(releaseBlockers, /Validate browser behavior/);
});

test("terminal completion distinguishes rule families and manual-review items", () => {
  let output = "";
  const stream = {
    isTTY: false,
    write(value) {
      output += value;
    },
  };
  const scan = result([
    finding(),
    finding({ id: "manual", severity: "info", manual: true }),
  ], { checks: ["one", "two", "three", "four"] });

  new TerminalUI({ stream, color: false }).scanComplete(scan);

  assert.match(output, /static review/);
  assert.match(output, /static risk/);
  assert.match(output, /4 rule families/);
  assert.match(output, /1 automated signal · 1 manual-review item/);
  assert.match(output, /applicability unreported for 4/);
  assert.doesNotMatch(output, /4 checks/);
});

test("runtime-enriched reports label combined evidence and disclose sampled route metrics", () => {
  const scan = result([
    finding({
      id: "runtime.slow-lcp",
      ruleFamily: "runtime-lab-performance",
      title: "Observed LCP is slow",
      severity: "medium",
    }),
  ], {
    checks: ["one", "two", "three", "four"],
    runtime: {
      requested: true,
      status: "completed",
      target: "http://127.0.0.1:4173/",
      capabilities: {
        playwright: { browserName: "chromium", packageName: "playwright" },
        axe: { available: true, packageName: "axe-core" },
      },
      policy: { allowRemote: false, repositoryScriptsExecuted: false },
      stages: { launch: { status: "completed", durationMs: 5 } },
      metrics: {
        routesRequested: 1,
        routesAudited: 1,
        routesCompleted: 1,
        routesPartial: 0,
        routesFailed: 0,
        blockedRequests: 0,
        requestFailures: 0,
        consoleErrors: 0,
        pageErrors: 0,
        routes: [{
          url: "http://127.0.0.1:4173/",
          status: "completed",
          httpStatus: 200,
          metrics: { performance: { largestContentfulPaintMs: 1234, cumulativeLayoutShift: 0.012 } },
          accessibility: { violations: 0, incomplete: 1 },
          network: { consoleErrors: 0, pageErrors: 0 },
        }],
      },
    },
  });
  const detailed = renderDetailedReport(scan);
  const action = renderActionPlan(scan);
  let output = "";
  new TerminalUI({
    stream: { isTTY: false, write(value) { output += value; } },
    color: false,
  }).scanComplete(scan);

  assert.match(detailed, /Combined review score/i);
  assert.match(detailed, /Runtime browser audit/);
  assert.match(detailed, /1\/1 requested routes audited/);
  assert.match(detailed, /1,234 ms|1234 ms/);
  assert.match(detailed, /0\.012/);
  assert.match(detailed, /not field Core Web Vitals/i);
  assert.match(action, /modular check mysite --runtime/);
  assert.match(action, /preserving its target, route, browser and network-permission options/i);
  assert.match(output, /combined review/);
  assert.match(output, /combined risk/);
});

test("an unavailable runtime request never relabels a static score as combined", () => {
  const scan = result([], {
    checks: ["one", "two", "three", "four"],
    runtime: {
      requested: true,
      status: "unavailable",
      target: "http://127.0.0.1:4173/",
      capabilities: {
        playwright: { browserName: "chromium", packageName: "playwright" },
        axe: { available: false },
      },
      policy: { allowRemote: false, repositoryScriptsExecuted: false },
      stages: { launch: { status: "failed", durationMs: 5, reason: "browser missing" } },
      metrics: {
        routesRequested: 1,
        routesAudited: 0,
        routesCompleted: 0,
        routesPartial: 0,
        routesFailed: 1,
        routes: [{
          url: "http://127.0.0.1:4173/",
          status: "failed",
          httpStatus: null,
          stages: { page: { status: "timed-out", reason: "page timed out" } },
          metrics: null,
          accessibility: { status: "unavailable" },
          network: {},
        }],
      },
    },
  });
  const detailed = renderDetailedReport(scan);
  let output = "";
  new TerminalUI({
    stream: { isTTY: false, write(value) { output += value; } },
    color: false,
  }).scanComplete(scan);

  assert.match(detailed, /Static review score/i);
  assert.doesNotMatch(detailed, /Combined review score/i);
  assert.match(detailed, /\| unavailable \|/i);
  assert.match(detailed, /page.*timed-out.*page timed out/i);
  assert.match(output, /static review/);
  assert.doesNotMatch(output, /combined review/);
});
