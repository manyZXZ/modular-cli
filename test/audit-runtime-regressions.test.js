import test from "node:test";
// Run: node audit/2026-09-05/runtime-site-repro.mjs
// Deterministic audit reproductions; no optional packages or external requests.
// Runtime uses the real callbacks supplied to the public injected browser adapter,
// executed in an isolated VM. This is not a real-browser integration test.
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { collectFiles } from "../src/core/files.js";
import { runSiteScan } from "../src/scanners/mysite.js";
import { runRuntimeBrowserAudit } from "../src/runtime/browser-audit.js";
import { startRuntimeStaticServer } from "../src/runtime/static-server.js";

test("runtime callbacks, native names, HTML titles and directory redirects match their contracts", async () => {
const observations = [];
const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-site-audit-repro-"));
const baseline = {
  title: "OK",
  document: {
    h1Count: 1, landmarkCount: 1, language: "en", languageValid: true,
    viewportConfigured: true, metaDescriptionPresent: true, canonicalPresent: true,
  },
  performance: {
    largestContentfulPaintMs: 100, cumulativeLayoutShift: 0,
    longTaskCount: 0, longTaskDurationMs: 0, maxLongTaskMs: 0,
  },
};

function adapters({ headers = {}, controls = null, shifts = null, missingLcp = false } = {}) {
  let init;
  const observers = new Map();
  class PerformanceObserver {
    static supportedEntryTypes = ["layout-shift", "largest-contentful-paint", "longtask"];
    constructor(callback) { this.callback = callback; }
    observe({ type }) { observers.set(type, this.callback); }
  }
  const document = {
    title: "OK", documentElement: { lang: "en", scrollWidth: 390 },
    body: { scrollWidth: 390 }, images: [],
    querySelectorAll(selector) {
      if (selector === 'input:not([type="hidden"]), select, textarea') return controls ?? [];
      if (selector === "h1" || selector.startsWith("main,")) return [{}];
      return [];
    },
    querySelector(selector) {
      if (selector === 'link[rel~="canonical"]') return { href: "https://example.test/" };
      if (selector === 'meta[name="description"]') return { getAttribute: () => "Good" };
      if (selector === 'meta[name="viewport"]') return {};
      return null;
    },
  };
  const sandbox = vm.createContext({
    document, innerWidth: 390, innerHeight: 844, PerformanceObserver,
    performance: { getEntriesByType: () => [] },
    getComputedStyle: () => ({ display: "block", visibility: "visible", contentVisibility: "visible" }),
    CSS: { escape: (value) => value },
  });
  const page = {
    on() {},
    async goto() {
      return {
        status: () => 200,
        headers: () => ({
          "content-type": "text/html", "x-content-type-options": "nosniff",
          "referrer-policy": "strict-origin-when-cross-origin", ...headers,
        }),
      };
    },
    url: () => "http://127.0.0.1:3000/",
    async evaluate(callback) {
      if (!(controls || shifts || missingLcp)) return baseline;
      vm.runInContext(`(${init.toString()})({allowRemote:true})`, sandbox);
      if (shifts) observers.get("layout-shift")({ getEntries: () => shifts });
      return vm.runInContext(`(${callback.toString()})()`, sandbox);
    },
    async waitForLoadState() {},
    async waitForTimeout() {},
  };
  class AxeBuilder {
    async analyze() { return { violations: [], incomplete: [], passes: [] }; }
  }
  return {
    AxeBuilder,
    playwright: { chromium: {
      async launch() {
        return {
          async newContext() {
            return {
              async route() {}, async routeWebSocket() {},
              async addInitScript(callback) { init = callback; },
              async newPage() { return page; }, async close() {},
            };
          },
          async close() {},
        };
      },
    } },
  };
}

async function audit(options) {
  return runRuntimeBrowserAudit({
    enabled: true, root, url: "http://127.0.0.1:3000/", adapters: adapters(options),
  });
}
const findingIds = (result, prefix) => result.findings.filter(({ id }) => id.includes(prefix)).map(({ id }) => id);

try {
  const filler = Array.from({ length: 15 }, (_, index) => `https://cdn${index}.example.test`).join(" ");
  for (const [name, csp] of [
    ["short", "default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'"],
    ["long", `default-src 'self'; img-src ${filler}; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'`],
  ]) {
    const result = await audit({ headers: { "content-security-policy": csp } });
    const ids = findingIds(result, "runtime.header-");
    assert.deepEqual(ids, ["runtime.header-csp-unsafe-eval"]);
    observations.push({
      case: `csp-${name}`, source: "src/runtime/browser-audit.js:838", input: csp,
      inputLength: csp.length,
      storedLength: result.metrics.routes[0].responseHeaders["content-security-policy"].length,
      expected: ["runtime.header-csp-unsafe-eval"], actual: ids,
    });
  }

  const control = (attributes) => ({
    hidden: false, getAttribute: (name) => attributes[name] ?? null, closest: () => null,
  });
  for (const [name, html, controls, expectedCount, actualCount] of [
    ["valid-native-submit", '<input type="submit" value="Send">', [control({ type: "submit", value: "Send" })], 0, 0],
    ["invalid-aria-reference", '<input type="text" aria-labelledby="missing-id">', [control({ type: "text", "aria-labelledby": "missing-id" })], 1, 1],
  ]) {
    const result = await audit({ controls });
    const count = result.metrics.routes[0].metrics.document.unlabeledFormControlCount;
    assert.equal(count, actualCount);
    observations.push({
      case: name, source: "src/runtime/browser-audit.js:631", input: html,
      expectedUnlabeledCount: expectedCount, actualUnlabeledCount: count,
      findings: findingIds(result, "runtime.unlabeled-controls"),
    });
  }

  const shifts = [1000, 3000, 5000].map((startTime) => ({ startTime, value: 0.08, hadRecentInput: false }));
  const clsResult = await audit({ shifts });
  const cls = clsResult.metrics.routes[0].metrics.performance.cumulativeLayoutShift;
  assert.equal(cls, 0.08);
  for (const [events, expected] of [
    [[0, 500, 900].map((startTime) => ({ startTime, value: 0.08 })), 0.24],
    [[0, 1000].map((startTime) => ({ startTime, value: 0.08 })), 0.08],
    [[0, 800, 1600, 2400, 3200, 4000, 4800, 5600].map((startTime) => ({ startTime, value: 0.01 })), 0.07],
    [[{ startTime: 0, value: 0.9, hadRecentInput: true }, { startTime: 100, value: 0.01 }], 0.01],
  ]) {
    const measured = (await audit({ shifts: events })).metrics.routes[0].metrics.performance.cumulativeLayoutShift;
    assert.ok(Math.abs(measured - expected) < 1e-10, `${measured} should equal ${expected}`);
  }
  observations.push({
    case: "separate-cls-session-windows", source: "src/runtime/browser-audit.js:509", input: shifts,
    expectedCLS: 0.08, actualCLS: cls, findings: findingIds(clsResult, "cls-"),
    reference: "https://web.dev/articles/cls",
  });

  const noLcp = await audit({ missingLcp: true });
  const performanceCheck = noLcp.metadata.checks.find(({ id }) => id === "runtime-lab-performance");
  assert.equal(noLcp.metrics.routes[0].metrics.performance.largestContentfulPaintMs, null);
  assert.equal(performanceCheck.status, "partial");
  observations.push({
    case: "lcp-supported-without-entry", source: "src/runtime/browser-audit.js:1967",
    expected: "partial performance coverage until LCP is measured",
    actual: { status: noLcp.status, lcp: null, check: performanceCheck },
  });

  for (const [name, headTitle, expectedIds] of [
    ["head-title-and-svg-title", "<title>Home</title>", []],
    ["svg-title-only", "", ["seo-missing-title"]],
  ]) {
    const html = `<!doctype html><html lang="en"><head>${headTitle}<meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="description" content="Home"><link rel="canonical" href="https://example.test/"></head><body><main><h1>Home</h1><svg role="img" aria-label="Logo"><title>Logo</title></svg><button>Save</button></main></body></html>`;
    await fs.writeFile(path.join(root, "index.html"), html);
    const { files } = await collectFiles(root);
    const result = await runSiteScan({ root, files, options: { includeManualReviews: false } });
    const actualIds = result.findings.filter(({ ruleFamily }) => ruleFamily === "document-title").map(({ id }) => id);
    assert.deepEqual(actualIds, expectedIds);
    observations.push({
      case: name, source: "src/scanners/mysite.js:2148", input: html,
      expected: expectedIds, actual: actualIds,
      additionalLedgerObservation: result.metadata.checkLedger.filter(({ id }) =>
        ["interaction-feedback", "mobile-first-readiness"].includes(id)),
    });
  }

  await fs.mkdir(path.join(root, "dist", "docs"), { recursive: true });
  await fs.writeFile(path.join(root, "dist", "index.html"), "<title>Root</title>");
  await fs.writeFile(path.join(root, "dist", "docs", "index.html"), '<script src="./app.js"></script>');
  await fs.writeFile(path.join(root, "dist", "docs", "app.js"), "console.log(1)");
  const server = await startRuntimeStaticServer({ enabled: true, root, directory: "dist" });
  try {
    const response = await fetch(new URL("docs", server.url), { redirect: "manual" });
    const documentUrl = new URL(response.headers.get("location"), response.url);
    const relativeAsset = new URL("./app.js", documentUrl);
    const assetResponse = await fetch(relativeAsset);
    assert.equal(response.status, 308);
    assert.equal(assetResponse.status, 200);
    observations.push({
      case: "slashless-directory", source: "src/runtime/static-server.js:210",
      expected: "redirect /docs to /docs/ before serving docs/index.html",
      actual: { status: response.status, location: response.headers.get("location"),
        resolvedAssetPath: relativeAsset.pathname, assetStatus: assetResponse.status },
    });
  } finally {
    await server.close();
  }
} finally {
  const resolvedFixtureRoot = await fs.realpath(root);
  const resolvedTempRoot = await fs.realpath(os.tmpdir());
  assert.equal(path.dirname(resolvedFixtureRoot).toLowerCase(), resolvedTempRoot.toLowerCase());
  assert.match(path.basename(resolvedFixtureRoot), /^modular-site-audit-repro-/);
  await fs.rm(resolvedFixtureRoot, { recursive: true, force: true });
}

});
