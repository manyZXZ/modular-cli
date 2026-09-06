import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  MAX_RUNTIME_ROUTES,
  RuntimeAuditError,
  discoverRuntimeCapabilities,
  isLoopbackHostname,
  isRuntimeNetworkUrlAllowed,
  runRuntimeBrowserAudit,
  runtimeCheckDescriptors,
} from "../src/runtime/browser-audit.js";

async function temporaryRoot(t, prefix = "modular-runtime-") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

async function writeEntry(root, relative, value) {
  const destination = path.join(root, relative);
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.writeFile(destination, typeof value === "string" ? value : JSON.stringify(value, null, 2));
}

function baselineSnapshot(overrides = {}) {
  return {
    title: "Runtime page",
    document: {
      elementCount: 24,
      h1Count: 1,
      landmarkCount: 2,
      formControlCount: 1,
      unlabeledFormControlCount: 0,
      imageCount: 1,
      imagesWithoutDimensions: 0,
      brokenImageCount: 0,
      duplicateIdCount: 0,
      interactiveTargetCount: 2,
      undersizedTargetCount: 0,
      language: "en",
      languageValid: true,
      viewportConfigured: true,
      metaDescriptionPresent: true,
      canonicalPresent: true,
      canonicalUrl: "http://localhost:3000/",
      viewportWidth: 1_280,
      viewportHeight: 720,
      documentWidth: 1_280,
      horizontalOverflowPx: 0,
      ...overrides.document,
    },
    navigation: {
      responseStartMs: 25,
      domContentLoadedMs: 80,
      loadEventMs: 100,
      durationMs: 100,
      transferBytes: 2_000,
      decodedBodyBytes: 4_000,
      ...overrides.navigation,
    },
    performance: {
      firstContentfulPaintMs: 60,
      largestContentfulPaintMs: 120,
      cumulativeLayoutShift: 0,
      longTaskCount: 0,
      longTaskDurationMs: 0,
      maxLongTaskMs: 0,
      measurementSupport: {
        largestContentfulPaint: true,
        cumulativeLayoutShift: true,
        longTasks: true,
      },
      resourceCount: 3,
      resourceTransferBytes: 3_000,
      resourceDecodedBodyBytes: 5_000,
      ...overrides.performance,
    },
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => !["document", "navigation", "performance"].includes(key))),
  };
}

function evaluateWithControls(callback, controls) {
  const documentValue = {
    title: "Runtime page",
    documentElement: { lang: "en", scrollWidth: 1_280 },
    body: { scrollWidth: 1_280 },
    images: [],
    querySelectorAll(selector) {
      if (selector === 'input:not([type="hidden"]), select, textarea') return controls;
      if (selector === "h1" || selector.startsWith("main,")) return [{}];
      return [];
    },
    querySelector(selector) {
      if (selector === 'link[rel~="canonical"]') return { href: "http://localhost:3000/" };
      if (selector === 'meta[name="description"]') return { getAttribute: () => "Description" };
      if (selector === 'meta[name="viewport"]') return {};
      return null;
    },
  };
  const replacements = {
    document: documentValue,
    innerWidth: 1_280,
    innerHeight: 720,
    getComputedStyle: (control) => control.style,
  };
  const originals = new Map();
  for (const [name, value] of Object.entries(replacements)) {
    originals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  }
  try {
    return callback();
  } finally {
    for (const [name, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
}

function fakeControl({ hidden = false, excluded = false, style = {}, attributes = {} } = {}) {
  return {
    hidden,
    style: { display: "block", visibility: "visible", contentVisibility: "visible", ...style },
    getAttribute(name) {
      return attributes[name] ?? null;
    },
    closest(selector) {
      if (selector === "[hidden], [inert], [aria-hidden='true']") return excluded ? {} : null;
      return null;
    },
  };
}

function runtimeHarness(options = {}) {
  const state = {
    browserCloseCount: 0,
    contextCloseCount: 0,
    launchOptions: null,
    contextOptions: [],
    initScripts: 0,
    continued: [],
    aborted: [],
    continuedWebSockets: [],
    blockedWebSockets: [],
    navigated: [],
  };

  class FakeAxeBuilder {
    constructor({ page }) {
      this.page = page;
    }

    async analyze() {
      const axeError = typeof options.axeError === "function" ? options.axeError(this.page) : options.axeError;
      if (axeError) throw axeError;
      return options.axeResults ?? { violations: [], incomplete: [], passes: [{ id: "document-title" }] };
    }
  }

  const browser = {
    async newContext(contextOptions) {
      state.contextOptions.push(contextOptions);
      let routeHandler;
      let webSocketRouteHandler;
      let currentUrl = "about:blank";
      const handlers = new Map();
      const page = {
        on(name, handler) {
          const values = handlers.get(name) ?? [];
          values.push(handler);
          handlers.set(name, values);
        },
        async goto(url) {
          state.navigated.push(url);
          currentUrl = options.redirectUrl ?? url;
          if (options.hangNavigation) return new Promise(() => {});
          const navigationError = typeof options.navigationError === "function"
            ? options.navigationError(url)
            : options.navigationError;
          if (navigationError) throw navigationError;
          for (const requestUrl of options.requests ?? []) {
            await routeHandler({
              request: () => ({ url: () => requestUrl }),
              abort: async () => state.aborted.push(requestUrl),
              continue: async () => state.continued.push(requestUrl),
            });
          }
          for (const socketUrl of options.webSockets ?? []) {
            await webSocketRouteHandler?.({
              url: () => socketUrl,
              close: async (closeOptions) => state.blockedWebSockets.push({ url: socketUrl, ...closeOptions }),
              connectToServer: () => state.continuedWebSockets.push(socketUrl),
            });
          }
          for (const detail of options.consoleErrors ?? []) {
            for (const handler of handlers.get("console") ?? []) handler({ type: () => "error", text: () => detail });
          }
          for (const detail of options.pageErrors ?? []) {
            for (const handler of handlers.get("pageerror") ?? []) handler(new Error(detail));
          }
          for (const requestUrl of options.failedRequests ?? []) {
            for (const handler of handlers.get("requestfailed") ?? []) handler({ url: () => requestUrl });
          }
          return {
            status: () => options.httpStatus ?? 200,
            headers: async () => options.responseHeaders ?? {
              "content-type": "text/html; charset=utf-8",
              "x-content-type-options": "nosniff",
            },
          };
        },
        url: () => currentUrl,
        async evaluate(callback) {
          if (typeof options.evaluate === "function") return options.evaluate(callback);
          return options.snapshot ?? baselineSnapshot();
        },
        async waitForLoadState() {
          if (options.hangLoadState) return new Promise(() => {});
        },
        async waitForTimeout() {},
        async addScriptTag() {},
        async close() {},
      };
      const context = {
        async route(_pattern, handler) {
          routeHandler = handler;
        },
        ...(options.withWebSocketRouting === false ? {} : {
          async routeWebSocket(_pattern, handler) {
            webSocketRouteHandler = handler;
          },
        }),
        async addInitScript() {
          state.initScripts += 1;
        },
        async newPage() {
          return page;
        },
        async close() {
          state.contextCloseCount += 1;
        },
      };
      if (options.contextDelayMs) await new Promise((resolve) => setTimeout(resolve, options.contextDelayMs));
      return context;
    },
    async close() {
      state.browserCloseCount += 1;
    },
  };

  return {
    state,
    adapters: {
      playwright: {
        chromium: {
          async launch(launchOptions) {
            state.launchOptions = launchOptions;
            if (options.launchError) throw options.launchError;
            if (options.hangLaunch) return new Promise(() => {});
            return browser;
          },
        },
      },
      ...(options.withAxe === false ? {} : { AxeBuilder: FakeAxeBuilder }),
    },
  };
}

test("runtime audit is inert unless explicitly enabled", async () => {
  const adapters = {};
  Object.defineProperty(adapters, "playwright", {
    get() {
      throw new Error("capability discovery must not run");
    },
  });
  const result = await runRuntimeBrowserAudit({
    root: path.join(os.tmpdir(), "a-root-that-does-not-need-to-exist"),
    url: "https://example.com/?token=must-not-appear",
    adapters,
  });

  assert.equal(result.status, "disabled");
  assert.equal(result.policy.optIn, false);
  assert.equal(result.policy.repositoryScriptsExecuted, false);
  assert.equal(result.capabilities.playwright.checked, false);
  assert.equal(result.metadata.checks.length, 10);
  assert.equal(result.metadata.checks.every((descriptor) => descriptor.status === "skipped"), true);
  assert.doesNotMatch(JSON.stringify(result), /must-not-appear/);
});

test("enabled runtime audit requires an explicit URL and never starts repository scripts", async (t) => {
  const root = await temporaryRoot(t);
  const marker = path.join(root, "SCRIPT-RAN");
  await writeEntry(root, "package.json", {
    private: true,
    scripts: { start: `node -e \"require('node:fs').writeFileSync('${marker.replace(/\\/g, "\\\\")}', 'yes')\"` },
  });
  await assert.rejects(
    runRuntimeBrowserAudit({ enabled: true, root }),
    (error) => error instanceof RuntimeAuditError && error.code === "RUNTIME_URL_REQUIRED",
  );
  await assert.rejects(fs.access(marker), (error) => error?.code === "ENOENT");
});

test("remote targets require explicit permission and requested routes stay same-origin", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness();
  await assert.rejects(
    runRuntimeBrowserAudit({ enabled: true, root, url: "https://example.com", adapters: harness.adapters }),
    (error) => error?.code === "REMOTE_URL_NOT_ALLOWED",
  );
  await assert.rejects(
    runRuntimeBrowserAudit({
      enabled: true,
      root,
      url: "http://127.0.0.1:4173",
      routes: ["https://example.com/elsewhere"],
      adapters: harness.adapters,
    }),
    (error) => error?.code === "CROSS_ORIGIN_ROUTE_NOT_ALLOWED",
  );

  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "https://example.com",
    allowRemote: true,
    adapters: harness.adapters,
  });
  assert.equal(result.status, "completed");
  assert.equal(result.policy.allowRemote, true);
});

test("route count is bounded and never silently truncated", async (t) => {
  const root = await temporaryRoot(t);
  const routes = ["/one", "/two", "/three"];
  await assert.rejects(
    runRuntimeBrowserAudit({
      enabled: true,
      root,
      url: "http://localhost:3000/",
      routes,
      maxRoutes: 3,
      adapters: runtimeHarness().adapters,
    }),
    (error) => error?.code === "RUNTIME_ROUTE_LIMIT_EXCEEDED" && /4 routes/.test(error.message),
  );
  await assert.rejects(
    runRuntimeBrowserAudit({
      enabled: true,
      root,
      url: "http://localhost:3000/",
      maxRoutes: MAX_RUNTIME_ROUTES + 1,
      adapters: runtimeHarness().adapters,
    }),
    (error) => error?.code === "INVALID_RUNTIME_OPTION",
  );
});

test("multi-route family descriptors distinguish complete, partial and unavailable coverage", () => {
  const completeRoute = {
    httpStatus: 200,
    metrics: baselineSnapshot(),
    stages: {
      page: { status: "completed" },
      "network-policy": { status: "completed" },
    },
    accessibility: { status: "completed" },
  };
  const mixedRoute = {
    httpStatus: null,
    metrics: null,
    stages: {
      page: { status: "completed" },
      "network-policy": { status: "completed" },
    },
    accessibility: { status: "failed" },
  };
  const byId = (descriptors) => Object.fromEntries(descriptors.map(({ id, status }) => [id, status]));

  assert.deepEqual(byId(runtimeCheckDescriptors([completeRoute, completeRoute], { requestedRoutes: 2 })), {
    "runtime-http": "completed",
    "runtime-rendered-document": "completed",
    "runtime-rendered-metadata": "completed",
    "runtime-rendered-forms": "completed",
    "runtime-rendered-layout": "completed",
    "runtime-lab-performance": "completed",
    "runtime-security-headers": "unavailable",
    "runtime-browser-errors": "completed",
    "runtime-network": "completed",
    "runtime-axe-a11y": "completed",
  });
  assert.deepEqual(byId(runtimeCheckDescriptors([completeRoute, mixedRoute], { requestedRoutes: 2 })), {
    "runtime-http": "partial",
    "runtime-rendered-document": "partial",
    "runtime-rendered-metadata": "partial",
    "runtime-rendered-forms": "partial",
    "runtime-rendered-layout": "partial",
    "runtime-lab-performance": "partial",
    "runtime-security-headers": "unavailable",
    "runtime-browser-errors": "completed",
    "runtime-network": "completed",
    "runtime-axe-a11y": "partial",
  });
  assert.equal(
    byId(runtimeCheckDescriptors([completeRoute, completeRoute], { requestedRoutes: 3 }))["runtime-network"],
    "partial",
  );
  assert.equal(
    runtimeCheckDescriptors([], { requestedRoutes: 2 }).every((descriptor) => descriptor.status === "unavailable"),
    true,
  );
  assert.equal(
    runtimeCheckDescriptors([], { disabled: true, requestedRoutes: 2 }).every((descriptor) => descriptor.status === "skipped"),
    true,
  );
});

test("an allowlisted installed Chromium channel can be selected explicitly", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness();
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:4173/",
    browserName: "chromium",
    browserChannel: "chrome",
    adapters: harness.adapters,
  });

  assert.equal(result.status, "completed");
  assert.deepEqual(harness.state.launchOptions, {
    headless: true,
    chromiumSandbox: true,
    channel: "chrome",
  });
  assert.equal(result.capabilities.playwright.browserChannel, "chrome");
  await assert.rejects(
    runRuntimeBrowserAudit({
      enabled: true,
      root,
      url: "http://127.0.0.1:4173/",
      browserName: "firefox",
      browserChannel: "chrome",
      adapters: harness.adapters,
    }),
    (error) => error?.code === "INVALID_RUNTIME_BROWSER_CHANNEL",
  );
  await assert.rejects(
    runRuntimeBrowserAudit({
      enabled: true,
      root,
      url: "http://127.0.0.1:4173/",
      browserChannel: "arbitrary-executable",
      adapters: harness.adapters,
    }),
    (error) => error?.code === "INVALID_RUNTIME_BROWSER_CHANNEL",
  );
});

test("loopback and request policy rejects private-network and unsafe protocols", () => {
  assert.equal(isLoopbackHostname("localhost"), true);
  assert.equal(isLoopbackHostname("app.localhost."), true);
  assert.equal(isLoopbackHostname("127.23.4.5"), true);
  assert.equal(isLoopbackHostname("[::1]"), true);
  assert.equal(isLoopbackHostname("localhost.example.com"), false);
  assert.equal(isLoopbackHostname("192.168.1.10"), false);
  assert.equal(isRuntimeNetworkUrlAllowed("http://127.0.0.1:3000/app"), true);
  assert.equal(isRuntimeNetworkUrlAllowed("ws://localhost:3000/socket"), true);
  assert.equal(isRuntimeNetworkUrlAllowed("https://example.com/app"), false);
  assert.equal(isRuntimeNetworkUrlAllowed("file:///etc/passwd", { allowRemote: true }), false);
  assert.equal(isRuntimeNetworkUrlAllowed("https://example.com/app", { allowRemote: true }), true);
});

test("capability discovery finds project-local optional packages without mandatory dependencies", async (t) => {
  const root = await temporaryRoot(t);
  await writeEntry(root, "node_modules/playwright/package.json", {
    name: "playwright",
    version: "0.0.0-test",
    main: "index.cjs",
  });
  await writeEntry(root, "node_modules/playwright/index.cjs", "module.exports = { chromium: { launch() {} } };\n");
  await writeEntry(root, "node_modules/axe-core/package.json", {
    name: "axe-core",
    version: "0.0.0-test",
    main: "index.cjs",
  });
  await writeEntry(root, "node_modules/axe-core/index.cjs", "module.exports = { source: 'globalThis.axe = {}' };\n");

  const capabilities = await discoverRuntimeCapabilities({ root, includeModuleFallback: false });
  assert.equal(capabilities.playwright.available, true);
  assert.equal(capabilities.playwright.packageName, "playwright");
  assert.equal(capabilities.playwright.source, "project");
  assert.equal(capabilities.axe.available, true);
  assert.equal(capabilities.axe.packageName, "axe-core");
  assert.equal(capabilities.axe.source, "project");
});

test("missing optional capabilities are reported honestly", async (t) => {
  const root = await temporaryRoot(t);
  const discovered = await discoverRuntimeCapabilities({ root, includeModuleFallback: false });
  assert.equal(discovered.playwright.available, false);
  assert.equal(discovered.axe.available, false);

  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://localhost:3000",
    adapters: {},
  });
  assert.equal(result.status, "unavailable");
  assert.equal(result.capabilities.playwright.available, false);
  assert.ok(result.findings.some((finding) => finding.id === "runtime.playwright-unavailable"));
  assert.equal(result.metrics.routesAudited, 0);
  assert.equal(result.metadata.checks.every((descriptor) => descriptor.status === "unavailable"), true);
});

test("runtime audit returns structured browser metrics, axe findings, timings and closes resources", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    snapshot: baselineSnapshot({
      document: {
        unlabeledFormControlCount: 2,
        metaDescriptionPresent: false,
        canonicalPresent: false,
        canonicalUrl: null,
        documentWidth: 1_360,
        horizontalOverflowPx: 80,
      },
      performance: { largestContentfulPaintMs: 4_500, cumulativeLayoutShift: 0.31 },
    }),
    axeResults: {
      violations: [{
        id: "button-name",
        impact: "serious",
        help: "Buttons must have discernible text",
        description: "Ensure buttons have accessible names.",
        helpUrl: "https://dequeuniversity.com/rules/axe/button-name/4.10",
        tags: ["wcag2a", "wcag412"],
        nodes: [{}, {}],
      }],
      incomplete: [{ id: "color-contrast" }],
      passes: [{ id: "document-title" }],
    },
  });
  const progress = [];
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:4173/?token=private-query-value",
    routes: ["/about"],
    maxRoutes: 2,
    adapters: harness.adapters,
    onProgress: (event) => progress.push(event),
  });

  assert.equal(result.status, "completed");
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.mode, "runtime");
  assert.equal(result.checks, 10);
  assert.equal(result.metadata.checks.length, 10);
  assert.equal(new Set(result.metadata.checks.map((descriptor) => descriptor.id)).size, 10);
  assert.equal(result.metadata.checks.every((descriptor) => descriptor.kind === "automated" && descriptor.status === "completed"), true);
  assert.equal(result.metrics.routesRequested, 2);
  assert.equal(result.metrics.routesAudited, 2);
  assert.equal(result.metrics.accessibilityViolations, 2);
  assert.equal(result.metrics.accessibilityAffectedNodes, 4);
  assert.equal(result.metrics.routes[0].accessibility.incomplete, 1);
  assert.ok(result.findings.some((finding) => finding.id === "runtime.axe.button-name" && finding.severity === "high"));
  assert.ok(result.findings.some((finding) => finding.id === "runtime.axe-incomplete-review" && finding.manual));
  assert.ok(result.findings.some((finding) => finding.id === "runtime.unlabeled-controls"));
  assert.ok(result.findings.some((finding) => finding.id === "runtime.slow-lcp"));
  assert.ok(result.findings.some((finding) => finding.id === "runtime.high-cls"));
  assert.ok(result.findings.some((finding) => finding.id === "runtime.meta-description"));
  assert.ok(result.findings.some((finding) => finding.id === "runtime.canonical-url"));
  assert.ok(result.findings.some((finding) => finding.id === "runtime.horizontal-overflow"));
  assert.equal(result.findings.find((finding) => finding.id === "runtime.axe.button-name").ruleFamily, "runtime-axe-a11y");
  assert.equal(result.findings.find((finding) => finding.id === "runtime.axe.button-name").scoreFamily, "accessible-controls");
  assert.ok(result.findings.find((finding) => finding.id === "runtime.axe.button-name").standards
    .some((standard) => standard.id === "WCAG-2.2-4.1.2"));
  assert.deepEqual(result.findings.find((finding) => finding.id === "runtime.axe.button-name").references, [
    "https://dequeuniversity.com/rules/axe/button-name/4.10",
  ]);
  assert.equal(result.findings.find((finding) => finding.id === "runtime.slow-lcp").ruleFamily, "runtime-lab-performance");
  assert.equal(result.findings.find((finding) => finding.id === "runtime.slow-lcp").scoreFamily, "core-web-vitals-readiness");
  assert.equal(result.findings.every((finding) => result.metadata.checks.some((descriptor) => descriptor.id === finding.ruleFamily)), true);
  assert.match(result.metrics.routes[0].responseHeaders["content-type"], /^text\/html/);
  assert.equal(result.metrics.routes[0].stages["load-state"].status, "completed");
  assert.equal(result.metrics.routes[0].stages.stabilization.status, "completed");
  assert.equal(harness.state.contextCloseCount, 2);
  assert.equal(harness.state.browserCloseCount, 1);
  assert.deepEqual(harness.state.launchOptions, { headless: true, chromiumSandbox: true });
  assert.equal(harness.state.contextOptions[0].serviceWorkers, "block");
  assert.equal(harness.state.contextOptions[0].acceptDownloads, false);
  assert.deepEqual(harness.state.contextOptions[0].viewport, { width: 390, height: 844 });
  assert.equal(result.viewport.preset, "mobile");
  assert.ok(progress.some((event) => event.stage === "route" && event.current === 2));
  assert.equal(Object.values(result.stages).every((stage) => stage.durationMs >= 0), true);
  assert.doesNotMatch(JSON.stringify(result), /private-query-value/);
  assert.equal(result.policy.repositoryScriptsExecuted, false);
});

test("runtime audit measures actionable mobile UX, performance and live-header signals", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    responseHeaders: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'",
      "referrer-policy": "unsafe-url",
    },
    snapshot: baselineSnapshot({
      document: {
        language: "not_a_language",
        languageValid: false,
        brokenImageCount: 2,
        duplicateIdCount: 4,
        interactiveTargetCount: 8,
        undersizedTargetCount: 3,
      },
      navigation: {
        responseStartMs: 950,
        transferBytes: 1_500_000,
      },
      performance: {
        firstContentfulPaintMs: 2_100,
        largestContentfulPaintMs: 3_200,
        cumulativeLayoutShift: 0.16,
        longTaskCount: 4,
        longTaskDurationMs: 650,
        maxLongTaskMs: 260,
        resourceTransferBytes: 3_500_000,
      },
    }),
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:4173/",
    adapters: harness.adapters,
  });
  const ids = new Set(result.findings.map((item) => item.id));

  for (const id of [
    "runtime.invalid-document-language",
    "runtime.broken-images",
    "runtime.duplicate-ids",
    "runtime.small-touch-targets",
    "runtime.lcp-needs-improvement",
    "runtime.cls-needs-improvement",
    "runtime.ttfb-needs-improvement",
    "runtime.fcp-needs-improvement",
    "runtime.long-main-thread-tasks",
    "runtime.large-page-transfer",
    "runtime.header-csp-unsafe-eval",
    "runtime.header-nosniff-missing",
    "runtime.header-referrer-policy-weak",
  ]) assert.ok(ids.has(id), id);
  assert.equal(ids.has("runtime.header-frame-protection-missing"), false);
  assert.ok(result.findings.find((item) => item.id === "runtime.small-touch-targets").standards
    .some((standard) => standard.id === "WCAG-2.2-2.5.8"));
  assert.ok(result.findings.find((item) => item.id === "runtime.header-csp-unsafe-eval").standards
    .some((standard) => standard.id === "CWE-95"));
  assert.equal(result.metrics.performanceCoverage.longTasks, 1);
});

test("runtime viewport selection and static-server header scope are explicit", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness();
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:4173/",
    viewportPreset: "desktop",
    auditSecurityHeaders: false,
    adapters: harness.adapters,
  });

  assert.deepEqual(harness.state.contextOptions[0].viewport, { width: 1_280, height: 720 });
  assert.equal(result.viewport.preset, "desktop");
  assert.equal(result.policy.securityHeadersAudited, false);
  assert.equal(result.findings.some((item) => item.id.startsWith("runtime.header-")), false);
  assert.equal(result.metadata.checks.find((item) => item.id === "runtime-security-headers").status, "skipped");
  await assert.rejects(
    runRuntimeBrowserAudit({
      enabled: true,
      root,
      url: "http://127.0.0.1:4173/",
      viewportPreset: "television",
      adapters: harness.adapters,
    }),
    (error) => error?.code === "INVALID_RUNTIME_VIEWPORT",
  );
});

test("unsupported browser performance observers remain partial instead of reporting false zeroes", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    snapshot: baselineSnapshot({
      performance: {
        largestContentfulPaintMs: null,
        cumulativeLayoutShift: null,
        longTaskCount: null,
        longTaskDurationMs: null,
        maxLongTaskMs: null,
        measurementSupport: {
          largestContentfulPaint: false,
          cumulativeLayoutShift: false,
          longTasks: false,
        },
      },
    }),
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:4173/",
    adapters: harness.adapters,
  });

  assert.equal(result.metrics.routes[0].metrics.performance.largestContentfulPaintMs, null);
  assert.equal(result.metrics.routes[0].metrics.performance.cumulativeLayoutShift, null);
  assert.equal(result.status, "partial");
  assert.equal(result.metadata.checks.find((item) => item.id === "runtime-lab-performance").status, "partial");
  assert.ok(result.findings.some((item) => item.id === "runtime.performance-metrics-unavailable"));
  assert.equal(result.findings.some((item) => [
    "runtime.slow-lcp",
    "runtime.lcp-needs-improvement",
    "runtime.high-cls",
    "runtime.cls-needs-improvement",
  ].includes(item.id)), false);
});

test("a failed route makes only its unfinished runtime families partial", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    navigationError: (url) => url.endsWith("/broken") ? new Error("route unavailable") : null,
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:4173/",
    routes: ["/broken"],
    maxRoutes: 2,
    adapters: harness.adapters,
  });
  const statuses = Object.fromEntries(result.metadata.checks.map(({ id, status }) => [id, status]));

  assert.equal(result.status, "partial");
  assert.equal(result.metrics.routesRequested, 2);
  assert.equal(result.metrics.routesAudited, 1);
  assert.equal(statuses["runtime-http"], "partial");
  assert.equal(statuses["runtime-rendered-document"], "partial");
  assert.equal(statuses["runtime-rendered-metadata"], "partial");
  assert.equal(statuses["runtime-rendered-forms"], "partial");
  assert.equal(statuses["runtime-rendered-layout"], "partial");
  assert.equal(statuses["runtime-lab-performance"], "partial");
  assert.equal(statuses["runtime-axe-a11y"], "partial");
  assert.equal(statuses["runtime-browser-errors"], "completed");
  assert.equal(statuses["runtime-network"], "completed");
});

test("axe keeps truthful totals when detailed violation groups are capped", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    axeResults: {
      violations: Array.from({ length: 105 }, (_, index) => ({
        id: `synthetic-rule-${index}`,
        impact: "minor",
        help: `Synthetic rule ${index}`,
        description: "Synthetic accessibility result.",
        nodes: [{}],
      })),
      incomplete: [],
      passes: [],
    },
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:4173/",
    adapters: harness.adapters,
  });

  assert.equal(result.metrics.routes[0].accessibility.violations, 105);
  assert.equal(result.metrics.routes[0].accessibility.reportedViolations, 100);
  assert.equal(result.metrics.accessibilityViolations, 105);
  assert.equal(result.findings.filter((item) => item.id.startsWith("runtime.axe.synthetic-rule-")).length, 100);
  assert.ok(result.findings.some((item) => item.id === "runtime.axe-results-truncated" && item.manual));
});

test("local-only request interception records partial coverage", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    requests: [
      "http://127.0.0.1:3000/app.js",
      "https://cdn.example.com/app.js?token=hidden-value",
    ],
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:3000/",
    adapters: harness.adapters,
  });

  assert.equal(result.status, "partial");
  assert.deepEqual(harness.state.continued, ["http://127.0.0.1:3000/app.js"]);
  assert.deepEqual(harness.state.aborted, ["https://cdn.example.com/app.js?token=hidden-value"]);
  assert.equal(result.metrics.blockedRequests, 1);
  assert.ok(result.findings.some((finding) => finding.id === "runtime.remote-requests-blocked"));
  assert.doesNotMatch(JSON.stringify(result), /hidden-value/);
});

test("local-only WebSocket routing blocks a remote socket opened inside a local worker", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    // Context-level routing sees sockets from workers as well as the page.
    webSockets: [
      "ws://127.0.0.1:3000/local-socket",
      "wss://events.example.com/socket?token=hidden-worker-value",
    ],
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:3000/",
    adapters: harness.adapters,
  });

  assert.equal(result.status, "partial");
  assert.deepEqual(harness.state.continuedWebSockets, ["ws://127.0.0.1:3000/local-socket"]);
  assert.equal(harness.state.blockedWebSockets.length, 1);
  assert.equal(harness.state.blockedWebSockets[0].url, "wss://events.example.com/socket?token=hidden-worker-value");
  assert.equal(harness.state.blockedWebSockets[0].code, 1008);
  assert.equal(result.metrics.blockedRequests, 1);
  assert.ok(result.findings.some((finding) => finding.id === "runtime.remote-requests-blocked"));
  assert.doesNotMatch(JSON.stringify(result), /hidden-worker-value/);
});

test("local-only auditing fails closed before navigation when WebSocket routing is unavailable", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({ withWebSocketRouting: false });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:3000/",
    adapters: harness.adapters,
  });

  assert.equal(result.status, "partial");
  assert.equal(result.metrics.routesAudited, 0);
  assert.deepEqual(harness.state.navigated, []);
  assert.equal(result.metrics.routes[0].stages["network-policy"].status, "failed");
  assert.match(result.metrics.routes[0].stages["network-policy"].reason, /cannot intercept WebSockets/i);
  assert.equal(result.metadata.checks.find((descriptor) => descriptor.id === "runtime-network").status, "unavailable");
});

test("blocked worker and transport APIs are explicit partial runtime evidence", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    snapshot: baselineSnapshot({
      policy: { blockedEgressAttempts: 2, blockedEgressKinds: ["Worker", "WebTransport"] },
    }),
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:3000/",
    adapters: harness.adapters,
  });

  assert.equal(result.status, "partial");
  assert.equal(result.metrics.blockedEgressAttempts, 2);
  assert.equal(result.metrics.routes[0].network.blockedEgressAttempts, 2);
  const finding = result.findings.find((item) => item.id === "runtime.unmediated-egress-blocked");
  assert.equal(finding.ruleFamily, "runtime-network");
  assert.match(finding.evidence, /Worker, WebTransport/);
});

test("runtime form heuristics ignore controls outside the accessibility tree", async (t) => {
  const root = await temporaryRoot(t);
  const visibleUnlabeled = fakeControl();
  const harness = runtimeHarness({
    evaluate: (callback) => evaluateWithControls(callback, [
      visibleUnlabeled,
      fakeControl({ hidden: true }),
      fakeControl({ excluded: true }),
      fakeControl({ style: { display: "none" }, attributes: { type: "file", class: "hidden" } }),
      fakeControl({ style: { visibility: "hidden" } }),
      fakeControl({ style: { contentVisibility: "hidden" } }),
    ]),
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://127.0.0.1:3000/",
    adapters: harness.adapters,
  });

  const documentMetrics = result.metrics.routes[0].metrics.document;
  assert.equal(documentMetrics.formControlCount, 1);
  assert.equal(documentMetrics.unlabeledFormControlCount, 1);
  const finding = result.findings.find((item) => item.id === "runtime.unlabeled-controls");
  assert.match(finding.description, /^1 rendered form control/);
});

test("axe absence produces a successful-but-partial runtime result", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({ withAxe: false });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://localhost:8080/",
    adapters: harness.adapters,
  });

  assert.equal(result.status, "partial");
  assert.equal(result.capabilities.playwright.available, true);
  assert.equal(result.capabilities.axe.available, false);
  assert.equal(result.metrics.routes[0].accessibility.status, "unavailable");
  assert.ok(result.findings.some((finding) => finding.id === "runtime.axe-unavailable"));
  assert.equal(result.metadata.checks.find((descriptor) => descriptor.id === "runtime-axe-a11y").status, "unavailable");
  assert.equal(result.metadata.checks.find((descriptor) => descriptor.id === "runtime-network").status, "completed");
  assert.equal(harness.state.contextCloseCount, 1);
  assert.equal(harness.state.browserCloseCount, 1);
});

test("navigation timeouts are bounded, surfaced and cleaned up", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({ hangNavigation: true });
  const startedAt = Date.now();
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://localhost:8080/",
    adapters: harness.adapters,
    totalTimeoutMs: 200,
    launchTimeoutMs: 50,
    navigationTimeoutMs: 20,
    measurementTimeoutMs: 50,
    accessibilityTimeoutMs: 50,
    cleanupTimeoutMs: 50,
  });

  assert.ok(Date.now() - startedAt < 1_000);
  assert.equal(result.status, "partial");
  assert.ok(result.findings.some((finding) => finding.id === "runtime.route-timeout" && finding.severity === "high" && !finding.manual));
  assert.ok(result.summary.score < 100);
  assert.equal(result.metrics.routesFailed, 1);
  assert.equal(result.metrics.routes[0].stages.navigation.status, "timed-out");
  assert.equal(harness.state.contextCloseCount, 1);
  assert.equal(harness.state.browserCloseCount, 1);
});

test("AbortSignal interrupts a hanging runtime audit and still closes browser resources", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({ hangNavigation: true });
  const controller = new AbortController();
  const startedAt = Date.now();
  const audit = runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://localhost:8080/",
    adapters: harness.adapters,
    signal: controller.signal,
    navigationTimeoutMs: 10_000,
    totalTimeoutMs: 20_000,
  });
  setTimeout(() => controller.abort(), 10);

  await assert.rejects(audit, (error) => error?.code === "RUNTIME_ABORTED");
  assert.ok(Date.now() - startedAt < 1_000);
  assert.equal(harness.state.contextCloseCount, 1);
  assert.equal(harness.state.browserCloseCount, 1);
});

test("browser launch failures return unavailable instead of claiming a completed scan", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({ launchError: new Error("browser executable is missing") });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://localhost:3000/",
    adapters: harness.adapters,
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.metrics.routesAudited, 0);
  assert.ok(result.findings.some((finding) => finding.id === "runtime.browser-launch-failed"));
  assert.equal(result.stages.launch.status, "failed");
});

test("a context that resolves after timeout is still closed", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({ contextDelayMs: 35 });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://localhost:3000/",
    adapters: harness.adapters,
    totalTimeoutMs: 200,
    launchTimeoutMs: 10,
    navigationTimeoutMs: 50,
    measurementTimeoutMs: 50,
    accessibilityTimeoutMs: 50,
    cleanupTimeoutMs: 50,
  });
  await new Promise((resolve) => setTimeout(resolve, 60));

  assert.equal(result.status, "partial");
  assert.equal(result.metrics.routes[0].stages.context.status, "timed-out");
  assert.ok(result.findings.some((finding) => finding.id === "runtime.audit-infrastructure-failed" && finding.severity === "info" && finding.manual));
  assert.equal(result.summary.score, 100);
  assert.equal(harness.state.contextCloseCount, 1);
  assert.equal(harness.state.browserCloseCount, 1);
});

test("navigation errors cannot leak arbitrary URL query values", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({
    navigationError: new Error("Navigation failed at http://localhost:3000/?debug=short-private-value"),
  });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://localhost:3000/?debug=short-private-value",
    adapters: harness.adapters,
  });

  assert.equal(result.status, "partial");
  assert.ok(result.findings.some((finding) => finding.id === "runtime.route-failed"));
  assert.doesNotMatch(JSON.stringify(result), /short-private-value/);
});

test("an incomplete browser load state is explicit partial coverage", async (t) => {
  const root = await temporaryRoot(t);
  const harness = runtimeHarness({ hangLoadState: true });
  const result = await runRuntimeBrowserAudit({
    enabled: true,
    root,
    url: "http://localhost:3000/",
    adapters: harness.adapters,
    totalTimeoutMs: 200,
    loadTimeoutMs: 15,
    stabilizationMs: 1,
  });

  assert.equal(result.status, "partial");
  assert.equal(result.metrics.routes[0].stages["load-state"].status, "timed-out");
  assert.ok(result.findings.some((finding) => finding.id === "runtime.load-state-incomplete"));
  assert.equal(result.findings.find((finding) => finding.id === "runtime.load-state-incomplete").ruleFamily, "runtime-browser-errors");
});
