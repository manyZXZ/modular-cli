import { promises as fs } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildScanResult } from "../core/model.js";
import { sanitizeEvidence } from "../core/sanitize.js";
import { runtimeInitScript, runtimeReadiness, runtimeSnapshot } from "./browser-probes.js";
import { normalizeSnapshot } from "./snapshot.js";
import {
  eventFindings,
  finding,
  findingsFromSnapshot,
  normalizeAxeResults,
  responseSecurityFindings,
  routeEvidence,
} from "./audit-findings.js";
import { isLoopbackHostname, isRuntimeNetworkUrlAllowed, redactUrlQueries, safeDisplayUrl } from "./url-policy.js";

export { isLoopbackHostname, isRuntimeNetworkUrlAllowed } from "./url-policy.js";

export const MAX_RUNTIME_ROUTES = 25;

export const RUNTIME_VIEWPORTS = Object.freeze({
  mobile: Object.freeze({ width: 390, height: 844 }),
  desktop: Object.freeze({ width: 1_280, height: 720 }),
});

export const RUNTIME_AUDIT_DEFAULTS = Object.freeze({
  maxRoutes: 5,
  totalTimeoutMs: 60_000,
  launchTimeoutMs: 15_000,
  navigationTimeoutMs: 15_000,
  loadTimeoutMs: 2_000,
  stabilizationMs: 250,
  measurementTimeoutMs: 5_000,
  accessibilityTimeoutMs: 10_000,
  cleanupTimeoutMs: 5_000,
  browserName: "chromium",
  viewportPreset: "mobile",
});

export const RUNTIME_RULE_FAMILIES = Object.freeze([
  Object.freeze({ id: "runtime-http", kind: "automated" }),
  Object.freeze({ id: "runtime-rendered-document", kind: "automated" }),
  Object.freeze({ id: "runtime-rendered-metadata", kind: "automated" }),
  Object.freeze({ id: "runtime-rendered-forms", kind: "automated" }),
  Object.freeze({ id: "runtime-rendered-layout", kind: "automated" }),
  Object.freeze({ id: "runtime-lab-performance", kind: "automated" }),
  Object.freeze({ id: "runtime-security-headers", kind: "automated" }),
  Object.freeze({ id: "runtime-browser-errors", kind: "automated" }),
  Object.freeze({ id: "runtime-network", kind: "automated" }),
  Object.freeze({ id: "runtime-axe-a11y", kind: "automated" }),
]);

const PLAYWRIGHT_PACKAGES = Object.freeze(["playwright", "@playwright/test", "playwright-core"]);
const AXE_PACKAGES = Object.freeze(["@axe-core/playwright", "axe-core"]);
const BROWSER_NAMES = new Set(["chromium", "firefox", "webkit"]);
const CHROMIUM_CHANNELS = new Set([
  "chrome",
  "chrome-beta",
  "chrome-dev",
  "chrome-canary",
  "msedge",
  "msedge-beta",
  "msedge-dev",
  "msedge-canary",
]);
const MAX_EVENT_DETAILS = 20;
const MODULE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export class RuntimeAuditError extends Error {
  constructor(code, message, options = {}) {
    super(message, options);
    this.name = "RuntimeAuditError";
    this.code = code;
    this.stage = options.stage ?? null;
    this.timedOut = options.timedOut === true;
  }
}

function now() {
  return Date.now();
}

function elapsed(startedAt) {
  return Math.max(0, now() - startedAt);
}

function boundedInteger(value, fallback, name, maximum = 600_000) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    throw new RuntimeAuditError(
      "INVALID_RUNTIME_OPTION",
      `${name} must be an integer between 1 and ${maximum}.`,
      { stage: "validation" },
    );
  }
  return selected;
}

function safeError(error, maximum = 260) {
  return sanitizeEvidence(redactUrlQueries(error instanceof Error ? error.message : String(error)), maximum) || "Unknown error";
}

function timeoutError(label, timeoutMs) {
  return new RuntimeAuditError(
    "RUNTIME_STAGE_TIMEOUT",
    `${label} exceeded its ${timeoutMs} ms time limit.`,
    { stage: label, timedOut: true },
  );
}

function abortError(label = "runtime-audit") {
  return new RuntimeAuditError(
    "RUNTIME_ABORTED",
    "Runtime audit was interrupted.",
    { stage: label },
  );
}

function withTimeout(task, timeoutMs, label, options = {}) {
  let finished = false;
  let detached = false;
  let timer;
  let abortHandler;
  const operation = options.signal?.aborted
    ? Promise.reject(abortError(label))
    : Promise.resolve().then(task);

  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      if (abortHandler) options.signal?.removeEventListener("abort", abortHandler);
    };
    timer = setTimeout(() => {
      if (finished) return;
      detached = true;
      finished = true;
      cleanup();
      reject(timeoutError(label, timeoutMs));
    }, timeoutMs);
    abortHandler = () => {
      if (finished) return;
      detached = true;
      finished = true;
      cleanup();
      reject(abortError(label));
    };
    if (options.signal) options.signal.addEventListener("abort", abortHandler, { once: true });
    if (options.signal?.aborted) abortHandler();

    operation.then(
      (value) => {
        if (detached) {
          Promise.resolve(options.onLateResolve?.(value)).catch(() => {});
          return;
        }
        if (finished) return;
        finished = true;
        cleanup();
        resolve(value);
      },
      (error) => {
        if (detached || finished) return;
        finished = true;
        cleanup();
        reject(error);
      },
    );
  });
}

async function closeResource(resource, timeoutMs) {
  if (!resource || typeof resource.close !== "function") return { status: "not-needed", durationMs: 0 };
  const startedAt = now();
  try {
    await withTimeout(() => resource.close(), timeoutMs, "cleanup");
    return { status: "completed", durationMs: elapsed(startedAt) };
  } catch (error) {
    return { status: "failed", durationMs: elapsed(startedAt), reason: safeError(error) };
  }
}

function createStageRecorder() {
  const stages = {};
  return {
    stages,
    async run(name, task) {
      const startedAt = now();
      stages[name] = { status: "running", durationMs: 0 };
      try {
        const value = await task();
        stages[name] = { status: "completed", durationMs: elapsed(startedAt) };
        return value;
      } catch (error) {
        stages[name] = {
          status: error?.timedOut ? "timed-out" : "failed",
          durationMs: elapsed(startedAt),
          reason: safeError(error),
        };
        throw error;
      }
    },
    mark(name, status, reason) {
      stages[name] = {
        status,
        durationMs: 0,
        ...(reason ? { reason: sanitizeEvidence(reason, 260) } : {}),
      };
    },
  };
}


function parseHttpUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch {
    throw new RuntimeAuditError("INVALID_RUNTIME_URL", `${label} must be an absolute HTTP or HTTPS URL.`, {
      stage: "validation",
    });
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new RuntimeAuditError("INVALID_RUNTIME_URL", `${label} must use HTTP or HTTPS.`, {
      stage: "validation",
    });
  }
  if (parsed.username || parsed.password) {
    throw new RuntimeAuditError("URL_CREDENTIALS_NOT_ALLOWED", `${label} must not contain embedded credentials.`, {
      stage: "validation",
    });
  }
  parsed.hash = "";
  return parsed;
}


function validateRouteList(baseUrl, routes, { allowRemote, maxRoutes }) {
  if (routes !== undefined && !Array.isArray(routes)) {
    throw new RuntimeAuditError("INVALID_RUNTIME_ROUTES", "routes must be an array of same-origin URL paths.", {
      stage: "validation",
    });
  }
  const candidates = [baseUrl.href, ...(routes ?? [])];
  const normalized = [];
  const seen = new Set();
  for (let index = 0; index < candidates.length; index += 1) {
    let route;
    try {
      route = index === 0 ? new URL(candidates[index]) : new URL(String(candidates[index]), baseUrl);
    } catch {
      throw new RuntimeAuditError("INVALID_RUNTIME_ROUTE", `Route ${index + 1} is not a valid URL or path.`, {
        stage: "validation",
      });
    }
    if (!['http:', 'https:'].includes(route.protocol) || route.origin !== baseUrl.origin) {
      throw new RuntimeAuditError(
        "CROSS_ORIGIN_ROUTE_NOT_ALLOWED",
        `Route ${index + 1} must stay on the audited URL origin.`,
        { stage: "validation" },
      );
    }
    if (route.username || route.password) {
      throw new RuntimeAuditError("URL_CREDENTIALS_NOT_ALLOWED", `Route ${index + 1} contains credentials.`, {
        stage: "validation",
      });
    }
    if (!allowRemote && !isLoopbackHostname(route.hostname)) {
      throw new RuntimeAuditError(
        "REMOTE_URL_NOT_ALLOWED",
        "Remote runtime auditing is disabled. Use a loopback URL or explicitly set allowRemote: true.",
        { stage: "validation" },
      );
    }
    route.hash = "";
    const key = route.href;
    if (!seen.has(key)) {
      seen.add(key);
      normalized.push(route);
    }
  }
  if (normalized.length > maxRoutes) {
    throw new RuntimeAuditError(
      "RUNTIME_ROUTE_LIMIT_EXCEEDED",
      `The runtime audit requested ${normalized.length} routes; the configured limit is ${maxRoutes}.`,
      { stage: "validation" },
    );
  }
  return normalized;
}

async function canonicalDirectory(root) {
  const lexical = path.resolve(String(root ?? process.cwd()));
  let real;
  let stat;
  try {
    real = await fs.realpath(lexical);
    stat = await fs.stat(real);
  } catch (error) {
    throw new RuntimeAuditError("INVALID_RUNTIME_ROOT", `Runtime audit root is not accessible: ${safeError(error)}`, {
      stage: "validation",
    });
  }
  if (!stat.isDirectory()) {
    throw new RuntimeAuditError("INVALID_RUNTIME_ROOT", "Runtime audit root must be a directory.", {
      stage: "validation",
    });
  }
  return real;
}

function resolvePackage(packageName, searchRoot) {
  try {
    const resolver = createRequire(path.join(searchRoot, "__modular_runtime_resolver__.cjs"));
    return resolver.resolve(packageName);
  } catch {
    return null;
  }
}

async function importPackage(entryPath) {
  return import(pathToFileURL(entryPath).href);
}

function playwrightApi(moduleValue) {
  const candidates = [moduleValue, moduleValue?.default];
  for (const candidate of candidates) {
    if (candidate && BROWSER_NAMES.size > 0
      && [...BROWSER_NAMES].some((name) => typeof candidate[name]?.launch === "function")) return candidate;
  }
  return null;
}

function axeApi(packageName, moduleValue) {
  if (packageName === "@axe-core/playwright") {
    const constructor = moduleValue?.AxeBuilder
      ?? moduleValue?.default?.AxeBuilder
      ?? moduleValue?.default;
    if (typeof constructor === "function") return { kind: "builder", AxeBuilder: constructor };
  }
  const source = moduleValue?.source ?? moduleValue?.default?.source;
  if (typeof source === "string" && source.length > 0) return { kind: "source", source };
  return null;
}

async function discoverOne({ packages, roots, normalize, importer }) {
  const failures = [];
  for (const candidateRoot of roots) {
    for (const packageName of packages) {
      const entryPath = resolvePackage(packageName, candidateRoot.path);
      if (!entryPath) continue;
      try {
        const moduleValue = await importer(entryPath);
        const api = normalize(packageName, moduleValue);
        if (!api) {
          failures.push(`${packageName} did not expose a compatible API`);
          continue;
        }
        return {
          available: true,
          packageName,
          source: candidateRoot.source,
          api,
        };
      } catch (error) {
        failures.push(`${packageName} could not be loaded: ${safeError(error, 160)}`);
      }
    }
  }
  return {
    available: false,
    packageName: null,
    source: null,
    reason: failures.length > 0
      ? failures.join("; ")
      : `No compatible package was found (${packages.join(", ")}).`,
    api: null,
  };
}

/**
 * Resolve optional runtime dependencies without running a package-manager or a
 * repository script. The target repository is searched before Modular's own
 * installation so a project-local Playwright/browser installation can be used.
 */
export async function discoverRuntimeCapabilities({
  root = process.cwd(),
  includeModuleFallback = true,
  importer = importPackage,
} = {}) {
  const canonicalRoot = await canonicalDirectory(root);
  const roots = [{ path: canonicalRoot, source: "project" }];
  if (includeModuleFallback && path.resolve(canonicalRoot) !== MODULE_ROOT) {
    roots.push({ path: MODULE_ROOT, source: "modular" });
  }
  const [playwright, axe] = await Promise.all([
    discoverOne({
      packages: PLAYWRIGHT_PACKAGES,
      roots,
      normalize: (_packageName, moduleValue) => playwrightApi(moduleValue),
      importer,
    }),
    discoverOne({ packages: AXE_PACKAGES, roots, normalize: axeApi, importer }),
  ]);
  return { playwright, axe };
}

function normalizeInjectedCapabilities(adapters) {
  if (!adapters) return null;
  const playwright = playwrightApi(adapters.playwright);
  let axe = null;
  if (typeof adapters.AxeBuilder === "function") axe = { kind: "builder", AxeBuilder: adapters.AxeBuilder };
  else if (typeof adapters.axeSource === "string" && adapters.axeSource.length > 0) {
    axe = { kind: "source", source: adapters.axeSource };
  }
  return {
    playwright: playwright
      ? { available: true, packageName: "injected", source: "adapter", api: playwright }
      : { available: false, packageName: null, source: null, reason: "No compatible injected Playwright API.", api: null },
    axe: axe
      ? { available: true, packageName: "injected", source: "adapter", api: axe }
      : { available: false, packageName: null, source: null, reason: "No compatible injected axe API.", api: null },
  };
}

function publicCapabilities(capabilities, browserName, browserChannel = null) {
  return {
    playwright: {
      available: capabilities.playwright.available,
      packageName: capabilities.playwright.packageName,
      source: capabilities.playwright.source,
      browserName,
      browserChannel,
      browserTypeAvailable: typeof capabilities.playwright.api?.[browserName]?.launch === "function",
      ...(capabilities.playwright.reason ? { reason: sanitizeEvidence(capabilities.playwright.reason, 260) } : {}),
    },
    axe: {
      available: capabilities.axe.available,
      packageName: capabilities.axe.packageName,
      source: capabilities.axe.source,
      engine: capabilities.axe.api?.kind ?? null,
      ...(capabilities.axe.reason ? { reason: sanitizeEvidence(capabilities.axe.reason, 260) } : {}),
    },
  };
}



async function selectedResponseHeaders(response) {
  if (!response || typeof response.headers !== "function") return {};
  let values;
  try {
    values = await response.headers();
  } catch {
    return {};
  }
  const selected = {};
  for (const name of [
    "cache-control",
    "content-language",
    "content-security-policy",
    "content-security-policy-report-only",
    "content-type",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
  ]) {
    if (typeof values?.[name] === "string") {
      if (Buffer.byteLength(values[name], "utf8") > 65536) {
        throw new RuntimeAuditError("RUNTIME_HEADER_TOO_LARGE", "A response header exceeded the 64 KiB analysis limit.");
      }
      selected[name] = values[name];
    }
  }
  return selected;
}


async function runAxe(page, axeCapability) {
  if (!axeCapability.available) return null;
  if (axeCapability.api.kind === "builder") {
    const builder = new axeCapability.api.AxeBuilder({ page });
    return builder.analyze();
  }
  await page.addScriptTag({ content: axeCapability.api.source });
  return page.evaluate(async () => globalThis.axe.run(document, {
    resultTypes: ["violations", "incomplete", "passes"],
  }));
}

function safeProgress(callback, event) {
  if (typeof callback !== "function") return;
  try {
    callback(event);
  } catch {}
}

async function installNetworkPolicy(context, allowRemote, counters) {
  if (typeof context.route !== "function") {
    throw new RuntimeAuditError(
      "RUNTIME_NETWORK_GUARD_UNAVAILABLE",
      "The selected Playwright context does not support request interception.",
      { stage: "network-policy" },
    );
  }
  if (!allowRemote && typeof context.routeWebSocket !== "function") {
    throw new RuntimeAuditError(
      "RUNTIME_WEBSOCKET_GUARD_UNAVAILABLE",
      "The selected Playwright context cannot intercept WebSockets, so local-only runtime isolation cannot be guaranteed.",
      { stage: "network-policy" },
    );
  }
  await context.route("**/*", async (route) => {
    let requestUrl = "";
    try {
      const request = typeof route.request === "function" ? route.request() : route.request;
      requestUrl = typeof request?.url === "function" ? request.url() : request?.url;
    } catch {}
    if (!isRuntimeNetworkUrlAllowed(requestUrl, { allowRemote })) {
      counters.blockedRequests += 1;
      if (counters.blockedUrls.length < MAX_EVENT_DETAILS) counters.blockedUrls.push(safeDisplayUrl(requestUrl));
      try {
        await route.abort("blockedbyclient");
      } catch {}
      return;
    }
    try {
      await route.continue();
    } catch {}
  });
  if (!allowRemote) {
    await context.routeWebSocket("**/*", async (socket) => {
      let socketUrl = "";
      try {
        socketUrl = typeof socket.url === "function" ? socket.url() : socket.url;
      } catch {}
      if (!isRuntimeNetworkUrlAllowed(socketUrl, { allowRemote: false })) {
        counters.blockedRequests += 1;
        if (counters.blockedUrls.length < MAX_EVENT_DETAILS) counters.blockedUrls.push(safeDisplayUrl(socketUrl));
        try {
          await socket.close({ code: 1008, reason: "Remote runtime request blocked" });
        } catch {}
        return;
      }
      try {
        socket.connectToServer();
      } catch (error) {
        counters.requestFailures += 1;
        if (counters.requestFailureDetails.length < MAX_EVENT_DETAILS) {
          counters.requestFailureDetails.push(`${safeDisplayUrl(socketUrl)} — ${safeError(error, 120)}`);
        }
        try {
          await socket.close({ code: 1011, reason: "WebSocket forwarding failed" });
        } catch {}
      }
    });
  }
}

function listenForPageEvents(page, counters) {
  if (typeof page.on !== "function") return;
  page.on("console", (message) => {
    const type = typeof message?.type === "function" ? message.type() : message?.type;
    if (type !== "error") return;
    counters.consoleErrors += 1;
    if (counters.consoleErrorDetails.length < MAX_EVENT_DETAILS) {
      const text = typeof message?.text === "function" ? message.text() : String(message?.text ?? "Console error");
      counters.consoleErrorDetails.push(sanitizeEvidence(redactUrlQueries(text), 180));
    }
  });
  page.on("pageerror", (error) => {
    counters.pageErrors += 1;
    if (counters.pageErrorDetails.length < MAX_EVENT_DETAILS) counters.pageErrorDetails.push(safeError(error, 180));
  });
  page.on("requestfailed", (request) => {
    counters.requestFailures += 1;
    if (counters.requestFailureDetails.length < MAX_EVENT_DETAILS) {
      const requestUrl = typeof request?.url === "function" ? request.url() : request?.url;
      counters.requestFailureDetails.push(safeDisplayUrl(requestUrl));
    }
  });
}


function emptyCounters() {
  return {
    blockedRequests: 0,
    blockedUrls: [],
    consoleErrors: 0,
    consoleErrorDetails: [],
    pageErrors: 0,
    pageErrorDetails: [],
    requestFailures: 0,
    requestFailureDetails: [],
    blockedEgressAttempts: 0,
    blockedEgressKinds: [],
  };
}

async function auditRoute({
  browser,
  routeUrl,
  allowRemote,
  auditSecurityHeaders,
  axeCapability,
  limits,
  deadlineAt,
  signal,
  viewport,
}) {
  const startedAt = now();
  const stages = {};
  const findings = [];
  const counters = emptyCounters();
  let context;
  let page;
  let httpStatus = null;
  let responseHeaders = {};
  let finalUrl = safeDisplayUrl(routeUrl);
  let snapshot = null;
  let accessibility = { status: axeCapability.available ? "pending" : "unavailable", violations: 0, affectedNodes: 0, incomplete: 0, passes: 0 };
  let routeStatus = "failed";

  const remaining = (requested) => {
    const budget = deadlineAt - now();
    if (budget <= 0) throw timeoutError("total-runtime-audit", limits.totalTimeoutMs);
    return Math.max(1, Math.min(requested, budget));
  };
  const stage = async (name, timeoutMs, task, options = {}) => {
    const stageStartedAt = now();
    try {
      const value = await withTimeout(task, remaining(timeoutMs), name, { ...options, signal });
      stages[name] = { status: "completed", durationMs: elapsed(stageStartedAt) };
      return value;
    } catch (error) {
      const stageError = error instanceof RuntimeAuditError && error.stage
        ? error
        : new RuntimeAuditError("RUNTIME_STAGE_FAILED", safeError(error), { stage: name });
      stages[name] = {
        status: stageError.timedOut ? "timed-out" : "failed",
        durationMs: elapsed(stageStartedAt),
        reason: safeError(stageError),
      };
      throw stageError;
    }
  };

  try {
    context = await stage(
      "context",
      limits.launchTimeoutMs,
      () => browser.newContext({
        acceptDownloads: false,
        bypassCSP: false,
        deviceScaleFactor: 1,
        ignoreHTTPSErrors: false,
        javaScriptEnabled: true,
        permissions: [],
        serviceWorkers: "block",
        viewport: { width: viewport.width, height: viewport.height },
      }),
      { onLateResolve: (lateContext) => closeResource(lateContext, limits.cleanupTimeoutMs) },
    );
    await stage("network-policy", limits.measurementTimeoutMs, () => installNetworkPolicy(context, allowRemote, counters));
    if (typeof context.addInitScript === "function") {
      await stage("instrumentation", limits.measurementTimeoutMs, () => context.addInitScript(runtimeInitScript, { allowRemote }));
    } else {
      stages.instrumentation = { status: "unavailable", durationMs: 0, reason: "Context init scripts are unavailable." };
    }
    page = await stage(
      "page",
      limits.launchTimeoutMs,
      () => context.newPage(),
      { onLateResolve: (latePage) => closeResource(latePage, limits.cleanupTimeoutMs) },
    );
    listenForPageEvents(page, counters);

    const response = await stage("navigation", limits.navigationTimeoutMs, () => page.goto(routeUrl.href, {
      waitUntil: "domcontentloaded",
      timeout: remaining(limits.navigationTimeoutMs),
    }));
    httpStatus = typeof response?.status === "function" ? response.status() : null;
    responseHeaders = await selectedResponseHeaders(response);
    const observedUrl = typeof page.url === "function" ? page.url() : routeUrl.href;
    finalUrl = safeDisplayUrl(observedUrl);
    if (!isRuntimeNetworkUrlAllowed(observedUrl, { allowRemote })) {
      throw new RuntimeAuditError("REMOTE_REDIRECT_BLOCKED", "The route redirected outside the permitted network boundary.", {
        stage: "navigation",
      });
    }
    if (httpStatus !== null && httpStatus >= 400) {
      findings.push(finding({
        id: "runtime.http-error",
        title: `Rendered route returned HTTP ${httpStatus}`,
        severity: httpStatus >= 500 ? "high" : "medium",
        description: "The audited route returned an error response in the browser.",
        recommendation: "Fix the route response and verify its loading, error recovery, and monitoring behavior.",
        evidence: routeEvidence(observedUrl),
        tags: ["runtime", "http", "reliability"],
      }));
    }
    if (responseHeaders["content-type"] && !/^text\/html\b/i.test(responseHeaders["content-type"])) {
      findings.push(finding({
        id: "runtime.document-content-type",
        title: "Route did not return an HTML content type",
        severity: "medium",
        description: `The browser navigation response used ${responseHeaders["content-type"]}.`,
        recommendation: "Serve document routes with a valid text/html content type and UTF-8 encoding.",
        evidence: routeEvidence(observedUrl),
        tags: ["runtime", "http", "seo"],
      }));
    }
    if (auditSecurityHeaders) {
      findings.push(...responseSecurityFindings(observedUrl, responseHeaders));
      stages["security-headers"] = { status: "completed", durationMs: 0 };
    } else {
      stages["security-headers"] = {
        status: "skipped",
        durationMs: 0,
        reason: "The isolated static-file server is not the application's production response layer.",
      };
    }

    if (typeof page.waitForLoadState === "function") {
      try {
        await stage("load-state", limits.loadTimeoutMs, () => page.waitForLoadState("load", {
          timeout: remaining(limits.loadTimeoutMs),
        }));
      } catch (error) {
        findings.push(finding({
          id: "runtime.load-state-incomplete",
          title: "Rendered route did not reach the load state",
          severity: "info",
          description: safeError(error),
          recommendation: "Review long-lived or failed resources and confirm the route reaches a stable loaded state in supported browsers.",
          evidence: routeEvidence(observedUrl),
          tags: ["runtime", "browser", "coverage"],
          manual: true,
        }));
      }
    } else {
      stages["load-state"] = { status: "unavailable", durationMs: 0, reason: "The browser adapter has no load-state API." };
    }
    try {
      if (typeof page.waitForFunction === "function") {
        const timeout = Math.max(limits.measurementTimeoutMs, limits.stabilizationMs + 250);
        await stage("stabilization", timeout, async () => {
          const handle = await page.waitForFunction(runtimeReadiness, { quietMs: Math.max(500, limits.stabilizationMs) },
            { timeout: remaining(timeout), polling: 100 });
          await handle?.dispose?.();
        });
      } else {
        await stage("stabilization", limits.stabilizationMs + 250, () => (
          typeof page.waitForTimeout === "function" ? page.waitForTimeout(limits.stabilizationMs)
            : new Promise((resolve) => setTimeout(resolve, limits.stabilizationMs))
        ));
      }
    } catch (error) {
      findings.push(finding({ id: "runtime.render-readiness-incomplete", title: "Rendered content did not settle within the audit budget",
        severity: "info", manual: true, description: safeError(error),
        recommendation: "Complete loading and hydration before relying on DOM or performance results; rerun against an available backend.",
        evidence: routeEvidence(observedUrl), tags: ["runtime", "coverage", "manual-review"] }));
    }

    const rawSnapshot = await stage("measurement", limits.measurementTimeoutMs, () => page.evaluate(runtimeSnapshot));
    snapshot = normalizeSnapshot(rawSnapshot);
    counters.blockedEgressAttempts += snapshot.policy.blockedEgressAttempts;
    for (const kind of snapshot.policy.blockedEgressKinds) {
      if (!counters.blockedEgressKinds.includes(kind) && counters.blockedEgressKinds.length < 10) {
        counters.blockedEgressKinds.push(kind);
      }
    }
    findings.push(...findingsFromSnapshot(observedUrl, snapshot));

    if (axeCapability.available) {
      try {
        const axeResults = await stage("accessibility", limits.accessibilityTimeoutMs, () => runAxe(page, axeCapability));
        const normalized = normalizeAxeResults(observedUrl, axeResults);
        accessibility = normalized.metrics;
        findings.push(...normalized.findings);
      } catch (error) {
        accessibility = { status: error?.timedOut ? "timed-out" : "failed", reason: safeError(error), violations: 0, affectedNodes: 0, incomplete: 0, passes: 0 };
        findings.push(finding({
          id: "runtime.axe-failed",
          title: "Browser accessibility audit could not complete",
          severity: "info",
          description: safeError(error),
          recommendation: "Verify the installed axe integration and rerun the runtime audit.",
          evidence: routeEvidence(observedUrl),
          tags: ["runtime", "accessibility", "axe"],
          manual: true,
        }));
      }
    } else {
      stages.accessibility = { status: "unavailable", durationMs: 0, reason: axeCapability.reason };
    }
    findings.push(...eventFindings(observedUrl, counters));
    const corePerformanceMeasured = snapshot.performance.measurementSupport?.largestContentfulPaint === true
      && snapshot.performance.measurementSupport?.cumulativeLayoutShift === true;
    routeStatus = counters.blockedRequests > 0
      || counters.blockedEgressAttempts > 0
      || !corePerformanceMeasured
      || accessibility.status !== "completed"
      || stages["load-state"]?.status !== "completed"
      || stages.instrumentation?.status !== "completed"
      || stages.stabilization?.status !== "completed"
      ? "partial"
      : "completed";
  } catch (error) {
    const navigationFailure = error?.stage === "navigation";
    const navigationTimeout = navigationFailure && error?.timedOut;
    findings.push(...eventFindings(routeUrl, counters));
    findings.push(finding({
      id: navigationFailure
        ? (navigationTimeout ? "runtime.route-timeout" : "runtime.route-failed")
        : "runtime.audit-infrastructure-failed",
      title: navigationFailure
        ? (navigationTimeout ? "Runtime route navigation timed out" : "Runtime route navigation failed")
        : "Runtime audit infrastructure could not complete the route",
      severity: navigationFailure ? "high" : "info",
      description: safeError(error),
      recommendation: navigationFailure
        ? "Confirm that the URL is already serving, loads without authentication, and completes within the configured navigation limit."
        : "Verify the Playwright/browser environment and rerun; this coverage failure is not scored as a site defect.",
      evidence: routeEvidence(routeUrl),
      tags: navigationFailure ? ["runtime", "reliability"] : ["runtime", "coverage", "capability"],
      manual: !navigationFailure,
    }));
  } finally {
    const cleanup = await closeResource(context ?? page, limits.cleanupTimeoutMs);
    stages.cleanup = cleanup;
    if (cleanup.status === "failed") {
      findings.push(finding({
        id: "runtime.cleanup-failed",
        title: "Browser route cleanup did not complete",
        severity: "info",
        description: cleanup.reason,
        recommendation: "Terminate the orphaned browser process before rerunning the audit and review the Playwright installation.",
        evidence: routeEvidence(routeUrl),
        tags: ["runtime", "process-safety"],
        manual: true,
      }));
      routeStatus = "failed";
    }
  }

  return {
    status: routeStatus,
    url: safeDisplayUrl(routeUrl),
    finalUrl,
    httpStatus,
    responseHeaders: Object.fromEntries(Object.entries(responseHeaders).map(([name, value]) =>
      [name, sanitizeEvidence(redactUrlQueries(value), 180)])),
    viewport,
    durationMs: elapsed(startedAt),
    stages,
    metrics: snapshot,
    network: {
      blockedRequests: counters.blockedRequests,
      blockedEgressAttempts: counters.blockedEgressAttempts,
      requestFailures: counters.requestFailures,
      consoleErrors: counters.consoleErrors,
      pageErrors: counters.pageErrors,
    },
    accessibility,
    findings,
  };
}

function aggregateMetrics(routes, requestedRoutes = routes.length) {
  const snapshots = routes.map((route) => route.metrics).filter(Boolean);
  return {
    routesRequested: requestedRoutes,
    routesAudited: routes.filter((route) => route.metrics).length,
    routesCompleted: routes.filter((route) => route.status === "completed").length,
    routesPartial: routes.filter((route) => route.status === "partial").length,
    routesFailed: routes.filter((route) => route.status === "failed").length,
    blockedRequests: routes.reduce((sum, route) => sum + route.network.blockedRequests, 0),
    blockedEgressAttempts: routes.reduce((sum, route) => sum + route.network.blockedEgressAttempts, 0),
    requestFailures: routes.reduce((sum, route) => sum + route.network.requestFailures, 0),
    consoleErrors: routes.reduce((sum, route) => sum + route.network.consoleErrors, 0),
    pageErrors: routes.reduce((sum, route) => sum + route.network.pageErrors, 0),
    accessibilityViolations: routes.reduce((sum, route) => sum + route.accessibility.violations, 0),
    accessibilityAffectedNodes: routes.reduce((sum, route) => sum + route.accessibility.affectedNodes, 0),
    resourceCount: snapshots.reduce((sum, snapshot) => sum + snapshot.performance.resourceCount, 0),
    longTaskCount: snapshots.reduce((sum, snapshot) => sum + (snapshot.performance.longTaskCount ?? 0), 0),
    longTaskDurationMs: snapshots.reduce((sum, snapshot) => sum + (snapshot.performance.longTaskDurationMs ?? 0), 0),
    transferredBytes: snapshots.reduce((sum, snapshot) => (
      sum + snapshot.performance.resourceTransferBytes + (snapshot.navigation?.transferBytes ?? 0)
    ), 0),
    performanceCoverage: {
      largestContentfulPaint: snapshots.filter((snapshot) => snapshot.performance.measurementStatus?.largestContentfulPaint === "measured").length,
      cumulativeLayoutShift: snapshots.filter((snapshot) => snapshot.performance.measurementStatus?.cumulativeLayoutShift === "measured").length,
      longTasks: snapshots.filter((snapshot) => snapshot.performance.measurementStatus?.longTasks === "measured").length,
    },
    routes,
  };
}

export function runtimeCheckDescriptors(routeResults, { disabled = false, requestedRoutes = routeResults.length } = {}) {
  if (disabled) return RUNTIME_RULE_FAMILIES.map((descriptor) => ({ ...descriptor, status: "skipped" }));
  const expectedRoutes = Math.max(
    routeResults.length,
    Number.isSafeInteger(requestedRoutes) && requestedRoutes >= 0 ? requestedRoutes : routeResults.length,
  );
  const familyStatus = (completed) => {
    const completedRoutes = routeResults.filter(completed).length;
    if (expectedRoutes > 0 && completedRoutes === expectedRoutes) return "completed";
    return completedRoutes > 0 ? "partial" : "unavailable";
  };
  const measured = (route) => route.metrics !== null;
  const receivedHttp = (route) => route.httpStatus !== null;
  const observedBrowser = (route) => route.stages.page?.status === "completed";
  const guardedNetwork = (route) => route.stages["network-policy"]?.status === "completed";
  const completedAxe = (route) => route.accessibility.status === "completed";
  const completedPerformance = (route) => {
    const performance = route?.metrics?.performance;
    if (!performance) return false;
    const supportsLcp = Number.isFinite(performance.largestContentfulPaintMs);
    const supportsCls = Number.isFinite(performance.cumulativeLayoutShift);
    return supportsLcp && supportsCls;
  };
  const headerStatuses = routeResults.map((route) => route.stages["security-headers"]?.status).filter(Boolean);
  const securityHeadersStatus = headerStatuses.length > 0 && headerStatuses.every((status) => status === "skipped")
    ? "skipped"
    : familyStatus((route) => route.stages["security-headers"]?.status === "completed");
  const statuses = {
    "runtime-http": familyStatus(receivedHttp),
    "runtime-rendered-document": familyStatus(measured),
    "runtime-rendered-metadata": familyStatus(measured),
    "runtime-rendered-forms": familyStatus(measured),
    "runtime-rendered-layout": familyStatus(measured),
    "runtime-lab-performance": routeResults.some(completedPerformance)
      ? familyStatus(completedPerformance)
      : (routeResults.some(measured) ? "partial" : "unavailable"),
    "runtime-security-headers": securityHeadersStatus,
    "runtime-browser-errors": familyStatus(observedBrowser),
    "runtime-network": familyStatus(guardedNetwork),
    "runtime-axe-a11y": familyStatus(completedAxe),
  };
  return RUNTIME_RULE_FAMILIES.map((descriptor) => ({ ...descriptor, status: statuses[descriptor.id] }));
}

function disabledResult(input, startedAt) {
  const root = path.resolve(String(input.root ?? process.cwd()));
  const checkDescriptors = runtimeCheckDescriptors([], { disabled: true });
  const base = buildScanResult({
    mode: "runtime",
    title: "Runtime browser audit",
    root,
    findings: [],
    checks: 0,
    filesScanned: 0,
    startedAt,
    metadata: { checks: checkDescriptors },
  });
  return {
    ...base,
    status: "disabled",
    url: input.url ? safeDisplayUrl(input.url) : null,
    capabilities: {
      playwright: { available: false, checked: false },
      axe: { available: false, checked: false },
    },
    stages: { validation: { status: "disabled", durationMs: 0 } },
    checkDescriptors,
    metrics: aggregateMetrics([]),
    policy: { optIn: false, allowRemote: false, repositoryScriptsExecuted: false },
  };
}

/**
 * Audit an already-running website with a disposable Playwright browser.
 *
 * Nothing is launched unless `enabled: true` and an explicit `url` are both
 * supplied. This function never runs package-manager or repository scripts and
 * never starts the target development server.
 */
export async function runRuntimeBrowserAudit(input = {}) {
  const startedAt = now();
  if (input.enabled !== true) return disabledResult(input, startedAt);

  const recorder = createStageRecorder();
  const validated = await recorder.run("validation", async () => {
    const root = await canonicalDirectory(input.root ?? process.cwd());
    if (!input.url) {
      throw new RuntimeAuditError(
        "RUNTIME_URL_REQUIRED",
        "An explicit URL is required for an opt-in runtime audit; Modular will not start repository scripts.",
        { stage: "validation" },
      );
    }
    const allowRemote = input.allowRemote === true;
    const baseUrl = parseHttpUrl(input.url, "url");
    if (!allowRemote && !isLoopbackHostname(baseUrl.hostname)) {
      throw new RuntimeAuditError(
        "REMOTE_URL_NOT_ALLOWED",
        "Remote runtime auditing is disabled. Use a loopback URL or explicitly set allowRemote: true.",
        { stage: "validation" },
      );
    }
    const maxRoutes = boundedInteger(input.maxRoutes, RUNTIME_AUDIT_DEFAULTS.maxRoutes, "maxRoutes", MAX_RUNTIME_ROUTES);
    const limits = {
      maxRoutes,
      totalTimeoutMs: boundedInteger(input.totalTimeoutMs, RUNTIME_AUDIT_DEFAULTS.totalTimeoutMs, "totalTimeoutMs"),
      launchTimeoutMs: boundedInteger(input.launchTimeoutMs, RUNTIME_AUDIT_DEFAULTS.launchTimeoutMs, "launchTimeoutMs"),
      navigationTimeoutMs: boundedInteger(input.navigationTimeoutMs, RUNTIME_AUDIT_DEFAULTS.navigationTimeoutMs, "navigationTimeoutMs"),
      loadTimeoutMs: boundedInteger(input.loadTimeoutMs, RUNTIME_AUDIT_DEFAULTS.loadTimeoutMs, "loadTimeoutMs"),
      stabilizationMs: boundedInteger(input.stabilizationMs, RUNTIME_AUDIT_DEFAULTS.stabilizationMs, "stabilizationMs", 10_000),
      measurementTimeoutMs: boundedInteger(input.measurementTimeoutMs, RUNTIME_AUDIT_DEFAULTS.measurementTimeoutMs, "measurementTimeoutMs"),
      accessibilityTimeoutMs: boundedInteger(input.accessibilityTimeoutMs, RUNTIME_AUDIT_DEFAULTS.accessibilityTimeoutMs, "accessibilityTimeoutMs"),
      cleanupTimeoutMs: boundedInteger(input.cleanupTimeoutMs, RUNTIME_AUDIT_DEFAULTS.cleanupTimeoutMs, "cleanupTimeoutMs"),
    };
    const browserName = input.browserName ?? RUNTIME_AUDIT_DEFAULTS.browserName;
    if (!BROWSER_NAMES.has(browserName)) {
      throw new RuntimeAuditError("INVALID_RUNTIME_BROWSER", "browserName must be chromium, firefox, or webkit.", {
        stage: "validation",
      });
    }
    const browserChannel = input.browserChannel ?? null;
    if (browserChannel !== null
      && (browserName !== "chromium" || !CHROMIUM_CHANNELS.has(browserChannel))) {
      throw new RuntimeAuditError(
        "INVALID_RUNTIME_BROWSER_CHANNEL",
        "browserChannel requires chromium and must name a supported installed Chrome or Edge channel.",
        { stage: "validation" },
      );
    }
    const viewportPreset = input.viewportPreset ?? RUNTIME_AUDIT_DEFAULTS.viewportPreset;
    if (!Object.hasOwn(RUNTIME_VIEWPORTS, viewportPreset)) {
      throw new RuntimeAuditError(
        "INVALID_RUNTIME_VIEWPORT",
        "viewportPreset must be mobile or desktop.",
        { stage: "validation" },
      );
    }
    return {
      root,
      allowRemote,
      auditSecurityHeaders: input.auditSecurityHeaders !== false,
      baseUrl,
      browserName,
      browserChannel,
      limits,
      routes: validateRouteList(baseUrl, input.routes, { allowRemote, maxRoutes }),
      viewportPreset,
      viewport: RUNTIME_VIEWPORTS[viewportPreset],
    };
  });

  safeProgress(input.onProgress, { stage: "capability-discovery", current: 0, total: validated.routes.length });
  let capabilities;
  try {
    capabilities = await recorder.run("capabilityDiscovery", () => withTimeout(
      () => Promise.resolve(normalizeInjectedCapabilities(input.adapters)
        ?? discoverRuntimeCapabilities({ root: validated.root, includeModuleFallback: input.includeModuleFallback !== false })),
      Math.min(validated.limits.measurementTimeoutMs, validated.limits.totalTimeoutMs),
      "capability-discovery",
      { signal: input.signal },
    ));
  } catch (error) {
    capabilities = {
      playwright: { available: false, packageName: null, source: null, reason: safeError(error), api: null },
      axe: { available: false, packageName: null, source: null, reason: safeError(error), api: null },
    };
  }
  const exposedCapabilities = publicCapabilities(capabilities, validated.browserName, validated.browserChannel);
  const findings = [];
  const routeResults = [];
  let status = "unavailable";
  let browser;

  if (!capabilities.playwright.available || !exposedCapabilities.playwright.browserTypeAvailable) {
    findings.push(finding({
      id: "runtime.playwright-unavailable",
      title: "Runtime browser audit is unavailable",
      severity: "info",
      description: capabilities.playwright.reason
        ?? `The discovered Playwright package does not expose ${validated.browserName}.`,
      recommendation: "Install Playwright in the target project, install its selected browser, then rerun with explicit runtime opt-in.",
      tags: ["runtime", "browser", "capability"],
      manual: true,
    }));
    recorder.mark("launch", "unavailable", "A compatible Playwright browser type was not found.");
  } else {
    if (!capabilities.axe.available) {
      findings.push(finding({
        id: "runtime.axe-unavailable",
        title: "Rendered accessibility audit is unavailable",
        severity: "info",
        description: capabilities.axe.reason,
        recommendation: "Install @axe-core/playwright or axe-core in the target project to include rendered accessibility checks.",
        tags: ["runtime", "accessibility", "capability"],
        manual: true,
      }));
    }

    const deadlineAt = startedAt + validated.limits.totalTimeoutMs;
    try {
      browser = await recorder.run("launch", () => withTimeout(
        () => capabilities.playwright.api[validated.browserName].launch({
          headless: true,
          ...(validated.browserName === "chromium" ? { chromiumSandbox: true } : {}),
          ...(validated.browserChannel ? { channel: validated.browserChannel } : {}),
        }),
        Math.max(1, Math.min(validated.limits.launchTimeoutMs, deadlineAt - now())),
        "browser-launch",
        {
          onLateResolve: (lateBrowser) => closeResource(lateBrowser, validated.limits.cleanupTimeoutMs),
          signal: input.signal,
        },
      ));
    } catch (error) {
      findings.push(finding({
        id: "runtime.browser-launch-failed",
        title: "Playwright browser could not launch",
        severity: "info",
        description: safeError(error),
        recommendation: "Install the selected Playwright browser and verify that sandboxed headless execution is supported.",
        tags: ["runtime", "browser", "capability"],
        manual: true,
      }));
    }

    if (browser) {
      for (let index = 0; index < validated.routes.length; index += 1) {
        if (input.signal?.aborted) break;
        const routeUrl = validated.routes[index];
        if (now() >= deadlineAt) {
          findings.push(finding({
            id: "runtime.total-timeout",
            title: "Runtime audit reached its total time limit",
            severity: "info",
            description: `${validated.routes.length - index} route(s) were not audited.`,
            recommendation: "Reduce the route set, fix slow routes, or deliberately raise the bounded total timeout.",
            evidence: routeEvidence(routeUrl),
            tags: ["runtime", "coverage", "timeout"],
            manual: true,
          }));
          break;
        }
        safeProgress(input.onProgress, {
          stage: "route",
          current: index + 1,
          total: validated.routes.length,
          url: safeDisplayUrl(routeUrl),
        });
        const routeResult = await auditRoute({
          browser,
          routeUrl,
          allowRemote: validated.allowRemote,
          auditSecurityHeaders: validated.auditSecurityHeaders,
          axeCapability: capabilities.axe,
          limits: validated.limits,
          deadlineAt,
          signal: input.signal,
          viewport: {
            preset: validated.viewportPreset,
            ...validated.viewport,
          },
        });
        routeResults.push(routeResult);
        findings.push(...routeResult.findings);
        if (input.signal?.aborted) break;
      }
      status = routeResults.length === validated.routes.length
        && routeResults.every((route) => route.status === "completed")
        && capabilities.axe.available
        ? "completed"
        : "partial";
    }
  }

  const cleanupStartedAt = now();
  const cleanup = await closeResource(browser, validated.limits.cleanupTimeoutMs);
  recorder.stages.cleanup = { ...cleanup, durationMs: elapsed(cleanupStartedAt) };
  if (cleanup.status === "failed") {
    status = status === "unavailable" ? "unavailable" : "partial";
    findings.push(finding({
      id: "runtime.browser-cleanup-failed",
      title: "Browser process cleanup did not complete",
      severity: "info",
      description: cleanup.reason,
      recommendation: "Terminate the orphaned browser process and inspect the Playwright/browser installation before retrying.",
      tags: ["runtime", "browser", "process-safety"],
      manual: true,
    }));
  }

  if (input.signal?.aborted) throw abortError();

  const metrics = aggregateMetrics(routeResults, validated.routes.length);
  const checkDescriptors = runtimeCheckDescriptors(routeResults, { requestedRoutes: validated.routes.length });
  const base = buildScanResult({
    mode: "runtime",
    title: "Runtime browser audit",
    root: validated.root,
    findings,
    checks: RUNTIME_RULE_FAMILIES.length,
    filesScanned: 0,
    startedAt,
    metadata: {
      status,
      checks: checkDescriptors,
      capabilities: exposedCapabilities,
      policy: {
        optIn: true,
        allowRemote: validated.allowRemote,
        localOnly: !validated.allowRemote,
        workerAndDirectTransportApisDisabled: !validated.allowRemote,
        webSocketInterceptionRequired: !validated.allowRemote,
        securityHeadersAudited: validated.auditSecurityHeaders,
        repositoryScriptsExecuted: false,
      },
      coverage: {
        requestedRoutes: validated.routes.length,
        auditedRoutes: routeResults.length,
        skippedRoutes: validated.routes.length - routeResults.length,
      },
      viewport: {
        preset: validated.viewportPreset,
        ...validated.viewport,
      },
    },
  });
  return {
    ...base,
    status,
    url: safeDisplayUrl(validated.baseUrl),
    capabilities: exposedCapabilities,
    stages: recorder.stages,
    limits: validated.limits,
    viewport: {
      preset: validated.viewportPreset,
      ...validated.viewport,
    },
    checkDescriptors,
    metrics,
    policy: {
      optIn: true,
      allowRemote: validated.allowRemote,
      localOnly: !validated.allowRemote,
      workerAndDirectTransportApisDisabled: !validated.allowRemote,
      webSocketInterceptionRequired: !validated.allowRemote,
      securityHeadersAudited: validated.auditSecurityHeaders,
      repositoryScriptsExecuted: false,
    },
  };
}
