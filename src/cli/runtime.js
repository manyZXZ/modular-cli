import path from "node:path";
import { buildScanResult } from "../core/model.js";
import { RUNTIME_RULE_FAMILIES, runRuntimeBrowserAudit, startRuntimeStaticServer } from "../runtime/index.js";
import { throwIfInterrupted } from "./errors.js";

function runtimeDisplayUrl(value) {
  try {
    const target = new URL(String(value));
    target.username = "";
    target.password = "";
    target.search = "";
    target.hash = "";
    return target.href;
  } catch {
    return "<invalid runtime URL>";
  }
}

function runtimeFailureResult(root, error, previous = null) {
  const reason = error instanceof Error ? error.message : String(error);
  const descriptors = previous?.checkDescriptors
    ?? previous?.metadata?.checks
    ?? RUNTIME_RULE_FAMILIES.map((descriptor) => ({ ...descriptor, status: "unavailable" }));
  const findings = [
    ...(previous?.findings ?? []),
    {
      id: "runtime.orchestration-failed",
      ruleFamily: "runtime-browser-errors",
      title: "Requested runtime audit did not complete",
      category: "Runtime & Browser",
      severity: "info",
      confidence: "high",
      description: reason,
      recommendation: "Resolve the reported runtime setup or cleanup failure, then rerun the explicit browser audit.",
      manual: true,
      tags: ["runtime", "coverage"],
    },
  ];
  const base = buildScanResult({
    mode: "runtime",
    title: "Runtime browser audit",
    root,
    findings,
    checks: previous?.checks ?? RUNTIME_RULE_FAMILIES.length,
    filesScanned: 0,
    startedAt: Date.now() - Number(previous?.durationMs ?? 0),
    metadata: {
      ...(previous?.metadata ?? {}),
      status: previous ? "partial" : "unavailable",
      checks: descriptors,
    },
  });
  return {
    ...base,
    status: previous ? "partial" : "unavailable",
    url: previous?.url ?? null,
    capabilities: previous?.capabilities ?? {
      playwright: { available: false, checked: false },
      axe: { available: false, checked: false },
    },
    stages: {
      ...(previous?.stages ?? {}),
      orchestration: { status: "failed", durationMs: 0, reason },
    },
    limits: previous?.limits ?? null,
    checkDescriptors: descriptors,
    metrics: previous?.metrics ?? {
      routesRequested: 0,
      routesAudited: 0,
      routesCompleted: 0,
      routesPartial: 0,
      routesFailed: 0,
      blockedRequests: 0,
      requestFailures: 0,
      consoleErrors: 0,
      pageErrors: 0,
      accessibilityViolations: 0,
      accessibilityAffectedNodes: 0,
      resourceCount: 0,
      transferredBytes: 0,
      routes: [],
    },
    policy: previous?.policy ?? {
      optIn: true,
      allowRemote: false,
      localOnly: true,
      repositoryScriptsExecuted: false,
    },
  };
}

export async function runRequestedRuntimeAudit(options, ui, runtime) {
  const startServer = runtime.startRuntimeStaticServer ?? startRuntimeStaticServer;
  const audit = runtime.runRuntimeBrowserAudit ?? runRuntimeBrowserAudit;
  let server = null;
  let result = null;
  let failure = null;
  let abortClosePromise = null;
  const closeServerForAbort = () => {
    if (server && !abortClosePromise) abortClosePromise = Promise.resolve().then(() => server.close());
  };
  runtime.signal?.addEventListener("abort", closeServerForAbort, { once: true });

  try {
    throwIfInterrupted(runtime.signal);
    if (options.runtimeStaticDir) {
      ui.info(`Starting an isolated loopback server for ${path.relative(options.root, options.runtimeStaticDir) || options.runtimeStaticDir}…`);
      server = await startServer({
        enabled: true,
        root: options.root,
        directory: options.runtimeStaticDir,
        spaFallback: options.runtimeSpaFallback,
      });
      throwIfInterrupted(runtime.signal);
    }
    const targetUrl = server?.url ?? options.runtimeUrl;
    const displayTargetUrl = runtimeDisplayUrl(targetUrl);
    result = await audit({
      enabled: true,
      root: options.root,
      url: targetUrl,
      routes: options.runtimeRoutes,
      allowRemote: options.runtimeAllowRemote,
      browserName: options.runtimeBrowser,
      browserChannel: options.runtimeBrowserChannel,
      viewportPreset: options.runtimeViewport,
      auditSecurityHeaders: !options.runtimeStaticDir,
      maxRoutes: options.runtimeMaxRoutes,
      totalTimeoutMs: options.runtimeTimeoutMs,
      signal: runtime.signal,
      onProgress: (state) => ui.progress({
        current: state.current ?? 0,
        total: state.total ?? options.runtimeRoutes.length + 1,
        phase: `Runtime browser · ${state.stage ?? "audit"}`,
        file: state.url ? runtimeDisplayUrl(state.url) : displayTargetUrl,
        check: options.runtimeBrowser,
      }),
    });
    throwIfInterrupted(runtime.signal);
  } catch (error) {
    failure = error;
  } finally {
    runtime.signal?.removeEventListener("abort", closeServerForAbort);
    if (server) {
      try {
        await (abortClosePromise ?? server.close());
      } catch (error) {
        failure ??= error;
      }
    }
  }

  throwIfInterrupted(runtime.signal);

  const completed = failure ? runtimeFailureResult(options.root, failure, result) : result;
  return {
    ...completed,
    source: options.runtimeStaticDir ? "isolated existing static build" : "already-running explicit URL",
  };
}

export function mergeSiteAndRuntime(siteResult, runtimeResult) {
  const siteChecks = Array.isArray(siteResult.metadata?.checks) ? siteResult.metadata.checks : [];
  const siteLedger = Array.isArray(siteResult.metadata?.checkLedger)
    ? siteResult.metadata.checkLedger
    : siteChecks;
  const runtimeChecks = runtimeResult.checkDescriptors
    ?? runtimeResult.metadata?.checks
    ?? [];
  const runtimeMetrics = runtimeResult.metrics ?? {};
  const hasRuntimeEvidence = Number(runtimeMetrics.routesAudited ?? 0) > 0;
  const existingLimitations = Array.isArray(siteResult.metadata?.limitations)
    ? siteResult.metadata.limitations.filter((item) => !hasRuntimeEvidence
      || !String(item).startsWith("Static analysis cannot prove rendered visual quality"))
    : [];
  const runtimeStatus = runtimeResult.status ?? "unavailable";
  const browserName = runtimeResult.capabilities?.playwright?.browserName ?? "unknown";
  const browserChannel = runtimeResult.capabilities?.playwright?.browserChannel;
  const browser = browserChannel ? `${browserName}/${browserChannel}` : browserName;
  const viewport = runtimeResult.viewport;
  const viewportLabel = viewport?.preset
    ? `${viewport.preset} ${Number(viewport.width ?? 0)}x${Number(viewport.height ?? 0)}`
    : "configured viewport";
  const runtimeRoutes = Array.isArray(runtimeMetrics.routes) ? runtimeMetrics.routes : [];
  const axeAvailable = runtimeResult.capabilities?.axe?.available === true;
  const axeCompleted = runtimeRoutes.length > 0
    && runtimeRoutes.every((route) => route.accessibility?.status === "completed");
  const axe = !axeAvailable ? "unavailable" : axeCompleted ? "completed" : "available but incomplete";
  const coverage = {
    ...(siteResult.metadata?.coverage ?? {}),
    "Runtime browser audit": `${runtimeStatus}; ${Number(runtimeMetrics.routesAudited ?? 0)}/${Number(runtimeMetrics.routesRequested ?? 0)} requested routes observed with ${browser}; Axe ${axe}`,
  };

  return buildScanResult({
    mode: "mysite",
    title: hasRuntimeEvidence ? "Website quality & runtime report" : "Website quality report (runtime unavailable)",
    root: siteResult.root,
    findings: [...siteResult.findings, ...runtimeResult.findings],
    checks: siteResult.checks + runtimeResult.checks,
    filesScanned: siteResult.filesScanned,
    startedAt: Date.now() - siteResult.durationMs - runtimeResult.durationMs,
    metadata: {
      ...siteResult.metadata,
      checks: [...siteChecks, ...runtimeChecks],
      checkLedger: [...siteLedger, ...runtimeChecks],
      coverage,
      runtime: {
        requested: true,
        target: runtimeResult.url,
        source: runtimeResult.source ?? "explicit runtime target",
        viewport: runtimeResult.viewport,
        status: runtimeStatus,
        durationMs: runtimeResult.durationMs,
        capabilities: runtimeResult.capabilities,
        stages: runtimeResult.stages,
        limits: runtimeResult.limits,
        metrics: runtimeMetrics,
        policy: runtimeResult.policy,
      },
      limitations: [
        ...existingLimitations,
        `The runtime audit sampled ${Number(runtimeMetrics.routesAudited ?? 0)} requested route(s) in one ${browser} ${viewportLabel} context; it is not field Core Web Vitals, authenticated-flow, cross-browser/device, assistive-technology, penetration, or real-user testing.`,
      ],
    },
  });
}
