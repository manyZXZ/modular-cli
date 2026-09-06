import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { runRuntimeBrowserAudit } from "../src/runtime/browser-audit.js";

// Explicit integration command: never silently skip a missing package/browser.
const temp = await fs.realpath(os.tmpdir());
const root = await fs.mkdtemp(path.join(temp, "modular-real-browser-"));
const csp = `default-src 'self'; img-src ${Array.from({ length: 15 }, (_, i) => `https://cdn${i}.example.test`).join(" ")}; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'`;
const evalPolicies = new Map([
  ["/csp-override", { policy: "default-src 'self' 'unsafe-eval'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'", allowed: false }],
  ["/csp-element", { policy: "script-src 'self'; script-src-elem 'self' 'unsafe-eval'; frame-ancestors 'none'", allowed: false }],
  ["/csp-duplicate", { policy: "script-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'", allowed: false }],
  ["/csp-multiple", { policy: ["script-src 'self' 'unsafe-eval'; frame-ancestors 'none'", "script-src 'self'"], allowed: false }],
  ["/csp-fallback", { policy: "default-src 'self' 'unsafe-eval'; frame-ancestors 'none'", allowed: true }],
]);
const evalOutcomes = new Map();
const html = (broken = false) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Browser integration</title><meta name="viewport" content="width=device-width"><meta name="description" content="Local runtime verification"></head><body><main><h1>Browser integration</h1><form><input type="submit" value="Send"><label for="email">Email</label><input id="email" type="email">${broken ? '<input type="text" aria-labelledby="missing-id">' : ''}</form></main></body></html>`;
const server = http.createServer((request, response) => {
  if (request.url.startsWith("/eval-result?")) {
    const params = new URL(request.url, "http://127.0.0.1").searchParams;
    evalOutcomes.set(params.get("route"), params.get("allowed") === "true");
    response.writeHead(204);
    response.end();
    return;
  }
  if (request.url === "/fixture.css") {
    response.writeHead(200, { "Content-Type": "text/css" });
    response.end(".hidden-loader, .hidden-control { display: none; } .hidden-content { content-visibility: hidden; } .hidden-visibility { visibility: hidden; } .visible-child { visibility: visible; } .offscreen { position: absolute; left: -10000px; }");
    return;
  }
  if (request.url === "/deferred.js") {
    response.writeHead(200, { "Content-Type": "text/javascript" });
    response.end("setTimeout(() => { document.querySelector('[role=status]').outerHTML = '<h1>Loaded route</h1>'; }, 900);");
    return;
  }
  if (request.url === "/eval.js") {
    response.writeHead(200, { "Content-Type": "text/javascript" });
    response.end("let allowed = false; try { allowed = new Function('return 42')() === 42; } catch {} fetch('/eval-result?route=' + encodeURIComponent(location.pathname) + '&allowed=' + allowed, { cache: 'no-store' });");
    return;
  }
  const evalPolicy = evalPolicies.get(request.url);
  response.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": evalPolicy?.policy ?? csp,
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin" });
  response.end(request.url === "/delayed"
    ? html().replace('</head>', '<link rel="stylesheet" href="/fixture.css"></head>').replace('<h1>Browser integration</h1>', '<div role="status">Loading...</div><div class="hidden-loader"><div role="progressbar"></div></div><script src="/deferred.js"></script>')
    : request.url === "/busy" ? html().replace('<h1>Browser integration</h1>', '<div role="status">Loading...</div>')
    : request.url === "/hidden-controls" ? html().replace('</head>', '<link rel="stylesheet" href="/fixture.css"></head>').replace('</form>', '<div class="hidden-control"><input type="text"></div><div class="hidden-content"><input type="text"></div><div class="hidden-visibility"><input type="text" class="visible-child" aria-label="Visible override"></div><input type="text" class="offscreen" aria-label="Offscreen control"></form>')
    : evalPolicy ? html().replace('</body>', '<script src="/eval.js"></script></body>')
    : html(request.url === "/broken"));
});
try {
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const url = `http://127.0.0.1:${server.address().port}/`;
  const routes = ["/broken", "/delayed", "/hidden-controls", ...evalPolicies.keys()];
  const result = await runRuntimeBrowserAudit({ enabled: true, root, url, routes, maxRoutes: routes.length + 1,
    browserChannel: process.env.MODULAR_TEST_BROWSER_CHANNEL || null, totalTimeoutMs: 60000 });
  assert.equal(result.status, "completed", JSON.stringify(result.findings));
  assert.equal(result.capabilities.axe.available, true);
  assert.equal(result.metrics.routes.length, routes.length + 1);
  const [good, broken, delayed, hidden, ...evalRoutes] = result.metrics.routes;
  assert.equal(delayed.metrics.document.h1Count, 1);
  assert.equal(delayed.findings.some(({ id }) => id === "runtime.missing-h1"), false);
  assert.ok(delayed.stages.stabilization.durationMs >= 900);
  assert.equal(good.metrics.document.unlabeledFormControlCount, 0);
  assert.equal(good.metrics.performance.cumulativeLayoutShift, 0);
  assert.equal(broken.metrics.performance.cumulativeLayoutShift, 0);
  assert.equal(broken.metrics.document.unlabeledFormControlCount, 1);
  assert.ok(broken.findings.some(({ id }) => id.startsWith("runtime.axe.") && /label/.test(id)));
  assert.equal(hidden.metrics.document.formControlCount, 4);
  assert.equal(hidden.metrics.document.unlabeledFormControlCount, 0);
  assert.equal(hidden.findings.some(({ id }) => id === "runtime.unlabeled-controls"), false);
  assert.equal(evalOutcomes.size, evalPolicies.size, "each CSP fixture must report its actual eval result to the local server");
  for (const [index, [routePath, { allowed }]] of [...evalPolicies.entries()].entries()) {
    const route = evalRoutes[index];
    assert.equal(evalOutcomes.get(routePath), allowed, routePath);
    assert.equal(route.findings.some(({ id }) => id === "runtime.header-csp-unsafe-eval"), allowed);
  }
  for (const route of result.metrics.routes) {
    if (!evalRoutes.includes(route)) assert.ok(route.findings.some(({ id }) => id === "runtime.header-csp-unsafe-eval"));
    assert.equal(route.findings.some(({ id }) => id === "runtime.header-frame-protection-missing"), false);
    assert.equal(route.metrics.performance.measurementStatus.largestContentfulPaint, "measured");
    assert.ok(Number.isFinite(route.metrics.performance.cumulativeLayoutShift));
  }
  const busy = await runRuntimeBrowserAudit({ enabled: true, root, url: new URL('/busy', url).href,
    browserChannel: process.env.MODULAR_TEST_BROWSER_CHANNEL || null, measurementTimeoutMs: 1000, totalTimeoutMs: 10000 });
  assert.equal(busy.status, "partial");
  assert.ok(busy.findings.some(({ id }) => id === "runtime.render-readiness-incomplete"));
  console.log(`Real browser and Axe integration passed: native names, hidden/offscreen controls, missing ARIA references, CSP precedence/duplicates/multiple policies checked against actual eval, deferred rendering, hidden loading indicators, readiness timeout and measured LCP/CLS (${result.metrics.routes.length + 1} routes).`);
} finally {
  await new Promise((resolve) => server.close(resolve));
  server.closeAllConnections();
  const real = await fs.realpath(root);
  if (path.dirname(real).toLowerCase() !== temp.toLowerCase() || !path.basename(real).startsWith("modular-real-browser-")) {
    throw new Error("Refusing cleanup outside the browser fixture.");
  }
  await fs.rm(real, { recursive: true, force: true });
}
