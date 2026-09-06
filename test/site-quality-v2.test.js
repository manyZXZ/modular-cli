import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { collectFiles } from "../src/core/files.js";
import { detectWebProject } from "../src/core/project.js";
import { runSiteScan } from "../src/scanners/mysite.js";

async function fixture(t, entries) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-site-v2-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const [relative, value] of Object.entries(entries)) {
    const destination = path.join(root, relative);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, typeof value === "string" || Buffer.isBuffer(value)
      ? value
      : JSON.stringify(value, null, 2));
  }
  const inventory = await collectFiles(root);
  const webDetection = await detectWebProject({ root, files: inventory.files });
  return { root, ...inventory, webDetection };
}

function ids(result) {
  return new Set(result.findings.map(({ id }) => id));
}

test("website scan validates canonical, document-head, JSON-LD, zoom, and timed refresh contracts", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "index.html": [
      "<!doctype html><html lang=\"en\"><head>",
      "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, maximum-scale=1, user-scalable=no\">",
      "<meta content=\"0;url=/next\" http-equiv=\"refresh\">",
      "<title>First</title><title>Second</title>",
      "<meta name=\"description\" content=\"The same route description\">",
      "<link rel=\"canonical\" href=\"/relative\"><link href=\"https://example.test/other\" rel=\"canonical\">",
      "<script type=\"application/ld+json\">{\"@context\":\"https://schema.org\", broken}</script>",
      "</head><body><main><h1>Home</h1></main></body></html>",
    ].join(""),
    "about.html": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>About</title><meta name=\"description\" content=\"The same route description\"><link rel=\"canonical\" href=\"https://example.test/about\"></head><body><main><h1>About</h1></main></body></html>",
  });

  const result = await runSiteScan({ ...project, options: { includeManualReviews: false } });
  const found = ids(result);
  for (const expected of [
    "seo-multiple-titles",
    "seo-multiple-canonicals",
    "seo-invalid-canonical",
    "seo-invalid-structured-data",
    "seo-duplicate-static-description",
    "a11y-viewport-zoom",
    "a11y-meta-refresh",
  ]) assert.ok(found.has(expected), `expected ${expected}`);

  const zoom = result.findings.find(({ id }) => id === "a11y-viewport-zoom");
  assert.equal(zoom.standards[0].id, "WCAG-1.4.4");
});

test("website scan validates robots sitemap directives and XML sitemap locations", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>App</title><meta name=\"description\" content=\"App page description\"><link rel=\"canonical\" href=\"https://example.test/\"></head><body><main><h1>App</h1></main></body></html>",
    "public/robots.txt": "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n",
    "public/sitemap.xml": [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<urlset>",
      "<url><loc>/relative</loc></url>",
      "<url><loc>http://example.test/insecure</loc></url>",
      "<url><loc>https://example.test/repeated</loc></url>",
      "<url><loc>https://example.test/repeated</loc></url>",
      "</urlset>",
    ].join(""),
  });

  const result = await runSiteScan({ ...project, options: { includeManualReviews: false } });
  const found = ids(result);
  for (const expected of [
    "crawl-invalid-sitemap-directive",
    "crawl-sitemap-namespace",
    "crawl-invalid-sitemap-location",
    "crawl-insecure-sitemap-location",
    "crawl-duplicate-sitemap-location",
  ]) assert.ok(found.has(expected), `expected ${expected}`);
});

test("website scan detects inaccessible compound widgets and semantic data structures", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>App</title></head><body><main id=\"root\"></main></body></html>",
    "src/pages/Form.tsx": [
      "export function FormPage() { return <main><h1>Checkout</h1>",
      "<dialog open><h2>Confirm order</h2></dialog>",
      "<button><a href=\"/account\">Account</a></button>",
      "<input type=\"image\" src=\"/submit.png\" />",
      "<fieldset><input aria-label=\"One\"/><input aria-label=\"Two\"/></fieldset>",
      "<table><thead><tr><th>Plan</th></tr></thead><tbody><tr><td>Pro</td></tr></tbody></table>",
      "</main>; }",
    ].join("\n"),
  });

  const result = await runSiteScan({ ...project, options: { includeManualReviews: false } });
  const found = ids(result);
  for (const expected of [
    "a11y-dialog-name",
    "a11y-interactive-nesting",
    "a11y-image-input-alt",
    "a11y-fieldset-legend",
    "a11y-table-name",
  ]) assert.ok(found.has(expected), `expected ${expected}`);
  assert.equal(result.findings.find(({ id }) => id === "a11y-dialog-name").standards[0].id, "WCAG-4.1.2");
});

test("website scan accepts valid head, structured data, sitemap, and accessible widget equivalents", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "index.html": [
      "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Home</title>",
      "<meta name=\"description\" content=\"A unique home description\"><link rel=\"canonical\" href=\"https://example.test/\">",
      "<meta property=\"og:title\" content=\"Home\"><meta property=\"og:type\" content=\"website\"><meta property=\"og:image\" content=\"https://example.test/social.png\"><meta property=\"og:url\" content=\"https://example.test/\">",
      "<script type=\"application/ld+json\">{\"@context\":\"https://schema.org\",\"@type\":\"WebSite\",\"name\":\"Example\"}</script>",
      "</head><body><main><h1>Home</h1>",
      "<dialog aria-labelledby=\"confirm-title\"><h2 id=\"confirm-title\">Confirm</h2></dialog>",
      "<a href=\"/account\">Account</a><button type=\"button\">Save</button><input type=\"image\" alt=\"Submit order\" src=\"/submit.png\">",
      "<fieldset><legend>Choose a plan</legend><input aria-label=\"Free\"><input aria-label=\"Pro\"></fieldset>",
      "<table><caption>Plan comparison</caption><tr><th>Plan</th></tr><tr><td>Pro</td></tr></table>",
      "</main></body></html>",
    ].join(""),
    "public/robots.txt": "User-agent: *\nAllow: /\nSitemap: https://example.test/sitemap.xml\n",
    "public/sitemap.xml": "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://example.test/</loc></url></urlset>",
  });

  const result = await runSiteScan({ ...project, options: { includeManualReviews: false } });
  const forbidden = new Set([
    "seo-multiple-titles", "seo-multiple-canonicals", "seo-invalid-canonical", "seo-invalid-structured-data",
    "seo-incomplete-social-metadata", "seo-invalid-social-url",
    "a11y-viewport-zoom", "a11y-meta-refresh", "a11y-dialog-name", "a11y-interactive-nesting",
    "a11y-image-input-alt", "a11y-fieldset-legend", "a11y-table-name", "crawl-invalid-sitemap-directive",
    "crawl-sitemap-namespace", "crawl-invalid-sitemap-location", "crawl-insecure-sitemap-location",
    "crawl-duplicate-sitemap-location", "crawl-empty-sitemap",
  ]);
  assert.deepEqual(result.findings.filter(({ id }) => forbidden.has(id)), []);
});

test("website scan recognizes Remix-style route metadata contracts", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { "@remix-run/react": "latest", react: "latest" } },
    "app/root.tsx": "export default function Root({ children }) { return <html lang=\"en\"><body><main>{children}</main></body></html>; }",
    "app/routes/_index.tsx": [
      "export const meta = () => [",
      "  { title: 'Dashboard' },",
      "  { name: 'description', content: 'Account dashboard' },",
      "  { tagName: 'link', rel: 'canonical', href: 'https://example.test/' },",
      "];",
      "export default function Index() { return <><h1>Dashboard</h1></>; }",
    ].join("\n"),
  });

  const result = await runSiteScan({ ...project, options: { includeManualReviews: false } });
  const missing = result.findings.filter(({ id }) => [
    "seo-missing-title", "seo-missing-description", "seo-missing-canonical",
  ].includes(id));
  assert.deepEqual(missing, []);
});

test("website scan does not treat capitalized framework components as native HTML widgets", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>App</title></head><body><main id=\"root\"></main></body></html>",
    "src/pages/Components.tsx": [
      "export function Components() { return <main><h1>Components</h1>",
      "<Dialog><h2>Library-owned name contract</h2></Dialog>",
      "<Button><Link href=\"/account\">Account</Link></Button>",
      "<Fieldset><Input/><Input/></Fieldset>",
      "<Table><Thead><Th>Plan</Th></Thead></Table>",
      "<Video autoplay />",
      "<script type=\"application/ld+json\">{JSON.stringify(schema)}</script>",
      "</main>; }",
    ].join("\n"),
  });

  const result = await runSiteScan({ ...project, options: { includeManualReviews: false } });
  const nativeOnlyRules = new Set([
    "a11y-dialog-name", "a11y-interactive-nesting", "a11y-fieldset-legend", "a11y-table-name",
    "a11y-audible-autoplay", "a11y-video-captions", "forms-implicit-button-type",
  ]);
  assert.deepEqual(result.findings.filter(({ id }) => nativeOnlyRules.has(id)), []);
  assert.equal(result.findings.some(({ id }) => id === "seo-invalid-structured-data"), false);
  const ledger = new Map(result.metadata.checkLedger.map((check) => [check.id, check]));
  assert.equal(ledger.get("responsive-breakpoints").status, "unknown");
  assert.equal(ledger.get("responsive-breakpoints").executionStatus, "not-evaluated");
  assert.equal(ledger.get("typography-readability").status, "unknown");
});

test("website scan verifies likely delivered asset metadata and reports meaningful transfer budgets", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Assets</title></head><body><main><h1>Assets</h1><img alt=\"Hero\" width=\"1000\" height=\"600\" src=\"/hero.png\"></main></body></html>",
    "public/hero.png": Buffer.alloc(1024 * 1024 + 1),
    "public/legacy.bmp": Buffer.alloc(128),
    "public/fonts/display.woff2": Buffer.alloc(300 * 1024 + 1),
    "public/media/intro.mp4": Buffer.alloc(5 * 1024 * 1024 + 1),
    "src/assets/unreferenced.png": Buffer.alloc(1024 * 1024 + 1),
  });

  const result = await runSiteScan({ ...project, options: { includeManualReviews: false } });
  const found = ids(result);
  for (const expected of [
    "performance-large-image-asset",
    "performance-legacy-image-format",
    "performance-large-font-asset",
    "performance-large-media-asset",
  ]) assert.ok(found.has(expected), `expected ${expected}`);
  assert.equal(result.findings.some(({ file }) => file === "src/assets/unreferenced.png"), false);
  assert.equal(result.metadata.scope.verifiedAssetFiles, 5);
  assert.equal(result.metadata.scope.likelyDeliveredAssetFiles, 4);
  assert.equal(result.filesScanned, result.metadata.scope.readableFiles + 5);
  assert.equal(result.metadata.assetReview.thresholdsBytes.imageReview, 1024 * 1024);
  assert.match(result.metadata.assetReview.method, /binary contents are never loaded/i);
});

test("website scan reports incomplete social cards, unsupported robots noindex, and unnamed custom interactions", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "index.html": [
      "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">",
      "<title>Social</title><meta name=\"description\" content=\"Social page\"><link rel=\"canonical\" href=\"https://example.test/\">",
      "<meta property=\"og:title\" content=\"Social page\"><meta property=\"og:image\" content=\"/preview.png\">",
      "</head><body><main><h1>Social</h1><a onClick=\"openDialog()\">Open</a><svg role=\"img\"><path d=\"M0 0\"></path></svg></main></body></html>",
    ].join(""),
    "public/robots.txt": "User-agent: *\nAllow: /\nNoindex: /private\n",
  });

  const result = await runSiteScan({ ...project, options: { includeManualReviews: false } });
  const found = ids(result);
  for (const expected of [
    "seo-incomplete-social-metadata",
    "seo-invalid-social-url",
    "crawl-unsupported-noindex",
    "a11y-clickable-noncontrol",
    "a11y-svg-image-name",
  ]) assert.ok(found.has(expected), `expected ${expected}`);
  assert.ok(result.findings.find(({ id }) => id === "crawl-unsupported-noindex").references
    .includes("https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag"));
});

test("website asset auditing rejects caller-supplied metadata outside the repository", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>App</title></head><body><main><h1>App</h1></main></body></html>",
    "public/safe.png": Buffer.alloc(32),
  });
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "modular-site-v2-outside-"));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  const absolute = path.join(outside, "huge.png");
  await fs.writeFile(absolute, Buffer.alloc(2 * 1024 * 1024 + 1));
  const legitimate = project.files.find(({ relative }) => relative === "public/safe.png");
  const forged = {
    ...legitimate,
    absolute,
    relative: "public/forged-huge.png",
    name: "forged-huge.png",
    size: 2 * 1024 * 1024 + 1,
  };

  const result = await runSiteScan({
    ...project,
    files: [...project.files, forged],
    options: { includeManualReviews: false },
  });
  assert.equal(result.findings.some(({ file }) => file === forged.relative), false);
  assert.ok(result.metadata.scope.unreadableFiles >= 1);
});
