import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { collectFiles } from "../src/core/files.js";
import { detectWebProject } from "../src/core/project.js";
import { runSecurityScan } from "../src/scanners/security.js";

async function fixture(t, entries) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-security-precision-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const [relative, value] of Object.entries(entries)) {
    const absolute = path.join(root, relative);
    await fs.mkdir(path.dirname(absolute), { recursive: true });
    await fs.writeFile(absolute, typeof value === "string" ? value : JSON.stringify(value, null, 2));
  }
  const inventory = await collectFiles(root);
  const webDetection = await detectWebProject({ root, files: inventory.files });
  return { root, ...inventory, webDetection };
}

async function descriptor(root, relative) {
  const absolute = path.join(root, relative);
  const stat = await fs.stat(absolute);
  return {
    absolute,
    relative: relative.replace(/\\/g, "/"),
    name: path.basename(relative),
    extension: path.extname(relative).toLowerCase(),
    size: stat.size,
    maxFileBytes: 1_500_000,
  };
}

async function scan(project, options = {}) {
  return runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false, ...options },
  });
}

test("collector and direct scanner API exclude generated browser-audit outputs", async (t) => {
  const generated = ["playwright-report/index.html", "test-results/result.json", "blob-report/report.json"];
  const secret = "AKIAABCDEFGHIJKLMNOP";
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    [generated[0]]: `<script>const password = 'a-production-looking-password'; const key = '${secret}'; element.innerHTML = value;</script>`,
    [generated[1]]: `{ "password": "a-production-looking-password", "token": "${secret}" }`,
    [generated[2]]: `{ "token": "${secret}" }`,
  });

  assert.ok(generated.every((relative) => !project.files.some((file) => file.relative === relative)));

  const forcedFiles = await Promise.all(generated.map((relative) => descriptor(project.root, relative)));
  const result = await scan({ ...project, files: [...project.files, ...forcedFiles] });
  assert.ok(result.findings.every((finding) => !generated.includes(finding.file)));
  assert.equal(result.metadata.filesConsidered, project.files.length);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test("high-confidence signatures survive broad-source scanning while generic UI and generated assignments do not", async (t) => {
  const awsKey = "AKIAQRSTUVWXYZABCDEF";
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const realSecret = "real-production-secret-value";
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "README.md": `Emergency token: ${jwt}`,
    "generated/client.js": [`const privateKeyLabel = 'Private key';`, `const password = 'generated-password-value';`, `const key = '${awsKey}';`].join("\n"),
    "fixtures/private-key.pem": "-----BEGIN PRIVATE KEY-----\nnot-real-key-material\n-----END PRIVATE KEY-----\n",
    "src/config.ts": `export const clientSecret = '${realSecret}';`,
    "src/locales/en.json": {
      passwordTitle: "Change your password",
      credentialsDescription: "Use your account credentials",
      secretLabel: "Client secret",
    },
    "src/CanvasDesigner.tsx": "export const mode = background ? 'use-credentials' : 'anonymous';",
    "src/authFailure.ts": "export const recovery = phase === 'session' ? 'retry-session' : 'restart-login';",
  });
  const result = await scan(project);
  const embedded = result.findings.filter((finding) => finding.id === "security.embedded-secrets");

  assert.deepEqual(new Set(embedded.map((finding) => finding.file)), new Set(["README.md", "fixtures/private-key.pem", "generated/client.js", "src/config.ts"]));
  assert.equal(embedded.filter((finding) => finding.file === "generated/client.js").length, 1);
  assert.ok(embedded.some((finding) => finding.file === "src/config.ts" && finding.severity === "high"));
  for (const value of [awsKey, jwt, realSecret]) assert.doesNotMatch(JSON.stringify(result), new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("per-rule caps prefer high-confidence production source over an equally severe documentation signature", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "README.md": "Old example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "src/config.ts": "export const clientSecret = 'real-production-secret-value';",
  });
  const result = await scan(project, { maxFindingsPerRule: 1 });
  const embedded = result.findings.filter((finding) => finding.id === "security.embedded-secrets");

  assert.equal(embedded.length, 1);
  assert.equal(embedded[0].file, "src/config.ts");
  assert.equal(result.metadata.suppressedByRule["embedded-secrets"], 1);
  assert.equal(result.metadata.suppressedSeverityByRule["embedded-secrets"].high, 1);
});

test("development-only authentication mocks are excluded without hiding production storage and cookies", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/AuthProvider.tsx": [
      "const mockAuth = new URLSearchParams(location.search).get('mock_auth') === 'true';",
      "if (import.meta.env.DEV && mockAuth) {",
      "  localStorage.setItem('mock_auth', 'true');",
      "  document.cookie = 'sample_session=dev_key; path=/';",
      "}",
      "localStorage.setItem('accessToken', liveToken);",
      "document.cookie = 'session=live_session; path=/';",
    ].join("\r\n"),
  });
  const result = await scan(project);

  const storage = result.findings.filter((finding) => finding.id === "security.browser-storage");
  const cookies = result.findings.filter((finding) => finding.id === "security.cookie-flags");
  assert.deepEqual(storage.map((finding) => finding.line), [6]);
  assert.deepEqual(cookies.map((finding) => finding.line), [7]);
});

test("WebSocket handlers and noreferrer links are not confused with unsafe cross-window APIs", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/App.tsx": [
      "ws.onmessage = (event) => consume(event.data);",
      "window.onmessage = (event) => consume(event.data);",
      "export const Safe = () => <a href='https://example.com' target='_blank' rel='noreferrer'>Safe</a>;",
      "export const Unsafe = () => <a href='https://example.com' target='_blank'>Unsafe</a>;",
    ].join("\n"),
  });
  const result = await scan(project);

  const messages = result.findings.filter((finding) => finding.id === "security.cross-window-messaging");
  const links = result.findings.filter((finding) => finding.id === "security.external-navigation");
  assert.deepEqual(messages.map((finding) => finding.line), [2]);
  assert.deepEqual(links.map((finding) => finding.line), [4]);
});

test("Docker headers, exact XML namespace values, internal proxies, and CSP directives keep their deployment context", async (t) => {
  const dockerfile = [
    "FROM nginx:alpine",
    "RUN printf 'config' > /tmp/config",
    "add_header X-Content-Type-Options 'nosniff' always;",
    "add_header X-Frame-Options 'DENY' always;",
    "add_header Referrer-Policy 'strict-origin' always;",
    "add_header Permissions-Policy 'camera=()' always;",
    "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'\" always;",
    "location /api { proxy_pass http://bot:3001; }",
  ].join("\n");
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    Dockerfile: dockerfile,
    "headers.js": "export const csp = \"Content-Security-Policy: script-src 'self' 'unsafe-inline'; object-src 'none'\";",
    "scripts/generate-seo-assets.mjs": "export const sitemap = `<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"></urlset>`;",
    "src/base.css": "select { background: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3C/svg%3E\"); }",
    "src/feed.ts": 'export const feed = `<feed xmlns="http://www.w3.org/2005/Atom"><link href="http://external.example/feed" /></feed>`;',
  });
  const result = await scan(project);
  const transport = result.findings.filter((finding) => finding.id === "security.insecure-transport");
  const csp = result.findings.filter((finding) => finding.id === "security.security-headers" && /permits/i.test(finding.title));

  assert.equal(transport.length, 2);
  const proxy = transport.find((finding) => finding.file === "Dockerfile");
  assert.equal(proxy?.severity, "low");
  assert.equal(proxy?.manual, true);
  assert.match(proxy?.title ?? "", /internal reverse proxy/i);
  assert.equal(transport.find((finding) => finding.file === "src/feed.ts")?.severity, "medium");
  assert.equal(result.findings.some((finding) => finding.id === "security.security-headers" && /incomplete/i.test(finding.title)), false);
  assert.equal(csp.length, 2);
  const styleInline = csp.find((finding) => /style-src/i.test(finding.evidence));
  assert.equal(styleInline?.severity, "low");
  assert.match(styleInline?.recommendation ?? "", /inline CSS|style nonces/i);
  assert.equal(csp.find((finding) => /script-src/i.test(finding.evidence))?.severity, "high");
});

test("security header remediation points at the real monorepo framework config", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, workspaces: ["apps/site"] },
    "apps/site/package.json": {
      private: true,
      dependencies: { next: "1.0.0", react: "1.0.0", "react-dom": "1.0.0" },
    },
    "apps/site/next.config.mjs": "export default {};",
    "apps/site/app/page.tsx": "export default function Page() { return <main><h1>Site</h1></main>; }",
  });
  const result = await scan(project);
  const headers = result.findings.find((finding) =>
    finding.id === "security.security-headers" && /incomplete/i.test(finding.title));

  assert.ok(headers);
  assert.ok(headers.suggestedFiles.includes("apps/site/next.config.mjs"));
  assert.ok(!headers.suggestedFiles.includes("next.config.mjs"));
});

test("DOM sanitizer suppression requires exact expressions and value-level symbol provenance", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0", dompurify: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/lib/docs/loader.ts": [
      "import DOMPurify from 'dompurify';",
      "export function sanitizeDocHtml(rawHtml: string) { return DOMPurify.sanitize(rawHtml); }",
      "export async function loadDocArticle(rawHtml: string) {",
      "  const sanitizedHtml = sanitizeDocHtml(rawHtml);",
      "  return { contentHtml: sanitizedHtml };",
      "}",
      "export function conditionallyLoadDoc(rawHtml: string, trusted: boolean) {",
      "  const conditionalHtml = trusted ? DOMPurify.sanitize(rawHtml) : rawHtml;",
      "  return { contentHtml: conditionalHtml };",
      "}",
    ].join("\n"),
    "src/routes/docs/DocsArticle.tsx": [
      "import { loadDocArticle } from '~/lib/docs/loader';",
      "export async function DocsArticle(rawHtml) {",
      "  const article = await loadDocArticle(rawHtml);",
      "  return <div dangerouslySetInnerHTML={{ __html: article.contentHtml }} />;",
      "}",
    ].join("\n"),
    "src/routes/docs/UnrelatedArticle.tsx": [
      "import { loadDocArticle } from '~/lib/docs/loader';",
      "void loadDocArticle('safe but unrelated');",
      "export const UnrelatedArticle = ({ rawHtml }) => {",
      "  const unrelated = { contentHtml: rawHtml };",
      "  return <div dangerouslySetInnerHTML={{ __html: unrelated.contentHtml }} />;",
      "};",
    ].join("\n"),
    "src/routes/docs/ConditionalArticle.tsx": [
      "import { conditionallyLoadDoc } from '~/lib/docs/loader';",
      "export const ConditionalArticle = ({ rawHtml }) => {",
      "  const article = conditionallyLoadDoc(rawHtml, false);",
      "  return <div dangerouslySetInnerHTML={{ __html: article.contentHtml }} />;",
      "};",
    ].join("\n"),
    "src/routes/Unsafe.tsx": "export const Unsafe = ({ rawHtml }) => <div dangerouslySetInnerHTML={{ __html: rawHtml }} />;",
    "src/lib/unsafeSanitizer.ts": [
      "export function sanitizePreviewHtml(rawHtml: string) {",
      "  // TODO: return DOMPurify.sanitize(rawHtml) after reviewing the policy.",
      "  return rawHtml;",
      "}",
      "export function loadPreview(rawHtml: string) {",
      "  const cleanedHtml = sanitizePreviewHtml(rawHtml);",
      "  return { previewHtml: cleanedHtml };",
      "}",
    ].join("\n"),
    "src/routes/UnsafePreview.tsx": [
      "import { loadPreview } from '../lib/unsafeSanitizer';",
      "export const UnsafePreview = ({ preview }) => <div dangerouslySetInnerHTML={{ __html: preview.previewHtml }} />;",
    ].join("\n"),
    "src/routes/FakePurifier.tsx": [
      "const DOMPurify = { sanitize: (value) => value };",
      "export const FakePurifier = ({ rawHtml }) => {",
      "  const cleaned = DOMPurify.sanitize(rawHtml);",
      "  return <div dangerouslySetInnerHTML={{ __html: cleaned }} />;",
      "};",
    ].join("\n"),
  });
  const result = await scan(project);
  const sinks = result.findings.filter((finding) => finding.id === "security.dom-xss");

  assert.equal(sinks.some((finding) => finding.file === "src/routes/docs/DocsArticle.tsx"), false);
  assert.deepEqual(sinks.map((finding) => finding.file), [
    "src/routes/FakePurifier.tsx",
    "src/routes/Unsafe.tsx",
    "src/routes/UnsafePreview.tsx",
    "src/routes/docs/ConditionalArticle.tsx",
    "src/routes/docs/UnrelatedArticle.tsx",
  ]);
  assert.ok(sinks.every((finding) => finding.manual === true));
  assert.ok(sinks.every((finding) => finding.confidence === "medium"));
  assert.ok(sinks.every((finding) => /data-flow review/i.test(finding.title)));
});

test("DOM sanitizer variables remain lexical and relative imports resolve to the exact module", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0", dompurify: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/routes/Scoped.tsx": [
      "import DOMPurify from 'dompurify';",
      "export function SafeScope(rawHtml) {",
      "  const cleaned = DOMPurify.sanitize(rawHtml);",
      "  return <div dangerouslySetInnerHTML={{ __html: cleaned }} />;",
      "}",
      "export function UnsafeScope(cleaned) {",
      "  return <div dangerouslySetInnerHTML={{ __html: cleaned }} />;",
      "}",
    ].join("\n"),
    "src/safe/loader.ts": [
      "import DOMPurify from 'dompurify';",
      "export function loadArticle(rawHtml) {",
      "  const cleaned = DOMPurify.sanitize(rawHtml);",
      "  return { contentHtml: cleaned };",
      "}",
    ].join("\n"),
    "src/safe/View.tsx": [
      "import { loadArticle } from './loader';",
      "export const SafeView = ({ rawHtml }) => { const article = loadArticle(rawHtml); return <div dangerouslySetInnerHTML={{ __html: article.contentHtml }} />; };",
    ].join("\n"),
    "src/unsafe/loader.ts": "export function loadArticle(rawHtml) { return { contentHtml: rawHtml }; }",
    "src/unsafe/View.tsx": [
      "import { loadArticle } from './loader';",
      "export const UnsafeView = ({ rawHtml }) => { const article = loadArticle(rawHtml); return <div dangerouslySetInnerHTML={{ __html: article.contentHtml }} />; };",
    ].join("\n"),
  });
  const result = await scan(project);
  const sinks = result.findings.filter((finding) => finding.id === "security.dom-xss");

  assert.equal(sinks.filter((finding) => finding.file === "src/routes/Scoped.tsx").length, 1);
  assert.equal(sinks.find((finding) => finding.file === "src/routes/Scoped.tsx")?.line, 7);
  assert.equal(sinks.some((finding) => finding.file === "src/safe/View.tsx"), false);
  assert.equal(sinks.some((finding) => finding.file === "src/unsafe/View.tsx"), true);
});

test("security metadata exposes a backward-compatible rule-family execution ledger", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/App.tsx": "export const App = ({ html }) => <main dangerouslySetInnerHTML={{ __html: html }} />;",
  });
  const result = await scan(project);
  const dom = result.metadata.checkLedger.find((check) => check.id === "dom-xss");
  const advisory = result.metadata.checkLedger.find((check) => check.id === "dependency-advisories");
  const ci = result.metadata.checkLedger.find((check) => check.id === "ci-workflow");

  assert.equal(result.checks, 32);
  assert.equal(result.metadata.checks.length, result.checks);
  assert.equal(result.metadata.checkLedger.length, 32);
  assert.deepEqual(
    { kind: dom.kind, status: dom.status, executionStatus: dom.executionStatus, applicability: dom.applicability, enabled: dom.enabled },
    { kind: "automated-static", status: "completed", executionStatus: "completed", applicability: "applicable", enabled: true },
  );
  assert.equal(dom.observedFindings, 1);
  assert.equal(dom.retainedFindings, 1);
  assert.equal(advisory.kind, "external-package-manager");
  assert.equal(advisory.status, "skipped");
  assert.equal(advisory.applicability, "applicable");
  assert.equal(advisory.enabled, false);
  assert.deepEqual(
    { status: ci.status, executionStatus: ci.executionStatus, applicability: ci.applicability, enabled: ci.enabled },
    { status: "not-applicable", executionStatus: "not-applicable", applicability: "not-applicable", enabled: false },
  );
  assert.equal(result.metadata.checks.find((check) => check.id === "dependency-advisories")?.status, "skipped");
  assert.ok(result.metadata.checks
    .filter((check) => check.kind === "automated-static")
    .every((check) => (
      check.status === "completed" && check.executionStatus === "completed" && check.applicability === "applicable"
    ) || (
      check.status === "not-applicable" && check.executionStatus === "not-applicable" && check.applicability === "not-applicable"
    )));
});

test("environment-backed secret fallbacks are detected without exposing their literal values", async (t) => {
  const secretValues = [
    "orchid-river-production-material",
    "cobalt-harbor-token-material",
    "violet-forest-session-material",
    "amber-meadow-development-material",
  ];
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/config.ts": [
      `const SESSION_SECRET = process.env.SESSION_SECRET || '${secretValues[0]}';`,
      `const API_TOKEN = process.env.API_TOKEN ?? '${secretValues[1]}';`,
      `const JWT_SECRET = process.env.JWT_SECRET ? process.env.JWT_SECRET : '${secretValues[2]}';`,
      `const DEV_SECRET = process.env.NODE_ENV === 'production' ? process.env.DEV_SECRET : '${secretValues[3]}';`,
    ].join("\n"),
  });
  const result = await scan(project);
  const embedded = result.findings.filter((finding) => finding.id === "security.embedded-secrets" && finding.file === "src/config.ts");

  assert.deepEqual(embedded.map((finding) => finding.line).sort((left, right) => left - right), [1, 2, 3]);
  assert.ok(embedded.every((finding) => /fallback/i.test(finding.title)));
  for (const secret of secretValues) assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test("credential fixtures and local environment values retain review context without unconditional rotation advice", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    ".gitignore": ".env\n",
    ".env": "SESSION_SECRET=a-local-workspace-value-that-needs-review\n",
    ".env.example": [
      "YOUTUBE_API_KEY=",
      "TWITCH_CLIENT_SECRET=",
      "NEXT_SETTING=enabled",
      "AGENT_API_KEY=",
    ].join("\n"),
    "src/diagnosticSanitizer.test.ts": [
      "const samples = ['xoxb-1234567890', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'];",
      "expect(redact(samples)).not.toContain(samples[0]);",
    ].join("\n"),
    "src/config.ts": [
      "const DEVELOPMENT_SESSION_SECRET = 'default_session_secret_must_be_long_for_security';",
      "const schema = { SESSION_SECRET: source.default(DEVELOPMENT_SESSION_SECRET) };",
      "if (env.NODE_ENV !== 'production') return schema;",
      "if (env.SESSION_SECRET === DEVELOPMENT_SESSION_SECRET) { ctx.addIssue({ message: 'configure production secret' }); }",
      "export const clientSecret = 'a-real-looking-production-value';",
    ].join("\n"),
    "src/redaction.ts": [
      "const PRIVATE_FIELDS = new Set(['authorization', 'authentication', 'cookie']);",
      "export const LOG_REDACTION_PATHS = ['headers.authorization', 'headers.cookie', 'request.headers.authorization'];",
    ].join("\n"),
  });
  const result = await scan(project);
  const embedded = result.findings.filter((finding) => finding.id === "security.embedded-secrets");

  assert.equal(result.findings.some((finding) => finding.id === "security.hardcoded-auth" && finding.file === "src/redaction.ts"), false);
  assert.equal(embedded.some((finding) => finding.file === ".env.example"), false);
  assert.equal(embedded.some((finding) => /DEVELOPMENT_SESSION_SECRET/.test(finding.evidence)), false);
  assert.ok(embedded.some((finding) => finding.file === "src/config.ts" && finding.severity === "high"));

  const localEnvironment = embedded.find((finding) => finding.file === ".env");
  assert.deepEqual(
    { severity: localEnvironment?.severity, confidence: localEnvironment?.confidence, manual: localEnvironment?.manual },
    { severity: "medium", confidence: "medium", manual: true },
  );
  assert.match(localEnvironment?.description ?? "", /does not prove/i);
  assert.match(localEnvironment?.recommendation ?? "", /rotate only if exposure is confirmed/i);

  const fixtures = embedded.filter((finding) => finding.file === "src/diagnosticSanitizer.test.ts");
  assert.equal(fixtures.length, 2);
  assert.ok(fixtures.every((finding) => finding.manual && finding.confidence === "medium"));
  assert.ok(fixtures.every((finding) => finding.severity !== "critical" && /only if.*confirmed|if it is confirmed/i.test(finding.recommendation)));
  assert.doesNotMatch(JSON.stringify(result), /assume exposed|rotate immediately/i);
});

test("environment hygiene follows applicable nested gitignore rules and negations", async (t) => {
  await t.test("nested workspace ignore applies", async (subtest) => {
    const project = await fixture(subtest, {
      "package.json": { private: true, workspaces: ["apps/web"], dependencies: { react: "1.0.0" } },
      "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
      "apps/web/.gitignore": ".env*\n!.env.example\n",
      "apps/web/.env.local": "SESSION_SECRET=local-workspace-value\n",
      "apps/web/package.json": { private: true, dependencies: { react: "1.0.0" } },
      "apps/web/src/App.tsx": "export const App = () => <main>App</main>;",
    });
    const result = await scan(project);
    assert.equal(result.findings.some(({ id }) => id === "security.environment-hygiene"), false);
  });

  await t.test("nearer negation overrides a root ignore", async (subtest) => {
    const project = await fixture(subtest, {
      "package.json": { private: true, workspaces: ["apps/web"], dependencies: { react: "1.0.0" } },
      "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
      ".gitignore": ".env*\n",
      "apps/web/.gitignore": "!.env.local\n",
      "apps/web/.env.local": "SESSION_SECRET=local-workspace-value\n",
      "apps/web/package.json": { private: true, dependencies: { react: "1.0.0" } },
      "apps/web/src/App.tsx": "export const App = () => <main>App</main>;",
    });
    const result = await scan(project);
    const finding = result.findings.find(({ id }) => id === "security.environment-hygiene");
    assert.equal(finding?.file, "apps/web/.env.local");
    assert.match(finding?.evidence ?? "", /not ignored/i);
  });
});

test("authorization detection requires an actual header assignment and preserves real literals", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/redaction.ts": [
      "const labels = ['authorization', 'authentication', 'headers.authorization', 'headers.cookie'];",
      "const copy = { oauth: 'an app authorization', discovery: 'Server Discovery' };",
      "const headers = { Authorization: 'Bearer real-production-access-material' };",
    ].join("\n"),
  });
  const result = await scan(project);
  const findings = result.findings.filter((finding) => finding.id === "security.hardcoded-auth");

  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 3);
  assert.match(findings[0].recommendation, /if it was exposed/i);
});

test("server cookie aliases require effective cookie flags and preserve protected cookies", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "server.ts": [
      "const isProduction = config.nodeEnv === 'production';",
      "const secure = config.nodeEnv === 'production';",
      "reply.setCookie('sample_session', encryptedSession, { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/' });",
      "reply.setCookie('sample_refresh', encryptedRefresh, { httpOnly: true, secure, sameSite: 'strict', path: '/' });",
      "reply.setCookie('sample_csrf', csrfToken, { httpOnly: false, secure: isProduction, sameSite: 'lax', path: '/' });",
      "reply.setCookie('unsafe_session', sessionToken, { httpOnly: true, sameSite: 'lax', path: '/' });",
      "ctx.cookies.set('protected_session', sessionToken, { httpOnly: true, secure: true, sameSite: 'strict' });",
      "response.cookie('protected_auth', authToken, { httpOnly: true, secure: true, sameSite: 'lax' });",
      "ctx.cookies.set('false_session', sessionToken, { httpOnly: true, secure: true, sameSite: false });",
      "response.cookie('null_auth', authToken, { httpOnly: true, secure: true, sameSite: null });",
      "ctx.cookies.set('undefined_token', authToken, { httpOnly: true, secure: true, sameSite: undefined });",
    ].join("\n"),
  });
  const result = await scan(project);
  const cookies = result.findings.filter((finding) => finding.id === "security.cookie-flags");

  assert.deepEqual(cookies.map((finding) => finding.line), [6, 9, 10, 11]);
  assert.match(cookies.find((finding) => finding.line === 6)?.description ?? "", /Secure/);
  assert.ok(cookies.filter((finding) => finding.line >= 9).every((finding) => /SameSite/.test(finding.description)));
});

test("fixed dynamic-import bridges retain a low CSP/runtime-hardening signal while data-driven constructors remain high", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/safe-loader.ts": [
      "const importPackage = new Function('specifier', 'return import(specifier)');",
      "export const load = () => importPackage('file-type');",
    ].join("\n"),
    "src/unsafe-loader.ts": [
      "const importAnything = new Function('specifier', 'return import(specifier)');",
      "export const load = (specifier) => importAnything(specifier);",
      "export const execute = (body) => new Function(body)();",
    ].join("\n"),
  });
  const result = await scan(project);
  const dynamic = result.findings.filter((finding) => finding.id === "security.dynamic-code");

  const bridge = dynamic.find((finding) => finding.file === "src/safe-loader.ts");
  assert.deepEqual({ severity: bridge?.severity, confidence: bridge?.confidence, manual: bridge?.manual }, { severity: "low", confidence: "medium", manual: true });
  assert.match(`${bridge?.description} ${bridge?.recommendation}`, /CSP|code-generation|interop/i);
  assert.equal(dynamic.filter((finding) => finding.file === "src/unsafe-loader.ts").length, 2);
  assert.ok(dynamic.filter((finding) => finding.file === "src/unsafe-loader.ts").every((finding) => finding.severity === "high"));
});

test("cache fingerprints are calibrated separately from password hashing", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/moderation/cache.ts": [
      "import { createHash } from 'node:crypto';",
      "const contentHash = (content) => createHash('md5').update(content).digest('hex').slice(0, 16);",
      "export const lookup = (content) => cacheGet(`moderation:${contentHash(content)}`);",
    ].join("\n"),
    "src/passwords.ts": [
      "import { createHash } from 'node:crypto';",
      "export const passwordDigest = (password) => createHash('sha1').update(password).digest('hex');",
    ].join("\n"),
  });
  const result = await scan(project);
  const hashes = result.findings.filter((finding) => finding.id === "security.weak-cryptography");
  const cache = hashes.find((finding) => finding.file === "src/moderation/cache.ts");
  const password = hashes.find((finding) => finding.file === "src/passwords.ts");

  assert.deepEqual({ severity: cache?.severity, confidence: cache?.confidence, manual: cache?.manual }, { severity: "low", confidence: "medium", manual: true });
  assert.match(cache?.title ?? "", /cache or deduplication/i);
  assert.deepEqual({ severity: password?.severity, confidence: password?.confidence, manual: password?.manual }, { severity: "medium", confidence: "high", manual: false });
});

test("URL parsing and development allowlists are not transport endpoints", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/origins.ts": [
      "const parsed = new URL(request.url, `http://${request.headers.host || 'localhost'}`);",
      "const canonical = new URL(`http://${host}`).hostname;",
      "const relative = new URL('/asset', 'http://parser-base.example').pathname;",
      "const parserOnly = new URL(`http://${candidateHost}`);",
      "const normalizedHost = parserOnly.hostname;",
      "fetch(new URL('http://external-fetch.example/data'));",
      "fetch(new URL('/api', 'http://fetch-base.example'));",
      "fetch(new URL('http://fetch-origin.example').origin);",
      "const assignedEndpoint = new URL('http://assigned-fetch.example');",
      "fetch(assignedEndpoint);",
      "if (input.nodeEnv === 'development' || input.nodeEnv === 'test') {",
      "  origins.add('http://localhost:*');",
      "  origins.add('http://127.0.0.1:*');",
      "}",
      "export const endpoint = 'http://api.example.com/data';",
    ].join("\n"),
    "docker-compose.yml": "services:\n  worker:\n    environment:\n      - MAIN_BOT_HEALTH_URL=http://bot:3001/api/v1/readyz\n",
  });
  const result = await scan(project);
  const transport = result.findings.filter((finding) => finding.id === "security.insecure-transport");

  assert.equal(transport.length, 6);
  assert.deepEqual(
    transport.filter((finding) => finding.file === "src/origins.ts").map((finding) => finding.line).sort((left, right) => left - right),
    [6, 7, 8, 9, 15],
  );
  assert.equal(transport.some((finding) => finding.file === "src/origins.ts" && finding.line === 4), false);
  const container = transport.find((finding) => finding.file === "docker-compose.yml");
  assert.deepEqual({ severity: container?.severity, confidence: container?.confidence, manual: container?.manual }, { severity: "low", confidence: "medium", manual: true });
  assert.match(container?.title ?? "", /container healthcheck/i);
});

test("monorepo sanitizer and downstream link contracts require real import and call provenance", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, workspaces: ["apps/*"], dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "apps/web/package.json": { private: true, dependencies: { react: "1.0.0", dompurify: "1.0.0" } },
    "apps/web/src/lib/docs/loader.ts": [
      "import DOMPurify from 'dompurify';",
      "export function sanitizeDocHtml(rawHtml) { return DOMPurify.sanitize(rawHtml); }",
      "export function loadDoc(rawHtml) { const clean = sanitizeDocHtml(rawHtml); return { contentHtml: clean }; }",
    ].join("\n"),
    "apps/web/src/routes/docs/article.tsx": [
      "import { loadDoc } from '~/lib/docs/loader';",
      "export const Article = ({ rawHtml }) => { const article = loadDoc(rawHtml); return <main dangerouslySetInnerHTML={{ __html: article.contentHtml }} />; };",
    ].join("\n"),
    "src/services/tickets/transcript.ts": [
      "const TRANSCRIPT_DIR = path.join(process.cwd(), 'transcripts');",
      "let html = `<a href=\"${attachment.url}\" target=\"_blank\">file</a>`;",
      "const fileName = `transcript-${ticketId}.html`;",
      "const filePath = path.join(TRANSCRIPT_DIR, fileName);",
      "writeFile(filePath, html);",
      "export const UnsafePanel = ({ url }) => <a href={url} target=\"_blank\">independent</a>;",
    ].join("\n"),
    "src/api/routes/transcripts.ts": [
      "import sanitizeHtml from 'sanitize-html';",
      "const options = { allowedAttributes: { a: ['href', 'target', 'rel'] }, transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) } };",
      "export function sanitizeTranscriptHtml(html) { const sanitized = sanitizeHtml(html, options); return sanitized; }",
      "fastify.get('/transcripts/:fileName', async (request, reply) => {",
      "  const transcriptsBaseDir = path.resolve(process.cwd(), 'transcripts');",
      "  const filePath = path.resolve(transcriptsBaseDir, request.params.fileName);",
      "  let content = fs.readFileSync(filePath, 'utf8');",
      "  content = sanitizeTranscriptHtml(content);",
      "  return reply.send(content);",
      "});",
    ].join("\n"),
    "src/api/routes/exports.ts": [
      "const sanitizeHtml = { simpleTransform: () => (frame) => frame };",
      "const options = { transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) } };",
    ].join("\n"),
    "src/services/exports/transcript.ts": [
      "let html = `<a href=\"${attachment.url}\" target=\"_blank\">forged</a>`;",
      "writeFile(filePath, html);",
    ].join("\n"),
    "src/api/routes/raw.ts": [
      "import sanitizeHtml from 'sanitize-html';",
      "const options = { allowedAttributes: { a: ['href', 'target', 'rel'] }, transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) } };",
      "function sanitizeRawHtml(content) { sanitizeHtml(content, options); return content; }",
      "fastify.get('/raw/:fileName', async (request, reply) => {",
      "  const base = path.resolve(process.cwd(), 'raw-files');",
      "  const filePath = path.resolve(base, request.params.fileName);",
      "  let content = fs.readFileSync(filePath, 'utf8');",
      "  content = sanitizeRawHtml(content);",
      "  return reply.send(content);",
      "});",
    ].join("\n"),
    "src/services/raw/producer.ts": [
      "const BASE = path.join(process.cwd(), 'raw-files');",
      "let html = `<a href=\"${url}\" target=\"_blank\">raw</a>`;",
      "const fileName = `raw-${id}.html`;",
      "const filePath = path.join(BASE, fileName);",
      "writeFile(filePath, html);",
    ].join("\n"),
    "src/api/routes/split.ts": [
      "import sanitizeHtml from 'sanitize-html';",
      "const options = { allowedAttributes: { a: ['href', 'target', 'rel'] }, transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) } };",
      "const sanitizeSplitHtml = (content) => sanitizeHtml(content, options);",
      "fastify.get('/split/:fileName', async (request, reply) => {",
      "  const base = path.resolve(process.cwd(), 'split-files');",
      "  const filePath = path.resolve(base, request.params.fileName);",
      "  let content = fs.readFileSync(filePath, 'utf8');",
      "  queueMicrotask(() => { content = sanitizeSplitHtml(content); });",
      "  return reply.send(content);",
      "});",
    ].join("\n"),
    "src/services/split/producer.ts": [
      "const BASE = path.join(process.cwd(), 'split-files');",
      "let html = `<a href=\"${url}\" target=\"_blank\">split</a>`;",
      "const fileName = `split-${id}.html`;",
      "const filePath = path.join(BASE, fileName);",
      "writeFile(filePath, html);",
    ].join("\n"),
    "src/api/routes/missing-rel.ts": [
      "import sanitizeHtml from 'sanitize-html';",
      "const options = { allowedAttributes: { a: ['href', 'target'] }, transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) } };",
      "const sanitizeMissingRelHtml = (content) => sanitizeHtml(content, options);",
      "fastify.get('/missing-rel/:fileName', async (request, reply) => {",
      "  const base = path.resolve(process.cwd(), 'missing-rel-files');",
      "  const filePath = path.resolve(base, request.params.fileName);",
      "  let content = fs.readFileSync(filePath, 'utf8');",
      "  content = sanitizeMissingRelHtml(content);",
      "  return reply.send(content);",
      "});",
    ].join("\n"),
    "src/services/missing-rel/producer.ts": [
      "const BASE = path.join(process.cwd(), 'missing-rel-files');",
      "let html = `<a href=\"${url}\" target=\"_blank\">missing rel</a>`;",
      "const fileName = `missing-rel-${id}.html`;",
      "const filePath = path.join(BASE, fileName);",
      "writeFile(filePath, html);",
    ].join("\n"),
    "src/api/routes/misplaced-transform.ts": [
      "import sanitizeHtml from 'sanitize-html';",
      "const options = { allowedAttributes: { a: ['href', 'target', 'rel'] }, transformTags: { a: identity }, unrelated: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) };",
      "const sanitizeMisplacedHtml = (content) => sanitizeHtml(content, options);",
      "fastify.get('/misplaced/:fileName', async (request, reply) => {",
      "  const base = path.resolve(process.cwd(), 'misplaced-files');",
      "  const filePath = path.resolve(base, request.params.fileName);",
      "  let content = fs.readFileSync(filePath, 'utf8');",
      "  content = sanitizeMisplacedHtml(content);",
      "  return reply.send(content);",
      "});",
    ].join("\n"),
    "src/services/misplaced/producer.ts": [
      "const BASE = path.join(process.cwd(), 'misplaced-files');",
      "let html = `<a href=\"${url}\" target=\"_blank\">misplaced transform</a>`;",
      "const fileName = `misplaced-${id}.html`;",
      "const filePath = path.join(BASE, fileName);",
      "writeFile(filePath, html);",
    ].join("\n"),
    "src/api/routes/no-send.ts": [
      "import sanitizeHtml from 'sanitize-html';",
      "const options = { allowedAttributes: { a: ['href', 'target', 'rel'] }, transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) } };",
      "const sanitizeNoSendHtml = (content) => sanitizeHtml(content, options);",
      "fastify.get('/no-send/:fileName', async (request, reply) => {",
      "  const base = path.resolve(process.cwd(), 'no-send-files');",
      "  const filePath = path.resolve(base, request.params.fileName);",
      "  let content = fs.readFileSync(filePath, 'utf8');",
      "  content = sanitizeNoSendHtml(content);",
      "  return reply.send('different content');",
      "});",
    ].join("\n"),
    "src/services/no-send/producer.ts": [
      "const BASE = path.join(process.cwd(), 'no-send-files');",
      "let html = `<a href=\"${url}\" target=\"_blank\">not sent</a>`;",
      "const fileName = `no-send-${id}.html`;",
      "const filePath = path.join(BASE, fileName);",
      "writeFile(filePath, html);",
    ].join("\n"),
    "src/services/tickets/archive.ts": [
      "const ARCHIVE_DIR = path.join(process.cwd(), 'archives');",
      "let html = `<a href=\"${url}\" target=\"_blank\">wrong storage</a>`;",
      "const fileName = `transcript-${id}.html`;",
      "const filePath = path.join(ARCHIVE_DIR, fileName);",
      "writeFile(filePath, html);",
    ].join("\n"),
    "src/unsafe.ts": "export const markup = `<a href=\"${url}\" target=\"_blank\">unsafe</a>`;",
  });
  const result = await scan(project);
  const dom = result.findings.filter((finding) => finding.id === "security.dom-xss");
  const links = result.findings.filter((finding) => finding.id === "security.external-navigation");

  assert.equal(dom.some((finding) => finding.file === "apps/web/src/routes/docs/article.tsx"), false);
  assert.equal(links.filter((finding) => finding.file === "src/services/tickets/transcript.ts").length, 1);
  assert.deepEqual(links.map((finding) => finding.file), [
    "src/services/exports/transcript.ts",
    "src/services/misplaced/producer.ts",
    "src/services/missing-rel/producer.ts",
    "src/services/no-send/producer.ts",
    "src/services/raw/producer.ts",
    "src/services/split/producer.ts",
    "src/services/tickets/archive.ts",
    "src/services/tickets/transcript.ts",
    "src/unsafe.ts",
  ]);
});

test("identical repeated CSP policies produce one weakness while distinct policies remain", async (t) => {
  const repeated = "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'";
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "headers.js": [
      `export const root = ${JSON.stringify(repeated)};`,
      `export const assets = ${JSON.stringify(repeated)};`,
      "export const admin = \"Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'\";",
    ].join("\n"),
  });
  const result = await scan(project);
  const weaknesses = result.findings.filter((finding) => finding.id === "security.security-headers" && /permits/i.test(finding.title));

  assert.equal(weaknesses.filter((finding) => /style-src/i.test(finding.evidence)).length, 1);
  assert.equal(weaknesses.filter((finding) => /unsafe-eval/i.test(finding.evidence)).length, 1);
});

test("server data-flow rules distinguish dangerous sinks from bounded alternatives", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { express: "1.0.0", react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/server/api.ts": [
      "import { exec, spawn } from 'node:child_process';",
      "import { readFile } from 'node:fs';",
      "export async function handler(request, response) {",
      "  const target = request.query.target;",
      "  const fileName = request.params.file;",
      "  const command = request.body.command;",
      "  const userId = request.query.userId;",
      "  await fetch(target);",
      "  readFile(path.join(UPLOADS, fileName), () => {});",
      "  exec(`convert ${command}`);",
      "  await db.query(`SELECT * FROM users WHERE id = '${userId}'`);",
      "  const safeName = path.basename(fileName);",
      "  readFile(path.join(UPLOADS, safeName), () => {});",
      "  const parsed = new URL(target);",
      "  if (!allowedOrigins.has(parsed.origin)) throw new Error('blocked');",
      "  await fetch(parsed);",
      "  await fetch(`https://api.example/search?q=${encodeURIComponent(userId)}`);",
      "  await db.query('SELECT * FROM users WHERE id = $1', [userId]);",
      "  await db.query({ text: 'SELECT * FROM users WHERE id = $1', values: [userId] });",
      "  spawn('convert', [command], { shell: false });",
      "  response.send('ok');",
      "}",
    ].join("\n"),
  });
  const result = await scan(project);
  const dataFlows = result.findings.filter((finding) => finding.tags.includes("data-flow"));

  assert.deepEqual(dataFlows.map(({ id }) => id).sort(), [
    "security.server-command-injection",
    "security.server-path-traversal",
    "security.server-sql-injection",
    "security.server-ssrf",
  ]);
  assert.ok(dataFlows.every((finding) => finding.manual));
  assert.ok(dataFlows.every((finding) => /Data flow:/.test(finding.evidence)));
  assert.ok(dataFlows.every((finding) => finding.standards.some(({ id }) => /^CWE-/.test(id))));
});

test("GitHub workflow rules expose shell injection, broad permissions, and mutable actions", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    ".github/workflows/review.yml": [
      "name: review",
      "on: pull_request_target",
      "permissions: write-all",
      "jobs:",
      "  inspect:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - run: |",
      "          echo \"${{ github.event.pull_request.title }}\"",
      "      - uses: owner/pinned@0123456789abcdef0123456789abcdef01234567",
    ].join("\r\n"),
  });
  const result = await scan(project);
  const workflow = result.findings.filter(({ id }) => id === "security.ci-workflow");

  assert.equal(workflow.length, 3);
  assert.deepEqual(workflow.map(({ severity }) => severity).sort(), ["critical", "high", "low"]);
  assert.equal(workflow.find(({ severity }) => severity === "critical")?.line, 10);
  assert.equal(workflow.some(({ evidence }) => /owner\/pinned/.test(evidence)), false);
  assert.ok(workflow.every((finding) => finding.standards.some(({ id }) => id === "OWASP-A03:2025" || id === "OWASP-A05:2025")));
});

test("lockfile transport and credential checks inspect files excluded from ordinary SAST", async (t) => {
  const lockfilePassword = "registry-password-that-must-not-leak";
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": {
      name: "site",
      lockfileVersion: 3,
      packages: {
        "node_modules/plain": { version: "1.0.0", resolved: "http://registry.example/plain.tgz" },
        "node_modules/private": { version: "1.0.0", resolved: `https://build:${lockfilePassword}@registry.example/private.tgz` },
        "node_modules/unverified": { version: "1.0.0", resolved: "https://registry.npmjs.org/unverified/-/unverified-1.0.0.tgz" },
        "node_modules/verified": {
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/verified/-/verified-1.0.0.tgz",
          integrity: "sha512-YWJjZA==",
        },
      },
    },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const result = await scan(project);

  const integrity = result.findings.filter(({ id }) => id === "security.lockfile-integrity");
  assert.equal(integrity.length, 2);
  assert.ok(integrity.some(({ title }) => /plaintext HTTP/.test(title)));
  assert.ok(integrity.some(({ title }) => /integrity digest/.test(title)));
  assert.ok(result.findings.some(({ id, file }) => id === "security.hardcoded-auth" && file === "package-lock.json"));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(lockfilePassword));
});

test("JWT checks reject lookalikes and flag syntactic tokens plus disabled verification", async (t) => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const lookalike = "eyJabcdefghijk.abcdefghijkl.mnopqrstuvwx";
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0", jsonwebtoken: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "README.md": `Not a JWT: ${lookalike}`,
    "src/server/auth.ts": [
      "import jwt from 'jsonwebtoken';",
      `const captured = '${jwt}';`,
      "export const claims = jwt.verify(captured, publicKey, { algorithms: ['none'], ignoreExpiration: true });",
    ].join("\n"),
  });
  const result = await scan(project);
  const tokens = result.findings.filter(({ id, title }) => id === "security.embedded-secrets" && /JSON Web Token/.test(title));
  const validation = result.findings.filter(({ id }) => id === "security.jwt-validation");

  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].file, "src/server/auth.ts");
  assert.equal(validation.length, 2);
  assert.ok(validation.every(({ severity, confidence, manual }) => severity === "critical" && confidence === "high" && manual === false));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(jwt.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("provider-specific secret signatures are deduplicated against generic assignments", async (t) => {
  const values = [
    `sk-proj-${"A".repeat(32)}`,
    `sk-ant-api03-${"B".repeat(40)}`,
    `SG.${"C".repeat(22)}.${"D".repeat(43)}`,
    `GOCSPX-${"E".repeat(24)}`,
    `SK${"a1".repeat(16)}`,
  ];
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/config.ts": values.map((value, index) => `const serviceSecret${index} = '${value}';`).join("\n"),
  });
  const result = await scan(project);
  const embedded = result.findings.filter(({ id, file }) => id === "security.embedded-secrets" && file === "src/config.ts");

  assert.equal(embedded.length, values.length);
  for (const value of values) assert.doesNotMatch(JSON.stringify(result), new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("server data-flow rules do not reinterpret browser routes or unrelated APIs as server vulnerabilities", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/routes/Search.tsx": [
      "export async function Search() {",
      "  const target = new URLSearchParams(location.search).get('target');",
      "  const response = await fetch(target);",
      "  return <main>{response.status}</main>;",
      "}",
    ].join("\n"),
    "src/server/metrics.ts": [
      "export function record(request) {",
      "  const metric = request.query.metric;",
      "  analytics.query(metric);",
      "  readFile(metric);",
      "  exec(metric);",
      "}",
    ].join("\n"),
  });
  const result = await scan(project);

  assert.equal(result.findings.some((finding) => finding.tags.includes("data-flow")), false);
});

test("container and Terraform checks report explicit privilege and public-exposure settings", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "Dockerfile": [
      "FROM node:24-alpine",
      "RUN curl -fsSL https://downloads.example/install.sh | /bin/sh",
      "RUN curl -o package.tgz https://downloads.example/package.tgz ; sh ./checked-in-script.sh",
      `ADD --checksum=sha256:${"a".repeat(64)} https://downloads.example/package.tgz /tmp/package.tgz`,
      "USER 0:1000",
      "CMD [\"node\", \"server.js\"]",
    ].join("\n"),
    "compose.yml": [
      "services:",
      "  app:",
      "    image: example/app@sha256:0123456789abcdef",
      "    privileged: true",
      "    volumes:",
      "      - /var/run/docker.sock:/var/run/docker.sock",
    ].join("\n"),
    "infra/main.tf": [
      "# publicly_accessible = true",
      "// acl = \"public-read\"",
      "resource \"aws_s3_bucket\" \"assets\" {",
      "  acl = \"public-read\"",
      "}",
      "resource \"aws_s3_bucket_public_access_block\" \"assets\" {",
      "  block_public_acls = false",
      "}",
      "resource \"aws_db_instance\" \"database\" {",
      "  publicly_accessible = true",
      "}",
    ].join("\n"),
    "deploy/safe.yml": [
      "apiVersion: apps/v1",
      "kind: Deployment",
      "spec:",
      "  template:",
      "    spec:",
      "      containers:",
      "        - image: example/app@sha256:0123456789abcdef",
      "          securityContext:",
      "            runAsNonRoot: true",
      "            allowPrivilegeEscalation: false",
    ].join("\n"),
  });
  const result = await scan(project);
  const container = result.findings.filter(({ id }) => id === "security.container-hardening");
  const terraform = result.findings.filter(({ id }) => id === "security.iac-exposure");

  assert.equal(container.length, 4);
  assert.deepEqual(new Set(container.map(({ file }) => file)), new Set(["Dockerfile", "compose.yml"]));
  assert.equal(terraform.length, 3);
  assert.ok(terraform.every(({ file, manual, confidence }) => file === "infra/main.tf" && manual && confidence === "medium"));
  assert.equal(result.findings.some(({ file, id }) => file === "deploy/safe.yml" && ["security.container-hardening", "security.iac-exposure"].includes(id)), false);
});

test("SSRF analysis does not treat a userinfo-capable URL prefix as a fixed origin", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { next: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/app/api/proxy/route.ts": [
      "export async function GET(request) {",
      "  const suffix = new URL(request.url).searchParams.get('suffix');",
      "  await fetch('https://trusted.example' + suffix);",
      "  await fetch('https://trusted.example/search?q=' + encodeURIComponent(suffix));",
      "  return new Response('ok');",
      "}",
    ].join("\n"),
  });
  const result = await scan(project);
  const ssrf = result.findings.filter(({ id }) => id === "security.server-ssrf");

  assert.equal(ssrf.length, 1);
  assert.equal(ssrf[0].line, 3);
});

test("workflow analysis catches privileged pull-request head execution without direct interpolation", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    ".github/workflows/privileged.yml": [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - run: npm test",
    ].join("\n"),
    ".github/workflows/unprivileged.yml": [
      "on: pull_request",
      "jobs:",
      "  inspect:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo '${{ github.event.pull_request.title }}'",
    ].join("\n"),
  });
  const result = await scan(project);
  const privileged = result.findings.find(({ title }) => /Privileged workflow/.test(title));
  const direct = result.findings.find(({ file, title }) => file === ".github/workflows/unprivileged.yml" && /interpolated/.test(title));

  assert.deepEqual({ severity: privileged?.severity, confidence: privileged?.confidence, manual: privileged?.manual }, { severity: "critical", confidence: "high", manual: true });
  assert.deepEqual({ severity: direct?.severity, confidence: direct?.confidence, manual: direct?.manual }, { severity: "high", confidence: "high", manual: false });
});

test("path data flow respects lexical scopes and strict filename allowlists", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { express: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/server/files.ts": [
      "import path from 'node:path';",
      "import { readFile } from 'node:fs';",
      "function translationPath(locale) {",
      "  return path.join(TRANSLATIONS, locale, 'messages.json');",
      "}",
      "export function translated(request, response) {",
      "  const locale = request.params.locale;",
      "  const translationFile = translationPath(locale);",
      "  readFile(translationFile, () => response.end());",
      "}",
      "export function image(request, response) {",
      "  const fileName = request.params.file;",
      "  if (!/^[a-f0-9]{32}\\.(?:png|jpg)$/.test(fileName)) return response.status(400).end();",
      "  const imageFile = path.resolve(UPLOADS, fileName);",
      "  readFile(imageFile, () => response.end());",
      "}",
      "export function report(request, response) {",
      "  const reportName = request.params.report;",
      "  if (!/^report-.+\\.html$/.test(reportName)) return response.status(400).end();",
      "  const reportFile = path.resolve(REPORTS, reportName);",
      "  if (!reportFile.startsWith(REPORTS)) return response.status(400).end();",
      "  readFile(reportFile, () => response.end());",
      "}",
      "export function shadowed(request, response) {",
      "  const selected = request.params.file;",
      "  if (DEFAULT_FILE) {",
      "    const selected = 'manual.pdf';",
      "    readFile(selected, () => response.end());",
      "  }",
      "}",
    ].join("\n"),
  });
  const result = await scan(project);
  const paths = result.findings.filter(({ id }) => id === "security.server-path-traversal");

  assert.equal(paths.length, 1);
  assert.equal(paths[0].line, 22);
  assert.match(paths[0].evidence, /reportFile/);
});

test("command data flow distinguishes shell-enabled spawn from argument-array execution", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { express: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/server/render.ts": [
      "import { spawn } from 'node:child_process';",
      "export function render(request) {",
      "  const input = request.body.input;",
      "  spawn('convert', [input], { shell: true });",
      "  spawn('convert', [input], { shell: false });",
      "  spawn('convert', [input]);",
      "}",
    ].join("\n"),
  });
  const result = await scan(project);
  const commands = result.findings.filter(({ id }) => id === "security.server-command-injection");

  assert.equal(commands.length, 1);
  assert.equal(commands[0].line, 4);
  assert.match(commands[0].evidence, /shell-enabled child process/);
});

test("data-flow guards must reject unsafe values instead of merely inspecting them", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { express: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/server/guards.ts": [
      "import path from 'node:path';",
      "import { readFile } from 'node:fs';",
      "export async function proxy(request) {",
      "  const target = request.query.target;",
      "  const parsed = new URL(target);",
      "  parsed.hostname === 'allowed.example';",
      "  await fetch(parsed);",
      "}",
      "export function file(request) {",
      "  const name = request.params.name;",
      "  path.basename(name);",
      "  const resolved = path.resolve(ROOT, name);",
      "  resolved.startsWith(ROOT + path.sep);",
      "  readFile(resolved, () => {});",
      "}",
    ].join("\n"),
  });
  const result = await scan(project);
  const flows = result.findings.filter(({ id }) => ["security.server-ssrf", "security.server-path-traversal"].includes(id));

  assert.deepEqual(flows.map(({ id }) => id).sort(), [
    "security.server-path-traversal",
    "security.server-ssrf",
  ]);
});

test("filename allowlists cannot admit directory separators through regex shortcuts", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { express: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/server/downloads.ts": [
      "import path from 'node:path';",
      "import { readFile } from 'node:fs';",
      "export function topLevelAlternative(request) {",
      "  const name = request.params.name;",
      "  if (!/^foo|bar$/.test(name)) return;",
      "  readFile(path.join(ROOT, name), () => {});",
      "}",
      "export function escapedSeparator(request) {",
      "  const name = request.params.name;",
      "  if (!/^foo\\/bar$/.test(name)) return;",
      "  readFile(path.join(ROOT, name), () => {});",
      "}",
      "export function negatedClass(request) {",
      "  const name = request.params.name;",
      "  if (!/^[^.]+$/.test(name)) return;",
      "  readFile(path.join(ROOT, name), () => {});",
      "}",
      "export function nonDigitClass(request) {",
      "  const name = request.params.name;",
      "  if (!/^\\D+$/.test(name)) return;",
      "  readFile(path.join(ROOT, name), () => {});",
      "}",
    ].join("\n"),
  });
  const result = await scan(project);
  const paths = result.findings.filter(({ id }) => id === "security.server-path-traversal");

  assert.equal(paths.length, 4);
});

test("data-flow analysis ignores source and identifier text inside comments and literals", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { express: "1.0.0", pg: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/server/comments.ts": [
      "import { exec } from 'node:child_process';",
      "import { Pool } from 'pg';",
      "const db = new Pool();",
      "export function inspect(request) {",
      "  // const command = request.body.command;",
      "  exec(command);",
      "  const id = request.query.id;",
      "  db.query('SELECT id FROM users');",
      "}",
    ].join("\n"),
    "src/api/client.ts": [
      "export async function browserApi(request) {",
      "  const target = request.url;",
      "  return fetch(target);",
      "}",
    ].join("\n"),
  });
  const result = await scan(project);

  assert.equal(result.findings.some((finding) => finding.tags.includes("data-flow")), false);
});

test("workflow analysis does not correlate checkout and execution across separate jobs", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    ".github/workflows/separated.yml": [
      "on: pull_request_target",
      "jobs:",
      "  inspect-source:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "  trusted-task:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: npm run trusted-task",
    ].join("\n"),
  });
  const result = await scan(project);
  const workflow = result.findings.filter(({ id }) => id === "security.ci-workflow");

  assert.equal(workflow.some(({ title }) => /Privileged workflow/.test(title)), false);
  assert.equal(workflow.filter(({ title }) => /mutable tag/.test(title)).length, 1);
});

test("lockfile transport recognizes Yarn syntax and exact loopback hosts", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "yarn.lock": [
      "safe@1.0.0:",
      "  resolved \"http://localhost:4873/safe.tgz\"",
      "remote@1.0.0:",
      "  resolved \"http://registry.example/remote.tgz\"",
      "lookalike@1.0.0:",
      "  resolved \"http://localhost.evil/lookalike.tgz\"",
    ].join("\n"),
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const result = await scan(project);
  const transport = result.findings.filter(({ id }) => id === "security.lockfile-integrity");

  assert.equal(transport.length, 2);
  assert.ok(transport.every(({ title }) => /plaintext HTTP/.test(title)));
});
