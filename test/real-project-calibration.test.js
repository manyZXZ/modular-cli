import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { collectFiles, runSecurityScan, runSiteScan, buildScanResult } from "../src/index.js";

// Reduced, synthetic cases derived from a real React/Vite + Fastify repository.
// No private project source, live credentials or external services are required.
async function fixture(t, files) {
  const parent = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(parent, "modular-calibration-"));
  t.after(async () => {
    const real = await fs.realpath(root);
    assert.equal(path.dirname(real).toLowerCase(), parent.toLowerCase());
    assert.ok(path.basename(real).startsWith("modular-calibration-"));
    await fs.rm(real, { recursive: true, force: true });
  });
  const entries = { "index.html": '<!doctype html><html lang="en"><head><title>Site</title></head><body><main><h1>Site</h1></main></body></html>', ...files };
  for (const [file, content] of Object.entries(entries)) {
    await fs.mkdir(path.dirname(path.join(root, file)), { recursive: true });
    await fs.writeFile(path.join(root, file), typeof content === "string" || Buffer.isBuffer(content) ? content : JSON.stringify(content));
  }
  return { root, ...await collectFiles(root) };
}

test("local provider credentials are counted once without asserting exposure; public config remains distinct", async (t) => {
  const synthetic = `sk-proj-${"A".repeat(32)}`;
  const input = await fixture(t, {
    ".gitignore": ".env\n", ".env": `OPENAI_API_KEY=${synthetic}\n`,
    ".env.production": "VITE_API_BASE_URL=/api\nVITE_FEATURE_ENABLED=true\n",
    "src/config.ts": `export const key = '${synthetic}';`,
  });
  const result = await runSecurityScan(input);
  const local = result.findings.filter(({ id, file }) => id === "security.embedded-secrets" && file === ".env");
  assert.equal(local.length, 1);
  assert.equal(local[0].severity, "medium");
  assert.equal(local[0].manual, true);
  assert.equal(result.findings.find(({ file }) => file === "src/config.ts").severity, "critical");
  assert.equal(result.findings.some(({ id }) => id === "security.environment-hygiene"), false);
  assert.equal(JSON.stringify(result).includes(synthetic), false);
});

test("a bounded provider match inside a longer dotenv value is not counted twice", async (t) => {
  const synthetic = `sk-proj-${"A".repeat(40)}-${"B".repeat(400)}`;
  const result = await runSecurityScan(await fixture(t, { ".env": `OPENAI_API_KEY=${synthetic}\n` }));
  assert.equal(result.findings.filter(({ id }) => id === "security.embedded-secrets").length, 1);
  assert.equal(JSON.stringify(result).includes(synthetic), false);
});

test("credential-bearing environment files still require ignore coverage", async (t) => {
  const result = await runSecurityScan(await fixture(t, { ".env.production": "VITE_PUBLIC_URL=https://example.test/?token=opaque\nSESSION_SECRET=not-a-placeholder-value\n" }));
  assert.ok(result.findings.some(({ id }) => id === "security.environment-hygiene"));
});

test("filename component rejection is recognized only with complete terminating checks and drive protection", async (t) => {
  const reject = String.raw`if (fileName.includes('/') || fileName.includes('\\') || fileName.includes('..')) return;`;
  const validation = String.raw`const allowed = /^transcript-(\d+)-.+-(\d+)\.html$/; const match = fileName.match(allowed); if (!match) return;`;
  const cases = [
    [reject + validation, 0],
    [reject, 1],
    [reject.replace(" || fileName.includes('\\\\')", "") + validation, 1],
    [reject.replaceAll("||", "&&") + validation, 1],
    [reject.replace("return;", "{ if (debug) return; }") + validation, 1],
    [reject + validation + "fileName = req.query.other;", 1],
    [reject + validation.replace("transcript-", "C-*") , 1],
  ];
  const files = Object.fromEntries(cases.map(([guard], i) => [`server/case-${i}.js`, `import fs from 'node:fs'; import path from 'node:path'; export function get(req) { let fileName = req.params.name; ${guard} const filePath = path.resolve('/files', fileName); return fs.readFileSync(filePath); }`]));
  const result = await runSecurityScan(await fixture(t, files));
  cases.forEach(([, expected], i) => assert.equal(result.findings.filter(({ id, file }) => id === "security.server-path-traversal" && file === `server/case-${i}.js`).length, expected, `case ${i}`));
  for (const name of ['transcript-123-topic-456.html', 'transcript-123-..-456.html', '../transcript-123-topic-456.html', 'C:private', '\\private', '/private']) {
    if (name.includes('/') || name.includes('\\') || name.includes('..') || !/^transcript-(\d+)-.+-(\d+)\.html$/.test(name)) continue;
    assert.ok(path.win32.resolve('C:\\files', name).startsWith('C:\\files\\'));
    assert.ok(path.posix.resolve('/files', name).startsWith('/files/'));
  }
});

test("bundled CSS imports and bot-only assets are not reported as browser delivery defects", async (t) => {
  const result = await runSiteScan(await fixture(t, {
    "package.json": { dependencies: { react: "1", vite: "1" }, scripts: { build: "vite build" } },
    "src/app.css": '@import "./theme.css";', "src/theme.css": '@import "tailwindcss";',
    "src/remote.css": '@import "./theme.css";\n@import "https://fonts.example.test/font.css";',
    "public/unbundled.css": '@import "./other.css";',
    "src/assets/bot-banner.png": Buffer.alloc(1024 * 1024 + 1),
    "src/bot/help.ts": "export const banner = new AttachmentBuilder('src/assets/bot-banner.png');",
    "src/App.tsx": 'export const App = () => <main><img src="/hero.png" alt="Hero" /></main>;',
    "public/hero.png": Buffer.alloc(1024 * 1024 + 1),
  }));
  assert.deepEqual(result.findings.filter(({ id }) => id === "performance-css-import").map(({ file }) => file).sort(), ["public/unbundled.css", "src/remote.css"]);
  assert.deepEqual(result.findings.filter(({ id }) => id === "performance-large-image-asset").map(({ file }) => file), ["public/hero.png"]);
});

test("a labeled FormField cannot implicitly name nested or sibling controls", async (t) => {
  const result = await runSiteScan(await fixture(t, {
    "src/App.tsx": `export function App() { return <main>
      <FormField label="Direct"><select><option>One</option></select></FormField>
      <FormField label="Nested"><div><input type="number" /></div></FormField>
      <FormField label="Siblings"><input type="text" /><input type="email" /></FormField>
      <FormField label="Explicit"><div><input aria-label="Amount" /></div></FormField>
    </main>; }`,
  }));
  const labels = result.findings.filter(({ id }) => id === "a11y-form-label");
  assert.equal(labels.length, 3);
  assert.ok(labels.every(({ line }) => line === 3 || line === 4));
});

test("nested runtime standards keep the same valid reference URLs as top-level findings", () => {
  const url = "https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html";
  const result = buildScanResult({ mode: "mysite", title: "Test", root: ".", findings: [], filesScanned: 0, checks: 0,
    metadata: { runtime: { findings: [{ standards: [{ id: "WCAG-2.2-2.5.8", url }], references: [url] }] } } });
  assert.equal(result.metadata.runtime.findings[0].standards[0].url, url);
  assert.equal(result.metadata.runtime.findings[0].references[0], url);
});

test("unrelated metadata reference fields remain permissive and redacted", () => {
  const synthetic = `sk-proj-${"A".repeat(40)}`;
  const result = buildScanResult({ mode: "mysite", title: "Test", root: ".", findings: [], filesScanned: 0, checks: 0,
    metadata: { references: ["local-file", synthetic], standards: ["internal convention"] } });
  assert.equal(result.metadata.references[0], "local-file");
  assert.deepEqual(result.metadata.standards, ["internal convention"]);
  assert.equal(JSON.stringify(result).includes(synthetic), false);
});
