import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseCliArguments, shouldFail } from "../src/cli.js";
import { buildScanResult, createFinding, deduplicateFindings } from "../src/core/model.js";
import { REPORT_FILES, writeScanReports } from "../src/core/reporter.js";
import { redactSensitiveText } from "../src/core/sanitize.js";

function sampleResult(root, mode = "security", findings = []) {
  return buildScanResult({
    mode,
    title: mode === "security" ? "Security report" : "Website quality report",
    root,
    findings,
    checks: 42,
    filesScanned: 7,
    startedAt: Date.now() - 120,
    metadata: { coverage: ["Test coverage"] },
  });
}

test("credential redaction is idempotent across typed, compound, computed and structured assignments", () => {
  const source = [
    'const token: string = "typed private value";',
    'token ??= "compound private value";',
    'config["password"] ||= "computed private value";',
    'const credentials = ["structured private value"];',
  ].join("\n");
  const once = redactSensitiveText(source);
  const twice = redactSensitiveText(once);

  assert.equal(twice, once);
  assert.equal((once.match(/<redacted>/g) ?? []).length, 4);
  assert.doesNotMatch(once, /private value/);
  assert.doesNotMatch(once, /<redacted>>/);
});

test("credential redaction covers contextual setters, HTML controls, cookies, curl and service URIs", () => {
  const secrets = [
    "storage private value",
    "setter private value",
    "input private value",
    "meta private value",
    "cookie-private-value",
    "curl-private-value",
    "wget-private-value",
    "database-private-value",
    "transport-private-token",
  ];
  const source = [
    `localStorage.setItem("session", "${secrets[0]}");`,
    `cookies.set("authToken", "${secrets[1]}");`,
    `<input value="${secrets[2]}" type="password">`,
    `<meta content="${secrets[3]}" name="csrf-token">`,
    `document.cookie = "session=${secrets[4]}; path=/";`,
    `curl -u admin:${secrets[5]} https://example.com/install`,
    `wget --user admin --password ${secrets[6]} https://example.com/install`,
    `const databaseUrl = "postgres://admin:${secrets[7]}@db.example.com/app";`,
    `fetch("http://${secrets[8]}@api.example.com/account");`,
  ].join("\n");
  const redacted = redactSensitiveText(source);

  for (const secret of secrets) assert.doesNotMatch(redacted, new RegExp(secret));
  assert.equal(redactSensitiveText(redacted), redacted);
});

test("credential context redaction preserves comparisons and masks fallback expressions", () => {
  const secrets = ["comparison secret value", "fallback secret value", "function secret value"];
  const source = [
    `token === "${secrets[0]}";`,
    `token = process.env.API_TOKEN ?? "${secrets[1]}";`,
    `const getToken = () => String("${secrets[2]}");`,
  ].join("\n");
  const redacted = redactSensitiveText(source);

  for (const secret of secrets) assert.doesNotMatch(redacted, new RegExp(secret));
  assert.match(redacted, /token === "<redacted>"/);
  assert.match(redacted, /getToken = <redacted>/);
  assert.doesNotMatch(redacted, /=<redacted>\s+"/);
});

test("credential YAML block scalars are redacted with their full payload", () => {
  const secret = "correct horse battery staple!";
  const source = [
    "config:",
    "  token: |",
    `    ${secret}`,
    "  provider: corporate-sso",
    "visible: true",
  ].join("\n");
  const redacted = redactSensitiveText(source);

  assert.doesNotMatch(redacted, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(redacted, /token: \|\n\s+<redacted>/);
  assert.match(redacted, /provider: corporate-sso/);
  assert.match(redacted, /visible: true/);
});

test("CLI parser recognizes the individual scan commands and defaults to Modular output", () => {
  const security = parseCliArguments(["check", "security", "--no-color"]);
  assert.equal(security.mode, "security");
  assert.equal(security.color, false);
  assert.equal(security.auditDependencies, false);
  assert.equal(path.basename(security.output), "Modular");

  const site = parseCliArguments(["check", "mysite", "--fail-on", "high", "--ignore", "generated"]);
  assert.equal(site.mode, "mysite");
  assert.equal(site.failOn, "high");
  assert.deepEqual(site.ignore, ["generated"]);

  const networkAudit = parseCliArguments(["check", "security", "--dependency-audit", "--max-findings-per-rule", "75", "--max-total-size", "209715200"]);
  assert.equal(networkAudit.auditDependencies, true);
  assert.equal(networkAudit.maxFindingsPerRule, 75);
  assert.equal(networkAudit.maxTotalBytes, 209715200);
});

test("CLI parser rejects unknown commands and invalid thresholds", () => {
  assert.throws(() => parseCliArguments(["scan", "security"]), /Choose one of/);
  assert.throws(() => parseCliArguments(["check", "security", "--fail-on", "urgent"]), /must be/);
  assert.throws(() => parseCliArguments(["check", "mysite", "--mystery"]), /Unknown option/);
});

test("finding model deduplicates exact evidence locations", () => {
  const finding = createFinding({
    id: "test-rule",
    title: "Test",
    category: "Tests",
    severity: "medium",
    file: "src/app.js",
    line: 2,
    evidence: "example",
  });
  assert.equal(deduplicateFindings([finding, { ...finding }]).length, 1);
});

test("finding model validates and isolates standards and authoritative references", () => {
  const inputStandards = [{
    id: "CWE-79",
    title: "Improper Neutralization of Input During Web Page Generation",
    url: "https://cwe.mitre.org/data/definitions/79.html",
  }];
  const finding = createFinding({
    id: "test-rule",
    title: "Test",
    category: "Tests",
    severity: "high",
    standards: [...inputStandards, { ...inputStandards[0] }],
    references: [
      "https://owasp.org/Top10/2025/A05_2025-Injection/",
      "https://owasp.org/Top10/2025/A05_2025-Injection/",
    ],
  });

  inputStandards[0].id = "mutated";
  assert.equal(finding.standards[0].id, "CWE-79");
  assert.equal(finding.standards.length, 1);
  assert.equal(finding.references.length, 1);
  assert.throws(() => createFinding({
    id: "bad-reference",
    title: "Bad reference",
    category: "Tests",
    severity: "low",
    references: ["http://example.com/not-authoritative"],
  }), /must use HTTPS/);
  assert.throws(() => createFinding({
    id: "bad-confidence",
    title: "Bad confidence",
    category: "Tests",
    severity: "low",
    confidence: "certain",
  }), /confidence must be/);
});

test("scan result redacts descriptive fields while preserving operational paths", () => {
  const secret = "result-boundary-private-value";
  const result = buildScanResult({
    mode: "security",
    title: "Security report",
    root: `C:\\work\\token=${secret}\\site`,
    findings: [createFinding({
      id: "boundary",
      title: `Problem token=${secret}`,
      category: "Security",
      severity: "high",
      description: `password=${secret}`,
      recommendation: `replace credential=${secret}`,
      evidence: `token = "${secret}"`,
      file: `src/token=${secret}.js`,
      suggestedFiles: [`src/password=${secret}.js`],
    })],
    checks: 1,
    filesScanned: 1,
    startedAt: Date.now(),
    metadata: { coverage: { note: `authToken=${secret}` } },
  });

  assert.equal(result.root, `C:\\work\\token=${secret}\\site`);
  assert.equal(result.findings[0].file, `src/token=${secret}.js`);
  assert.deepEqual(result.findings[0].suggestedFiles, [`src/password=${secret}.js`]);
  assert.doesNotMatch(JSON.stringify({
    title: result.findings[0].title,
    description: result.findings[0].description,
    recommendation: result.findings[0].recommendation,
    evidence: result.findings[0].evidence,
    metadata: result.metadata,
  }), new RegExp(secret));
});

test("threshold failure includes findings at and above configured severity", () => {
  const root = process.cwd();
  const high = sampleResult(root, "security", [
    createFinding({ id: "high", title: "High", category: "Security", severity: "high" }),
  ]);
  assert.equal(shouldFail(high, "critical"), false);
  assert.equal(shouldFail(high, "high"), true);
  assert.equal(shouldFail(high, "medium"), true);
  assert.equal(shouldFail(high, "none"), false);
});

test("report writer keeps a deterministic maximum of five Markdown reports", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-reporter-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const outputDirectory = path.join(root, "Modular");
  const finding = createFinding({
    id: "unsafe-html",
    title: "Unsafe HTML sink",
    category: "Browser security",
    severity: "high",
    description: "Untrusted data may reach an HTML sink.",
    recommendation: "Sanitize the value before rendering.",
    evidence: "dangerouslySetInnerHTML",
    file: "src/Card.jsx",
    line: 12,
    suggestedFiles: ["src/Card.jsx"],
    standards: [{
      id: "CWE-79",
      title: "Cross-site Scripting",
      url: "https://cwe.mitre.org/data/definitions/79.html",
    }],
    references: ["https://owasp.org/www-community/attacks/xss/"],
  });

  await writeScanReports(sampleResult(root, "security", [finding]), { outputDirectory });
  await writeScanReports(sampleResult(root, "mysite", []), { outputDirectory });

  const markdown = (await fs.readdir(outputDirectory)).filter((name) => name.endsWith(".md")).sort();
  assert.deepEqual(markdown, [REPORT_FILES.overview, ...REPORT_FILES.security, ...REPORT_FILES.mysite].sort());
  const detailed = await fs.readFile(path.join(outputDirectory, REPORT_FILES.security[0]), "utf8");
  assert.match(detailed, /src\/Card\.jsx:12/);
  assert.match(detailed, /Sanitize the value before rendering/);
  assert.match(detailed, /CWE-79/);
  assert.match(detailed, /https:\/\/cwe\.mitre\.org\/data\/definitions\/79\.html/);
  assert.match(detailed, /https:\/\/owasp\.org\/www-community\/attacks\/xss/);
});
