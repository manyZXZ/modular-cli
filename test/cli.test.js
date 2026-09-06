import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { EXIT, parseCliArguments, runCli } from "../src/cli.js";
import { collectFiles, readTextFile } from "../src/core/files.js";
import { buildScanResult, createFinding } from "../src/core/model.js";
import { MODULAR_BRAILLE_LOGO, MODULAR_LOGO_SOURCE } from "../src/core/logo.js";
import { REPORT_MARKER } from "../src/core/reporter.js";
import { TerminalUI } from "../src/core/ui.js";

function captureStream({ isTTY = false, columns = 100 } = {}) {
  const chunks = [];
  return {
    columns,
    isTTY,
    write(chunk) {
      chunks.push(String(chunk));
      return true;
    },
    text() {
      return chunks.join("");
    },
  };
}

async function temporaryDirectory(t, prefix = "modular-cli-") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

function scanResult(root, findings = [], mode = "mysite") {
  return buildScanResult({
    mode,
    title: mode === "security" ? "Security report" : "Website quality report",
    root,
    findings,
    checks: 10,
    filesScanned: 2,
    startedAt: Date.now() - 10,
  });
}

function runtimeScanResult(root, { status = "completed", findings = [] } = {}) {
  const checks = Array.from({ length: 10 }, (_value, index) => ({
    id: `runtime-family-${index + 1}`,
    kind: "automated",
    status: status === "completed" ? "completed" : "unavailable",
  }));
  const result = buildScanResult({
    mode: "runtime",
    title: "Runtime browser audit",
    root,
    findings,
    checks: 10,
    filesScanned: 0,
    startedAt: Date.now() - 15,
    metadata: { checks },
  });
  return {
    ...result,
    status,
    url: "http://127.0.0.1:4173/",
    capabilities: {
      playwright: { available: true, browserName: "chromium", browserTypeAvailable: true },
      axe: { available: true, engine: "axe-core" },
    },
    stages: { launch: { status: "completed", durationMs: 2 } },
    viewport: { preset: "mobile", width: 390, height: 844 },
    checkDescriptors: checks,
    metrics: {
      routesRequested: 1,
      routesAudited: 1,
      routesCompleted: status === "completed" ? 1 : 0,
      routesPartial: status === "partial" ? 1 : 0,
      routesFailed: 0,
      blockedRequests: 0,
      requestFailures: 0,
      consoleErrors: 0,
      pageErrors: 0,
      accessibilityViolations: 0,
      accessibilityAffectedNodes: 0,
      resourceCount: 3,
      transferredBytes: 2048,
      routes: [],
    },
    policy: { optIn: true, allowRemote: false, localOnly: true, repositoryScriptsExecuted: false },
  };
}

test("relative output paths resolve from --root regardless of option order", () => {
  const parsed = parseCliArguments(["check", "mysite", "--output", "reports", "--root", "fixtures/site"]);
  assert.equal(parsed.root, path.resolve("fixtures/site"));
  assert.equal(parsed.output, path.resolve("fixtures/site", "reports"));
});

test("check all is a first-class mode", () => {
  const parsed = parseCliArguments(["check", "all", "--no-color"]);
  assert.equal(parsed.mode, "all");
  assert.equal(parsed.color, false);
});

test("ignore values are exact directory names rather than silently ineffective paths", () => {
  const parsed = parseCliArguments(["check", "security", "--ignore", "generated"]);
  assert.deepEqual(parsed.ignore, ["generated"]);

  for (const invalid of [".", "..", "src/generated", "src\\generated"]) {
    assert.throws(
      () => parseCliArguments(["check", "security", "--ignore", invalid]),
      /exact directory name.*not a path/i,
    );
  }
});

test("argument errors cannot inject terminal controls or extra lines", async () => {
  const stdout = captureStream();
  const stderr = captureStream();
  const code = await runCli(["check", "security", "--bad\n\u001b[31moption"], {
    stdout,
    stderr,
    setExitCode() {},
  });

  assert.equal(code, EXIT.usage);
  assert.equal(stdout.text(), "");
  assert.equal(stderr.text().split(/\r?\n/, 1)[0], "Unknown option: --bad �[31moption");
  assert.doesNotMatch(stderr.text(), /\u001b\[/);
});

test("runtime browser options require explicit opt-in and one target", () => {
  assert.throws(
    () => parseCliArguments(["check", "mysite", "--url", "http://localhost:4173"]),
    /explicit --runtime opt-in/i,
  );
  assert.throws(
    () => parseCliArguments(["check", "security", "--runtime", "--url", "http://localhost:4173"]),
    /mysite.*check all/i,
  );
  assert.throws(
    () => parseCliArguments(["check", "mysite", "--runtime"]),
    /exactly one target/i,
  );
  assert.throws(
    () => parseCliArguments([
      "check", "mysite", "--runtime", "--url", "http://localhost:4173", "--runtime-static-dir", "dist",
    ]),
    /exactly one target/i,
  );
  assert.throws(
    () => parseCliArguments([
      "check", "mysite", "--runtime", "--url", "http://localhost:4173", "--route", "/a", "--runtime-max-routes", "1",
    ]),
    /base URL.*exceed/i,
  );
  assert.throws(
    () => parseCliArguments(["check", "mysite", "--runtime", "--url", "not-a-url"]),
    /absolute HTTP or HTTPS/i,
  );
  assert.throws(
    () => parseCliArguments(["check", "mysite", "--runtime", "--url", "http://user:pass@localhost:4173"]),
    /embedded credentials/i,
  );
  assert.throws(
    () => parseCliArguments(["check", "mysite", "--runtime", "--url", "https://example.com"]),
    /--allow-remote/i,
  );
  assert.throws(
    () => parseCliArguments([
      "check", "mysite", "--runtime", "--url", "http://localhost:4173", "--runtime-max-routes", "26",
    ]),
    /cannot exceed 25/i,
  );
  assert.throws(
    () => parseCliArguments([
      "check", "mysite", "--runtime", "--url", "http://localhost:4173", "--runtime-spa-fallback",
    ]),
    /requires --runtime-static-dir/i,
  );
  assert.throws(
    () => parseCliArguments(["check", "mysite", "--dependency-audit"]),
    /security.*check all/i,
  );

  const parsed = parseCliArguments([
    "check", "mysite", "--runtime", "--url", "http://localhost:4173", "--route", "/about",
    "--browser", "chromium", "--browser-channel", "chrome", "--runtime-timeout", "45000", "--allow-remote",
  ]);
  assert.equal(parsed.runtimeAudit, true);
  assert.equal(parsed.runtimeUrl, "http://localhost:4173");
  assert.deepEqual(parsed.runtimeRoutes, ["/about"]);
  assert.equal(parsed.runtimeBrowser, "chromium");
  assert.equal(parsed.runtimeBrowserChannel, "chrome");
  assert.equal(parsed.runtimeTimeoutMs, 45_000);
  assert.equal(parsed.runtimeAllowRemote, true);
  assert.throws(
    () => parseCliArguments([
      "check", "mysite", "--runtime", "--url", "http://localhost:4173",
      "--browser", "firefox", "--browser-channel", "chrome",
    ]),
    /only.*chromium/i,
  );
});

test("mysite runtime audit merges browser evidence into the same three reports", async (t) => {
  const root = await temporaryDirectory(t);
  const stdout = captureStream();
  let browserOptions;
  let writtenResult;
  const runtimeFinding = createFinding({
    id: "runtime.document-title",
    ruleFamily: "runtime-rendered-document",
    title: "Rendered page has no title",
    category: "Runtime & Browser",
    severity: "medium",
  });

  const code = await runCli([
    "check", "mysite", "--root", root, "--runtime", "--url", "http://127.0.0.1:4173/?campaign=do-not-leak", "--route", "/about",
  ], {
    stdout,
    stderr: captureStream(),
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, framework: "Test", confidence: 1 }),
    runSiteScan: async () => scanResult(root),
    runRuntimeBrowserAudit: async (options) => {
      browserOptions = options;
      options.onProgress({ stage: "capability-discovery", current: 0, total: 2 });
      return runtimeScanResult(root, { findings: [runtimeFinding] });
    },
    writeScanReports: async (result) => {
      writtenResult = result;
      return [
        path.join(root, "Modular", "00-overview.md"),
        path.join(root, "Modular", "03-site-report.md"),
        path.join(root, "Modular", "04-site-action-plan.md"),
      ];
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.ok);
  assert.equal(browserOptions.enabled, true);
  assert.deepEqual(browserOptions.routes, ["/about"]);
  assert.equal(writtenResult.mode, "mysite");
  assert.equal(writtenResult.checks, 20);
  assert.equal(writtenResult.metadata.runtime.status, "completed");
  assert.equal(writtenResult.metadata.checkLedger.length, 10);
  assert.ok(writtenResult.metadata.checkLedger.some((descriptor) => descriptor.id === "runtime-family-1"));
  assert.match(writtenResult.metadata.limitations.at(-1), /mobile 390x844 context/i);
  assert.ok(writtenResult.findings.some((finding) => finding.id === "runtime.document-title"));
  assert.match(stdout.text(), /Runtime browser audit/);
  assert.match(stdout.text(), /combined review/i);
  assert.doesNotMatch(stdout.text(), /do-not-leak/);
});

test("runtime static-directory mode closes its isolated server and uses its ephemeral URL", async (t) => {
  const root = await temporaryDirectory(t);
  let closed = 0;
  let servedOptions;
  let auditedUrl;

  const code = await runCli([
    "check", "mysite", "--root", root, "--runtime", "--runtime-static-dir", "dist", "--runtime-spa-fallback",
  ], {
    stdout: captureStream(),
    stderr: captureStream(),
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSiteScan: async () => scanResult(root),
    startRuntimeStaticServer: async (options) => {
      servedOptions = options;
      return { url: "http://127.0.0.1:54321/", async close() { closed += 1; } };
    },
    runRuntimeBrowserAudit: async (options) => {
      auditedUrl = options.url;
      return runtimeScanResult(root);
    },
    writeScanReports: async () => [],
    setExitCode() {},
  });

  assert.equal(code, EXIT.ok);
  assert.equal(servedOptions.enabled, true);
  assert.equal(servedOptions.directory, path.join(root, "dist"));
  assert.equal(servedOptions.spaFallback, true);
  assert.equal(auditedUrl, "http://127.0.0.1:54321/");
  assert.equal(closed, 1);
});

test("SIGTERM during a runtime audit closes the isolated server and exits 143", async (t) => {
  const root = await temporaryDirectory(t);
  const controller = new AbortController();
  const stderr = captureStream();
  let closed = 0;
  let writerCalled = false;

  const code = await runCli([
    "check", "mysite", "--root", root, "--runtime", "--runtime-static-dir", "dist",
  ], {
    signal: controller.signal,
    stdout: captureStream(),
    stderr,
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSiteScan: async () => scanResult(root),
    startRuntimeStaticServer: async () => ({
      url: "http://127.0.0.1:54321/",
      async close() { closed += 1; },
    }),
    runRuntimeBrowserAudit: async () => {
      controller.abort({ signal: "SIGTERM" });
      return runtimeScanResult(root);
    },
    writeScanReports: async () => {
      writerCalled = true;
      return [];
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.sigterm);
  assert.equal(closed, 1);
  assert.equal(writerCalled, false, "an interrupted combined result must not be published as complete");
  assert.match(stderr.text(), /interrupted by SIGTERM/i);
});

test("an explicitly requested partial runtime audit preserves reports and exits 1", async (t) => {
  const root = await temporaryDirectory(t);
  let writerCalled = false;
  const stderr = captureStream();
  const code = await runCli([
    "check", "mysite", "--root", root, "--runtime", "--url", "http://127.0.0.1:4173",
  ], {
    stdout: captureStream(),
    stderr,
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSiteScan: async () => scanResult(root),
    runRuntimeBrowserAudit: async () => runtimeScanResult(root, { status: "partial" }),
    writeScanReports: async () => {
      writerCalled = true;
      return [path.join(root, "Modular", "00-overview.md")];
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.failed);
  assert.equal(writerCalled, true);
  assert.match(stderr.text(), /runtime browser audit did not complete \(partial\)/i);
});

test("relative output paths cannot escape the repository, while explicit absolute paths can", () => {
  const root = path.resolve("fixtures/site");
  const outside = path.resolve(root, "..", "external-reports");

  assert.throws(
    () => parseCliArguments(["check", "mysite", "--root", root, "--output", path.join("..", "external-reports")]),
    /relative --output path must stay inside the repository/i,
  );
  const parsed = parseCliArguments(["check", "mysite", "--root", root, "--output", outside]);
  assert.equal(parsed.output, outside);
  assert.throws(
    () => parseCliArguments(["check", "all", "--root", root, "--output", "."]),
    /dedicated report directory/i,
  );
});

test("an output path below a regular file is reported as invalid usage", async (t) => {
  const root = await temporaryDirectory(t);
  await fs.writeFile(path.join(root, "not-a-directory"), "content");
  const stderr = captureStream();

  const code = await runCli([
    "check", "security", "--root", root, "--output", path.join("not-a-directory", "reports"), "--quiet",
  ], {
    stdout: captureStream(),
    stderr,
    setExitCode() {},
  });

  assert.equal(code, EXIT.usage);
  assert.match(stderr.text(), /report output path.*not a directory/i);
  assert.doesNotMatch(stderr.text(), /ENOTDIR/);
});

test("output ownership errors list conflicting entries deterministically", async (t) => {
  const root = await temporaryDirectory(t);
  const output = path.join(root, "Modular");
  await fs.mkdir(output);
  for (const name of ["zeta.txt", "middle.txt", "alpha.txt"]) {
    await fs.writeFile(path.join(output, name), name);
  }
  const stderr = captureStream();

  const code = await runCli(["check", "security", "--root", root, "--quiet"], {
    stdout: captureStream(),
    stderr,
    setExitCode() {},
  });

  assert.equal(code, EXIT.usage);
  assert.match(stderr.text(), /alpha\.txt, middle\.txt, zeta\.txt/);
});

test("package root exposes the documented programmatic API", async () => {
  const api = await import("modular-check");
  for (const name of [
    "buildScanResult",
    "collectFiles",
    "detectWebProject",
    "renderDetailedReport",
    "runCli",
    "runSecurityScan",
    "runSiteScan",
    "summarizeRuleFamilies",
    "writeScanReports",
  ]) {
    assert.equal(typeof api[name], "function", `${name} should be exported`);
  }
});

test("invalid repository paths use the documented usage exit code and stderr", async (t) => {
  const parent = await temporaryDirectory(t);
  const missing = path.join(parent, "does-not-exist");
  const stdout = captureStream();
  const stderr = captureStream();
  let exitCode;

  const returned = await runCli(["check", "security", "--root", missing], {
    stdout,
    stderr,
    setExitCode(code) { exitCode = code; },
  });

  assert.equal(returned, EXIT.usage);
  assert.equal(exitCode, EXIT.usage);
  assert.equal(stdout.text(), "");
  assert.match(stderr.text(), /Repository path does not exist/);
});

test("a non-website stops before scanner and report creation", async (t) => {
  const root = await temporaryDirectory(t);
  const stdout = captureStream();
  const stderr = captureStream();
  let scannerCalled = false;
  let writerCalled = false;

  const code = await runCli(["check", "mysite", "--root", root], {
    stdout,
    stderr,
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: false, reasons: ["No browser entry point was found."] }),
    runSiteScan: async () => { scannerCalled = true; },
    writeScanReports: async () => { writerCalled = true; },
    setExitCode() {},
  });

  assert.equal(code, EXIT.usage);
  assert.equal(scannerCalled, false);
  assert.equal(writerCalled, false);
  assert.match(stderr.text(), /does not appear to be a website project/);
  assert.match(stderr.text(), /No report was created/);
});

test("successful CLI runs exclude an in-repository custom report directory", async (t) => {
  const root = await temporaryDirectory(t);
  const output = path.join(root, "audit-output");
  const stdout = captureStream();
  const stderr = captureStream();
  let collectionOptions;
  let writerOptions;

  const code = await runCli([
    "check", "mysite", "--root", root, "--output", "audit-output",
  ], {
    stdout,
    stderr,
    collectFiles: async (_root, options) => {
      collectionOptions = options;
      return { files: [], skipped: {} };
    },
    detectWebProject: async () => ({ isWebsite: true, framework: "Test", confidence: 1 }),
    runSiteScan: async () => scanResult(root),
    writeScanReports: async (_result, options) => {
      writerOptions = options;
      return [path.join(output, "00-overview.md")];
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.ok);
  assert.deepEqual(collectionOptions.excludeDirectories, [output]);
  assert.equal(writerOptions.outputDirectory, output);
  assert.equal(stderr.text(), "");
  assert.doesNotMatch(stdout.text(), /\u001b\[/);
});

test("CLI reports only marker-owned generated directories outside the selected output", async (t) => {
  const root = await temporaryDirectory(t);
  const generatedDirectory = path.join(root, "web", "Modular");
  const userDirectory = path.join(root, "notes", "Modular");
  await fs.mkdir(generatedDirectory, { recursive: true });
  await fs.mkdir(userDirectory, { recursive: true });
  const generatedReport = path.join(generatedDirectory, "03-site-report.md");
  const userReport = path.join(userDirectory, "03-site-report.md");
  await fs.writeFile(generatedReport, `${REPORT_MARKER}\n# Older report\n`);
  await fs.writeFile(userReport, "# User-authored notes\n");
  const stdout = captureStream();
  let writtenResult;

  const code = await runCli(["check", "mysite", "--root", root, "--no-color"], {
    stdout,
    stderr: captureStream(),
    collectFiles: async () => ({
      files: [
        { absolute: generatedReport, relative: "web/Modular/03-site-report.md" },
        { absolute: userReport, relative: "notes/Modular/03-site-report.md" },
      ],
      skipped: {},
    }),
    detectWebProject: async () => ({ isWebsite: true, framework: "Test", confidence: 1 }),
    runSiteScan: async () => scanResult(root),
    writeScanReports: async (result) => {
      writtenResult = result;
      return [];
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.ok);
  assert.match(stdout.text(), /1 other Modular-generated report directory was found/i);
  assert.match(stdout.text(), /web\/Modular/);
  assert.doesNotMatch(stdout.text(), /notes\/Modular/);
  assert.equal(writtenResult.metadata.reporting.outputDirectory, "Modular");
  assert.deepEqual(writtenResult.metadata.reporting.otherGeneratedReportDirectories, ["web/Modular"]);
});

test("an application directory cannot be hidden from scanning through --output", async (t) => {
  const root = await temporaryDirectory(t);
  const source = path.join(root, "src");
  await fs.mkdir(source);
  await fs.writeFile(path.join(source, "App.jsx"), "export const App = ({ html }) => <main dangerouslySetInnerHTML={{ __html: html }} />;");
  let collectorCalled = false;

  const code = await runCli(["check", "security", "--root", root, "--output", "src", "--quiet"], {
    stdout: captureStream(),
    stderr: captureStream(),
    collectFiles: async () => {
      collectorCalled = true;
      return { files: [], skipped: {} };
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.usage);
  assert.equal(collectorCalled, false);
});

test("a canonical report filename without Modular's marker is never overwritten", async (t) => {
  const root = await temporaryDirectory(t);
  const output = path.join(root, "Modular");
  await fs.mkdir(output);
  const userReport = path.join(output, "00-overview.md");
  await fs.writeFile(userReport, "# My project notes\n\nDo not replace this file.\n");
  let collectorCalled = false;

  const code = await runCli(["check", "mysite", "--root", root, "--quiet"], {
    stdout: captureStream(),
    stderr: captureStream(),
    collectFiles: async () => {
      collectorCalled = true;
      return { files: [], skipped: {} };
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.usage);
  assert.equal(collectorCalled, false);
  assert.match(await fs.readFile(userReport, "utf8"), /Do not replace this file/);
});

test("an external output directory cannot overwrite a user-owned canonical filename", async (t) => {
  const root = await temporaryDirectory(t);
  const output = await temporaryDirectory(t, "modular-external-output-");
  const userReport = path.join(output, "03-site-report.md");
  await fs.writeFile(userReport, "# Independent notes\n");
  let collectorCalled = false;

  const code = await runCli(["check", "mysite", "--root", root, "--output", output, "--quiet"], {
    stdout: captureStream(),
    stderr: captureStream(),
    collectFiles: async () => {
      collectorCalled = true;
      return { files: [], skipped: {} };
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.usage);
  assert.equal(collectorCalled, false);
  assert.equal(await fs.readFile(userReport, "utf8"), "# Independent notes\n");
});

test("dedicated output names follow the host filesystem's case semantics", async (t) => {
  const root = await temporaryDirectory(t);
  const output = path.join(root, "Modular");
  await fs.mkdir(output);
  await fs.writeFile(
    path.join(output, "01-SECURITY-REPORT.md"),
    "<!-- Generated by Modular. Changes to this file may be replaced by the next scan. -->\n",
  );
  let collectorCalled = false;

  const code = await runCli(["check", "security", "--root", root, "--quiet"], {
    stdout: captureStream(),
    stderr: captureStream(),
    collectFiles: async () => {
      collectorCalled = true;
      return { files: [], skipped: {} };
    },
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSecurityScan: async () => scanResult(root, [], "security"),
    writeScanReports: async () => [],
    setExitCode() {},
  });

  if (process.platform === "win32") {
    assert.equal(code, EXIT.ok);
    assert.equal(collectorCalled, true);
  } else {
    assert.equal(code, EXIT.usage);
    assert.equal(collectorCalled, false);
  }
});

test("check all discovers once, runs both phases and lists no more than five reports", async (t) => {
  const root = await temporaryDirectory(t);
  const stdout = captureStream();
  const calls = [];
  const scannerOptions = [];
  let collections = 0;
  let detections = 0;

  const makeRunner = (mode) => async ({ onProgress, options }) => {
    calls.push(mode);
    scannerOptions.push([mode, options.auditDependencies]);
    await onProgress({ current: 1, total: 1, phase: mode, file: `src/${mode}.js`, check: "analysis" });
    const result = scanResult(root, [], mode);
    if (mode === "security") result.metadata.dependencyAudit = { status: "completed" };
    return result;
  };

  const code = await runCli(["check", "all", "--root", root, "--dependency-audit"], {
    stdout,
    stderr: captureStream(),
    collectFiles: async () => {
      collections += 1;
      return { files: [], skipped: {} };
    },
    detectWebProject: async () => {
      detections += 1;
      return { isWebsite: true, framework: "Test", confidence: 1 };
    },
    runSecurityScan: makeRunner("security"),
    runSiteScan: makeRunner("mysite"),
    writeScanReports: async (result) => [
      path.join(root, "Modular", "00-overview.md"),
      path.join(root, "Modular", result.mode === "security" ? "01-security-report.md" : "03-site-report.md"),
      path.join(root, "Modular", result.mode === "security" ? "02-security-action-plan.md" : "04-site-action-plan.md"),
    ],
    setExitCode() {},
  });

  assert.equal(code, EXIT.ok);
  assert.equal(collections, 1);
  assert.equal(detections, 1);
  assert.deepEqual(calls, ["security", "mysite"]);
  assert.deepEqual(scannerOptions, [["security", true], ["mysite", false]]);
  assert.match(stdout.text(), /Phase 1 of 2/);
  assert.match(stdout.text(), /\[100%\] 1\/2 security — src\/security\.js/);
  const listedReports = stdout.text().split(/\r?\n/).filter((line) => line.includes("→ Modular/") || line.includes("-> Modular/"));
  assert.equal(listedReports.length, 5);
});

test("check all identifies reports preserved when a later phase fails", async (t) => {
  const root = await temporaryDirectory(t);
  const stderr = captureStream();
  const securityReport = path.join(root, "Modular", "01-security-report.md");

  const code = await runCli(["check", "all", "--root", root, "--quiet"], {
    stdout: captureStream(),
    stderr,
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSecurityScan: async () => scanResult(root, [], "security"),
    runSiteScan: async () => { throw new Error("site phase exploded"); },
    writeScanReports: async () => [securityReport],
    setExitCode() {},
  });

  assert.equal(code, EXIT.failed);
  assert.match(stderr.text(), /site phase exploded/);
  assert.match(stderr.text(), /Completed phase reports were preserved/);
  assert.match(stderr.text(), /Modular/);
});

test("fail-on returns exit 3 after reports have been written", async (t) => {
  const root = await temporaryDirectory(t);
  let writerCalled = false;
  const finding = createFinding({
    id: "example",
    title: "Example",
    category: "Security",
    severity: "high",
  });

  const code = await runCli([
    "check", "mysite", "--root", root, "--fail-on", "medium", "--quiet",
  ], {
    stdout: captureStream(),
    stderr: captureStream(),
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSiteScan: async () => scanResult(root, [finding]),
    writeScanReports: async () => {
      writerCalled = true;
      return [];
    },
    setExitCode() {},
  });

  assert.equal(writerCalled, true);
  assert.equal(code, EXIT.threshold);
});

test("an interrupt waits for an in-flight report write and reports preserved output", async (t) => {
  const root = await temporaryDirectory(t);
  const controller = new AbortController();
  const stderr = captureStream();
  const reportPath = path.join(root, "Modular", "01-security-report.md");
  let writerFinished = false;

  const code = await runCli(["check", "security", "--root", root], {
    signal: controller.signal,
    stdout: captureStream(),
    stderr,
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSecurityScan: async () => scanResult(root, [], "security"),
    writeScanReports: async () => {
      controller.abort({ signal: "SIGINT" });
      writerFinished = true;
      return [reportPath];
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.sigint);
  assert.equal(writerFinished, true);
  assert.match(stderr.text(), /interrupted by SIGINT/i);
  assert.match(stderr.text(), /completed phase reports were preserved/i);
});

test("a pre-aborted scan stops before repository work and exits 130", async (t) => {
  const root = await temporaryDirectory(t);
  const controller = new AbortController();
  controller.abort({ signal: "SIGINT" });
  const stderr = captureStream();
  let collectorCalled = false;

  const code = await runCli(["check", "security", "--root", root], {
    signal: controller.signal,
    stdout: captureStream(),
    stderr,
    collectFiles: async () => {
      collectorCalled = true;
      return { files: [], skipped: {} };
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.sigint);
  assert.equal(collectorCalled, false);
  assert.match(stderr.text(), /interrupted by SIGINT/i);
});

test("an explicitly requested incomplete dependency audit exits 1 after preserving reports", async (t) => {
  const root = await temporaryDirectory(t);
  const stdout = captureStream();
  const stderr = captureStream();
  let writerCalled = false;
  const incomplete = scanResult(root, [], "security");
  incomplete.metadata.dependencyAudit = { status: "unavailable", reason: "manager missing" };

  const code = await runCli(["check", "security", "--root", root, "--dependency-audit"], {
    stdout,
    stderr,
    collectFiles: async () => ({ files: [], skipped: {} }),
    detectWebProject: async () => ({ isWebsite: true, confidence: 1 }),
    runSecurityScan: async () => incomplete,
    writeScanReports: async () => {
      writerCalled = true;
      return [path.join(root, "Modular", "00-overview.md")];
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.failed);
  assert.equal(writerCalled, true);
  assert.match(stdout.text(), /exit with code 1/i);
  assert.match(stderr.text(), /did not complete/i);
});

test("file-count truncation fails instead of presenting a partial scan as complete", async (t) => {
  const root = await temporaryDirectory(t);
  const stderr = captureStream();
  let detectorCalled = false;
  const code = await runCli(["check", "security", "--root", root, "--max-files", "2"], {
    stdout: captureStream(),
    stderr,
    collectFiles: async () => ({ files: [], skipped: { limit: 1 } }),
    detectWebProject: async () => {
      detectorCalled = true;
      return { isWebsite: true };
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.failed);
  assert.equal(detectorCalled, false);
  assert.match(stderr.text(), /exceeds the 2-file safety limit/);
});

test("total readable-byte truncation fails before detection or partial reports", async (t) => {
  const root = await temporaryDirectory(t);
  const stderr = captureStream();
  let detectorCalled = false;
  const code = await runCli(["check", "security", "--root", root, "--max-total-size", "1024"], {
    stdout: captureStream(),
    stderr,
    collectFiles: async () => ({ files: [], skipped: { totalBytes: 1 } }),
    detectWebProject: async () => {
      detectorCalled = true;
      return { isWebsite: true };
    },
    setExitCode() {},
  });

  assert.equal(code, EXIT.failed);
  assert.equal(detectorCalled, false);
  assert.match(stderr.text(), /1024-byte total readable-source safety limit/);
});

test("non-TTY progress is color-free and terminal-control safe", () => {
  const stream = captureStream();
  const ui = new TerminalUI({ stream, color: true });
  ui.banner();
  ui.progress({ current: 1, total: 2, phase: "Scan\nphase", file: "src/good.js\n\u001b[31mbad" });
  ui.reportPaths([path.join("repo", "safe\n\u001b[31mreport.md")], "repo");

  assert.doesNotMatch(stream.text(), /\u001b\[/);
  assert.match(stream.text(), /\[ 50%\] Scan phase — src\/good\.js �\[31mbad/);
  assert.match(stream.text(), /safe �\[31mreport\.md/);
});

test("non-interactive output uses a compact accessible banner", () => {
  const stream = captureStream();
  new TerminalUI({ stream, color: true }).banner();

  assert.match(stream.text(), /M O D U L A R.*Repository intelligence/);
  assert.doesNotMatch(stream.text(), /⣿⣿⣿/);
  assert.doesNotMatch(stream.text(), /\u001b\[/);
});

test("TERM=dumb disables terminal control sequences even for a TTY stream", () => {
  const stream = captureStream({ isTTY: true, columns: 80 });
  const ui = new TerminalUI({ stream, color: true, environment: { TERM: "dumb" } });
  ui.banner();
  ui.progress({ current: 1, total: 2, phase: "Scan", file: "src/app.js" });

  assert.doesNotMatch(stream.text(), /\u001b\[/);
  assert.doesNotMatch(stream.text(), /⣿⣿⣿/);
  assert.match(stream.text(), /\[ 50%\] Scan — src\/app\.js/);
});

test("redirected stderr stays ANSI-free when stdout is a TTY", () => {
  let errors = "";
  const stdout = { isTTY: true, columns: 88, write() {} };
  const stderr = { isTTY: false, write(value) { errors += value; } };
  const ui = new TerminalUI({ stream: stdout, errorStream: stderr, color: true });

  ui.failure("failed safely");

  assert.match(errors, /failed safely/);
  assert.doesNotMatch(errors, /\u001b\[/);
});

test("interactive terminal banner uses the verified high-resolution raster-derived logo", async () => {
  const source = await fs.readFile(new URL("../assets/modular-logo.png", import.meta.url));
  const sourceHash = createHash("sha256").update(source).digest("hex");
  const artHash = createHash("sha256").update(MODULAR_BRAILLE_LOGO.join("\n")).digest("hex");
  assert.equal(sourceHash, MODULAR_LOGO_SOURCE.sha256);
  assert.equal(artHash, MODULAR_LOGO_SOURCE.terminalArtSha256);
  assert.deepEqual(MODULAR_LOGO_SOURCE.dotRaster, [84, 96]);
  assert.equal(MODULAR_BRAILLE_LOGO.length, 24);
  assert.ok(MODULAR_BRAILLE_LOGO.some((line) => line.includes("⣿⣿⣿")));

  const stream = captureStream({ isTTY: true });
  new TerminalUI({ stream, color: false, environment: {} }).banner();
  for (const row of MODULAR_BRAILLE_LOGO) assert.ok(stream.text().includes(row));
  assert.doesNotMatch(stream.text(), /╭───╱/);

  const visibleLines = stream.text().split(/\r?\n/).filter(Boolean);
  assert.ok(visibleLines.every((line) => [...line].length <= 48), visibleLines.join("\n"));
});

test("narrow TTY progress never emits a visible line wider than the terminal", () => {
  const stream = captureStream({ isTTY: true, columns: 28 });
  const ui = new TerminalUI({ stream, color: false, environment: {} });
  ui.progress({
    current: 50,
    total: 100,
    phase: "Website accessibility audit",
    file: "src/components/a/very/deep/path/NavigationMenu.tsx",
    check: "static analysis",
  });

  const visibleLines = stream.text()
    .replace(/\u001b\[[0-9;]*[A-Za-z]/g, "")
    .split(/\r?\n/)
    .map((line) => line.replace(/^\r/, ""))
    .filter(Boolean);
  assert.ok(visibleLines.length >= 2);
  assert.ok(visibleLines.every((line) => [...line].length <= 28), visibleLines.join("\n"));
});

test("TTY progress reserves space for the check label without wrapping", () => {
  const stream = captureStream({ isTTY: true, columns: 48 });
  const ui = new TerminalUI({ stream, color: true, environment: {} });
  ui.progress({
    current: 50,
    total: 100,
    phase: "Website audit",
    file: "src/components/a/very/deep/path/NavigationMenu.tsx",
    check: "static analysis",
  });

  const visibleLines = stream.text()
    .replace(/\u001b\[[0-9;]*[A-Za-z]/g, "")
    .split(/\r?\n/)
    .map((line) => line.replace(/^\r/, ""))
    .filter(Boolean);
  assert.ok(visibleLines.length >= 2);
  assert.ok(visibleLines.every((line) => line.length <= 48), visibleLines.join("\n"));
});

test("collector excludes custom output trees and rejects invalid safety limits", async (t) => {
  const root = await temporaryDirectory(t, "modular-files-");
  const output = path.join(root, "reports");
  await fs.mkdir(output);
  await fs.mkdir(path.join(root, "src", "Modular"), { recursive: true });
  await fs.writeFile(path.join(root, "index.html"), "<main>Hello</main>");
  await fs.writeFile(path.join(output, "old.md"), "old report");
  await fs.writeFile(path.join(root, "src", "Modular", "live.js"), "export const live = true;");

  const inventory = await collectFiles(root, { excludeDirectories: [output] });
  assert.deepEqual(inventory.files.map((file) => file.relative), ["index.html", "src/Modular/live.js"]);
  await assert.rejects(collectFiles(root, { maxFiles: 0 }), /positive integer/);
  await assert.rejects(collectFiles(root, { maxFileBytes: Number.POSITIVE_INFINITY }), /positive integer/);
  await assert.rejects(collectFiles(root, { maxTotalBytes: 0 }), /positive integer/);
});

test("collector enforces an aggregate readable-byte budget", async (t) => {
  const root = await temporaryDirectory(t, "modular-byte-limit-");
  await fs.writeFile(path.join(root, "a.js"), "12345678");
  await fs.writeFile(path.join(root, "b.js"), "abcdefgh");

  const inventory = await collectFiles(root, { maxTotalBytes: 12 });

  assert.deepEqual(inventory.files.map((file) => file.relative), ["a.js"]);
  assert.equal(inventory.totalReadableBytes, 8);
  assert.equal(inventory.maxTotalBytes, 12);
  assert.equal(inventory.skipped.totalBytes, 1);
});

test("reader rejects a file whose size changed after the aggregate budget was measured", async (t) => {
  const root = await temporaryDirectory(t, "modular-byte-race-");
  const source = path.join(root, "app.js");
  await fs.writeFile(source, "export const value = 1;");
  const inventory = await collectFiles(root, { maxTotalBytes: 1024 });
  await fs.appendFile(source, "\nexport const changed = true;");

  assert.equal(await readTextFile(inventory.files[0]), null);
});

test("reader rejects same-size mutations made after repository discovery", async (t) => {
  const root = await temporaryDirectory(t, "modular-identity-race-");
  const source = path.join(root, "app.js");
  await fs.writeFile(source, "export const value = 1;");
  const inventory = await collectFiles(root, { maxTotalBytes: 1024 });
  await fs.writeFile(source, "export const value = 2;");

  assert.equal(await readTextFile(inventory.files[0], { root }), null);
});

test("reader confines externally supplied descriptors to the declared repository root", async (t) => {
  const root = await temporaryDirectory(t, "modular-reader-root-");
  const outside = await temporaryDirectory(t, "modular-reader-outside-");
  const insideSource = path.join(root, "app.js");
  const outsideSource = path.join(outside, "secret.js");
  await fs.writeFile(insideSource, "export const safe = true;");
  await fs.writeFile(outsideSource, "const password = 'outside';");
  const inventory = await collectFiles(root);

  assert.equal(await readTextFile(inventory.files[0], { root }), "export const safe = true;");
  assert.equal(await readTextFile({
    absolute: outsideSource,
    relative: "src/forged.js",
    name: "forged.js",
    extension: ".js",
  }, { root }), null);
});

test("collector does not follow repository links and reports the coverage gap", async (t) => {
  const root = await temporaryDirectory(t, "modular-linked-root-");
  const outside = await temporaryDirectory(t, "modular-linked-outside-");
  await fs.writeFile(path.join(root, "index.html"), "<main>Hello</main>");
  await fs.writeFile(path.join(outside, "secret.js"), "const password = 'not-scanned';");
  const linkedSource = path.join(root, "linked-src");
  try {
    await fs.symlink(outside, linkedSource, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "UNKNOWN"].includes(error?.code)) {
      t.skip(`directory links are unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  const inventory = await collectFiles(root);

  assert.deepEqual(inventory.files.map((file) => file.relative), ["index.html"]);
  assert.equal(inventory.skipped.links, 1);
});

test("file safety limit also bounds binary and skipped file entries", async (t) => {
  const root = await temporaryDirectory(t, "modular-binary-limit-");
  await Promise.all([
    fs.writeFile(path.join(root, "a.png"), Buffer.from([0, 1, 2])),
    fs.writeFile(path.join(root, "b.png"), Buffer.from([0, 1, 2])),
    fs.writeFile(path.join(root, "c.png"), Buffer.from([0, 1, 2])),
  ]);

  const inventory = await collectFiles(root, { maxFiles: 2 });

  assert.equal(inventory.files.length, 2);
  assert.equal(inventory.files.every((file) => file.assetMetadata && file.contentReadable === false), true);
  assert.equal(inventory.skipped.binary, 2);
  assert.equal(inventory.skipped.assetMetadata, 2);
  assert.equal(inventory.skipped.limit, 1);
});
