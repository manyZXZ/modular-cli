import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildScanResult, createFinding } from "../src/core/model.js";
import {
  REPORT_FILES,
  REPORT_LOCK_FILE,
  REPORT_LOCK_MARKER,
  renderDetailedReport,
  writeScanReports,
} from "../src/core/reporter.js";

async function temporaryDirectory(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-reporter-hardening-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

function result(root, mode, findings = [], title = `${mode} report`) {
  return buildScanResult({
    mode,
    title,
    root,
    findings,
    checks: 3,
    filesScanned: 1,
    startedAt: Date.now() - 5,
    metadata: { coverage: ["source"] },
  });
}

async function waitForFile(filePath, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await fs.access(filePath);
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${filePath}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function runReporterChild(root, outputDirectory, coordinationDirectory, role) {
  const source = String.raw`
import { promises as fs } from "node:fs";
import path from "node:path";
import { buildScanResult } from "./src/core/model.js";
import { writeScanReports } from "./src/core/reporter.js";
const [root, outputDirectory, coordinationDirectory, role] = process.argv.slice(1);
await fs.writeFile(path.join(coordinationDirectory, role + ".started"), "started");
const originalRename = fs.rename.bind(fs);
let paused = false;
fs.rename = async (source, destination) => {
  if (role === "A" && !paused && String(source).endsWith(".tmp")) {
    paused = true;
    await fs.writeFile(path.join(coordinationDirectory, "A.ready"), "ready");
    const release = path.join(coordinationDirectory, "A.release");
    const deadline = Date.now() + 5000;
    for (;;) {
      try { await fs.access(release); break; }
      catch (error) { if (error?.code !== "ENOENT") throw error; }
      if (Date.now() >= deadline) throw new Error("child coordination timeout");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
  return originalRename(source, destination);
};
const scan = buildScanResult({
  mode: "security", title: "Process " + role, root, findings: [], checks: 3,
  filesScanned: 1, startedAt: Date.now() - 5, metadata: { coverage: ["source"] },
});
await writeScanReports(scan, { outputDirectory });
`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", source, root, outputDirectory, coordinationDirectory, role], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const completed = new Promise((resolve) => child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr })));
  return { child, completed };
}

test("Markdown rendering contains untrusted values without creating injected blocks or HTML", () => {
  const finding = createFinding({
    id: "rule`\n## forged rule",
    title: "Unsafe\n# forged heading <script>alert(1)</script>",
    category: "Category\n---",
    severity: "high",
    description: "Description\r\n<img src=x onerror=alert(1)>",
    recommendation: "Use [trusted](javascript:alert(1)) input.",
    evidence: "value ``` tail",
    file: "src/file`\n# forged.js",
    line: 4,
    suggestedFiles: ["src/fix`here.js"],
  });

  const markdown = renderDetailedReport(result("C:\\repo`name", "security", [finding], "Title\n# forged"));

  assert.doesNotMatch(markdown, /\n# forged/);
  assert.doesNotMatch(markdown, /<script>|<img/);
  assert.doesNotMatch(markdown, /(^|[^\\])\]\(javascript:/m);
  assert.match(markdown, /````value ``` tail````/);
  assert.match(markdown, /&lt;script&gt;/);
});

test("report rendering applies a final credential-redaction boundary", () => {
  const token = "correct horse battery staple!";
  const finding = createFinding({
    id: "site-example",
    title: "Site example",
    category: "Accessibility",
    severity: "medium",
    evidence: `<img data-password="${token}">`,
  });

  const markdown = renderDetailedReport(result("C:\\repo", "mysite", [finding]));
  assert.match(markdown, /redacted/i);
  assert.doesNotMatch(markdown, new RegExp(token));
});

test("report rendering preserves exact long repository and source paths", () => {
  const root = "C:\\Users\\Ata\\Documents\\ChatGPT\\Modular";
  const sourcePath = "src/features/auth/components/LoginForm.tsx";
  const finding = createFinding({
    id: "path-example",
    title: "Path example",
    category: "Security",
    severity: "medium",
    file: sourcePath,
    line: 12,
    suggestedFiles: [sourcePath, "public/assets/0123456789abcdef0123456789abcdef.svg"],
  });

  const markdown = renderDetailedReport(result(root, "security", [finding]));
  assert.ok(markdown.includes(root));
  assert.ok(markdown.includes(`${sourcePath}:12`));
  assert.ok(markdown.includes("public/assets/0123456789abcdef0123456789abcdef.svg"));
});

test("security reports state when dependency advisory lookup was skipped", () => {
  const scan = result("C:\\repo", "security");
  scan.metadata.dependencyAudit = {
    status: "skipped",
    reason: "disabled (opt in with auditDependencies: true)",
  };

  const markdown = renderDetailedReport(scan);
  assert.match(markdown, /Dependency advisory lookup:\*\* skipped/i);
  assert.match(markdown, /opt in/i);
});

test("report writer refuses to replace a user-owned canonical report file", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  await fs.mkdir(outputDirectory);
  const userFile = path.join(outputDirectory, REPORT_FILES.overview);
  await fs.writeFile(userFile, "# My notes\n");

  await assert.rejects(
    writeScanReports(result(root, "security"), { outputDirectory }),
    /not generated by Modular/i,
  );
  assert.equal(await fs.readFile(userFile, "utf8"), "# My notes\n");
  assert.deepEqual(await fs.readdir(outputDirectory), [REPORT_FILES.overview]);
});

test("repeated and concurrent report writes overwrite cleanly without temporary artifacts", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  const first = result(root, "security", [], "First report");
  const second = result(root, "security", [], "Second report");

  await writeScanReports(first, { outputDirectory });
  await writeScanReports(second, { outputDirectory });
  await Promise.all([
    writeScanReports(result(root, "security", [], "Concurrent A"), { outputDirectory }),
    writeScanReports(result(root, "security", [], "Concurrent B"), { outputDirectory }),
  ]);

  const names = await fs.readdir(outputDirectory);
  assert.deepEqual(names.filter((name) => name.endsWith(".md")).sort(), [
    REPORT_FILES.overview,
    ...REPORT_FILES.security,
  ].sort());
  assert.equal(names.some((name) => name.endsWith(".tmp")), false);

  for (const name of names) {
    const contents = await fs.readFile(path.join(outputDirectory, name), "utf8");
    assert.match(contents, /Generated by Modular/);
  }

  const detailed = await fs.readFile(path.join(outputDirectory, REPORT_FILES.security[0]), "utf8");
  const action = await fs.readFile(path.join(outputDirectory, REPORT_FILES.security[1]), "utf8");
  const overview = await fs.readFile(path.join(outputDirectory, REPORT_FILES.overview), "utf8");
  const committedTitle = detailed.includes("Concurrent A") ? "Concurrent A" : "Concurrent B";
  assert.ok([detailed, action, overview].every((contents) => contents.includes(committedTitle)));
});

test("separate writer processes cannot publish a mixed report set", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  const coordinationDirectory = path.join(root, "coordination");
  await fs.mkdir(coordinationDirectory);

  const first = runReporterChild(root, outputDirectory, coordinationDirectory, "A");
  t.after(() => first.child.kill());
  await waitForFile(path.join(coordinationDirectory, "A.ready"));
  const second = runReporterChild(root, outputDirectory, coordinationDirectory, "B");
  t.after(() => second.child.kill());
  await waitForFile(path.join(coordinationDirectory, "B.started"));
  // Without the cross-process lock B can complete while A is paused between
  // per-file promotions, after which A rolls back or leaves a mixed set.
  await new Promise((resolve) => setTimeout(resolve, 150));
  await fs.writeFile(path.join(coordinationDirectory, "A.release"), "release");

  const completed = await Promise.all([first.completed, second.completed]);
  assert.deepEqual(completed.map(({ code }) => code), [0, 0], JSON.stringify(completed));
  const canonical = [REPORT_FILES.security[0], REPORT_FILES.security[1], REPORT_FILES.overview];
  const contents = await Promise.all(canonical.map((name) => fs.readFile(path.join(outputDirectory, name), "utf8")));
  const identities = new Set(contents.map((value) => value.includes("Process A") ? "A" : value.includes("Process B") ? "B" : "unknown"));
  assert.deepEqual([...identities], ["B"]);
  assert.equal((await fs.readdir(outputDirectory)).includes(REPORT_LOCK_FILE), false);
});

test("a stale lock from a proven-dead local owner is recovered", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  await fs.mkdir(outputDirectory);
  const exited = spawn(process.execPath, ["-e", ""]);
  const deadPid = exited.pid;
  await new Promise((resolve) => exited.on("close", resolve));
  const lockPath = path.join(outputDirectory, REPORT_LOCK_FILE);
  const oldTime = new Date(Date.now() - 60_000);
  await fs.writeFile(lockPath, `${JSON.stringify({
    marker: REPORT_LOCK_MARKER,
    token: "stale-lock-owner-token",
    pid: deadPid,
    hostname: os.hostname(),
    createdAt: oldTime.getTime(),
  })}\n`);
  await fs.utimes(lockPath, oldTime, oldTime);

  await writeScanReports(result(root, "security", [], "Recovered report"), {
    outputDirectory,
    reportLockStaleMs: 10,
    reportLockTimeoutMs: 1_000,
  });

  assert.equal((await fs.readdir(outputDirectory)).includes(REPORT_LOCK_FILE), false);
  assert.match(await fs.readFile(path.join(outputDirectory, REPORT_FILES.security[0]), "utf8"), /Recovered report/);
});

test("a live owner lock is never reaped and times out with its metadata intact", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  await fs.mkdir(outputDirectory);
  const lockPath = path.join(outputDirectory, REPORT_LOCK_FILE);
  const owner = `${JSON.stringify({
    marker: REPORT_LOCK_MARKER,
    token: "currently-live-owner-token",
    pid: process.pid,
    hostname: os.hostname(),
    createdAt: Date.now() - 60_000,
  })}\n`;
  await fs.writeFile(lockPath, owner);
  const oldTime = new Date(Date.now() - 60_000);
  await fs.utimes(lockPath, oldTime, oldTime);

  await assert.rejects(
    writeScanReports(result(root, "security"), {
      outputDirectory,
      reportLockStaleMs: 0,
      reportLockTimeoutMs: 75,
    }),
    (error) => error?.code === "REPORT_LOCK_TIMEOUT",
  );
  assert.equal(await fs.readFile(lockPath, "utf8"), owner);
  assert.deepEqual(await fs.readdir(outputDirectory), [REPORT_LOCK_FILE]);
});

test("a failed report-set promotion restores every previously published report", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  await writeScanReports(result(root, "security", [], "Stable report"), { outputDirectory });

  const canonicalNames = [REPORT_FILES.overview, ...REPORT_FILES.security];
  const before = new Map(await Promise.all(canonicalNames.map(async (name) => [
    name,
    await fs.readFile(path.join(outputDirectory, name), "utf8"),
  ])));
  const originalRename = fs.rename.bind(fs);
  const overviewPath = path.resolve(outputDirectory, REPORT_FILES.overview);
  let injected = false;
  t.mock.method(fs, "rename", async (source, destination) => {
    if (!injected && String(source).endsWith(".tmp") && path.resolve(destination) === overviewPath) {
      injected = true;
      throw Object.assign(new Error("injected overview promotion failure"), { code: "EIO" });
    }
    return originalRename(source, destination);
  });

  await assert.rejects(
    writeScanReports(result(root, "security", [], "Replacement report"), { outputDirectory }),
    /injected overview promotion failure/,
  );
  assert.equal(injected, true);
  for (const name of canonicalNames) {
    assert.equal(await fs.readFile(path.join(outputDirectory, name), "utf8"), before.get(name));
  }
  const names = await fs.readdir(outputDirectory);
  assert.equal(names.some((name) => /\.(?:tmp|bak)$/.test(name)), false);
});

test("a failed first report-set promotion publishes no partial report set", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  const originalRename = fs.rename.bind(fs);
  const actionPath = path.resolve(outputDirectory, REPORT_FILES.security[1]);
  let injected = false;
  t.mock.method(fs, "rename", async (source, destination) => {
    if (!injected && String(source).endsWith(".tmp") && path.resolve(destination) === actionPath) {
      injected = true;
      throw Object.assign(new Error("injected action promotion failure"), { code: "EIO" });
    }
    return originalRename(source, destination);
  });

  await assert.rejects(
    writeScanReports(result(root, "security", [], "Incomplete report"), { outputDirectory }),
    /injected action promotion failure/,
  );
  assert.equal(injected, true);
  assert.deepEqual(await fs.readdir(outputDirectory), []);
});

test("running both modes repeatedly never creates more than five generated Markdown files", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");

  for (let index = 0; index < 3; index += 1) {
    await writeScanReports(result(root, "security"), { outputDirectory });
    await writeScanReports(result(root, "mysite"), { outputDirectory });
  }

  const markdown = (await fs.readdir(outputDirectory)).filter((name) => name.endsWith(".md"));
  assert.equal(markdown.length, 5);
  assert.deepEqual(markdown.sort(), [
    REPORT_FILES.overview,
    ...REPORT_FILES.security,
    ...REPORT_FILES.mysite,
  ].sort());
  assert.throws(() => REPORT_FILES.security.push("05-extra.md"), TypeError);
});

test("a combined run summarizes both scan scores in the single overview", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  const security = result(root, "security", [], "Modular Security Check");
  const mysite = result(root, "mysite", [], "Website quality report");

  await writeScanReports(security, { outputDirectory, overviewResults: [security] });
  await writeScanReports(mysite, { outputDirectory, overviewResults: [security, mysite] });

  const overview = await fs.readFile(path.join(outputDirectory, REPORT_FILES.overview), "utf8");
  const detailed = await fs.readFile(path.join(outputDirectory, REPORT_FILES.security[0]), "utf8");
  assert.match(overview, /Combined run complete/);
  assert.match(overview, /\| Modular Security Check \| \*\*100\/100\*\*/);
  assert.match(overview, /\| Website quality report \| \*\*100\/100\*\*/);
  assert.equal((overview.match(/## Scan summary/g) ?? []).length, 1);
  assert.match(detailed, /^# Modular Security Check$/m);
  assert.doesNotMatch(detailed, /Modular Modular/);
});

test("a combined overview reports shared stale directories only once", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  const security = result(root, "security", [], "Modular Security Check");
  const mysite = result(root, "mysite", [], "Modular Website Check");
  for (const scan of [security, mysite]) {
    scan.metadata.reporting = { otherGeneratedReportDirectories: ["web/Modular"] };
  }

  await writeScanReports(security, { outputDirectory, overviewResults: [security] });
  await writeScanReports(mysite, { outputDirectory, overviewResults: [security, mysite] });

  const overview = await fs.readFile(path.join(outputDirectory, REPORT_FILES.overview), "utf8");
  assert.equal((overview.match(/other Modular-generated report directory was not updated by this run and may be stale/g) ?? []).length, 1);
  assert.doesNotMatch(overview, /Modular Security Check: 1 other Modular-generated report directory/);
  assert.doesNotMatch(overview, /Modular Website Check: 1 other Modular-generated report directory/);
});

test("a standalone run labels marker-owned reports from an earlier mode as not refreshed", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  await writeScanReports(result(root, "security"), { outputDirectory });
  await writeScanReports(result(root, "mysite"), { outputDirectory });

  const overview = await fs.readFile(path.join(outputDirectory, REPORT_FILES.overview), "utf8");
  const refreshed = overview.match(/### Refreshed by this run([\s\S]*?)(?:\n### |\n## |$)/)?.[1] ?? "";
  const earlier = overview.match(/### Earlier generated reports — not refreshed([\s\S]*?)(?:\n## |$)/)?.[1] ?? "";
  assert.match(refreshed, /Site report/);
  assert.doesNotMatch(refreshed, /Security report/);
  assert.match(earlier, /Security report/);
  assert.match(overview, /2 marker-owned report files.*not refreshed/i);
  assert.match(overview, /not a finding count, backlog size, or effort estimate/i);
});

test("an invalid report mode fails before creating the output directory", async (t) => {
  const root = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "should-not-exist");
  const invalid = result(root, "unknown");

  await assert.rejects(writeScanReports(invalid, { outputDirectory }), /No report mapping/);
  await assert.rejects(fs.access(outputDirectory));
});

test("an in-repository report symlink or junction cannot redirect writes outside the repository", async (t) => {
  const root = await temporaryDirectory(t);
  const outside = await temporaryDirectory(t);
  const outputDirectory = path.join(root, "Modular");
  try {
    await fs.symlink(outside, outputDirectory, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "UNKNOWN"].includes(error?.code)) {
      t.skip(`directory links are unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  await assert.rejects(
    writeScanReports(result(root, "security"), { outputDirectory }),
    (error) => error?.code === "UNSAFE_OUTPUT_PATH" && /symbolic link|junction/i.test(error.message),
  );
  assert.deepEqual(await fs.readdir(outside), []);
});

test("an explicitly supplied absolute output outside the repository remains supported", async (t) => {
  const root = await temporaryDirectory(t);
  const outside = await temporaryDirectory(t);

  const reports = await writeScanReports(result(root, "security"), { outputDirectory: outside });

  assert.equal(reports.length, 3);
  assert.ok((await fs.readdir(outside)).includes(REPORT_FILES.overview));
});

test("partial file coverage is prominent in both detailed and overview reports", async (t) => {
  const root = await temporaryDirectory(t);
  const partial = buildScanResult({
    mode: "security",
    title: "Partial security report",
    root,
    findings: [],
    checks: 3,
    filesScanned: 2,
    startedAt: Date.now() - 5,
    metadata: {
      filesConsidered: 2,
      unreadableFiles: 1,
      skipped: { binary: 4, large: 2, inaccessible: 1, links: 1, limit: 0 },
      suppressedByRule: { "a11y-image-alt": 4 },
      limitations: ["Runtime behavior requires separate testing."],
      reporting: {
        outputDirectory: "Modular",
        otherGeneratedReportDirectories: ["web/Modular"],
      },
    },
  });
  const outputDirectory = path.join(root, "Modular");
  await writeScanReports(partial, { outputDirectory });

  const detailed = await fs.readFile(path.join(outputDirectory, REPORT_FILES.security[0]), "utf8");
  const action = await fs.readFile(path.join(outputDirectory, REPORT_FILES.security[1]), "utf8");
  const overview = await fs.readFile(path.join(outputDirectory, REPORT_FILES.overview), "utf8");
  assert.match(detailed, /Scan scope & limitations/);
  assert.match(detailed, /Oversized file contents not inspected:\*\* 2/);
  assert.match(detailed, /Runtime behavior requires separate testing/);
  assert.match(detailed, /Symbolic links or junctions not followed:\*\* 1/);
  assert.match(detailed, /a11y-image-alt \| 4/);
  assert.match(detailed, /Report directory updated by this run:\*\* `Modular`/);
  assert.match(detailed, /Other Modular report directories not updated by this run:\*\* `web\/Modular`/);
  assert.match(action, /Detail-cap notice/);
  assert.match(action, /4 additional matching locations/);
  assert.match(action, /--max-findings-per-rule/);
  assert.match(overview, /Coverage & detail notice/);
  assert.match(overview, /2 oversized files/);
  assert.match(overview, /1 symbolic links or junctions/);
  assert.match(overview, /4 repeated finding occurrences/);
  assert.match(overview, /1 other Modular-generated report directory was not updated by this run and may be stale/);
});
