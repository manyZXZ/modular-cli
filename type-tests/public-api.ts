import {
  EXIT,
  MACHINE_REPORT_LOCK_FILE,
  RUNTIME_VIEWPORTS,
  SCAN_MODULES,
  applyFindingPolicy,
  buildScanResult,
  collectFiles,
  createFinding,
  createJsonReport,
  createSarifReport,
  createScanModuleRegistry,
  getScanModule,
  findingsAtOrAbove,
  detectWebProject,
  fingerprintFindings,
  runSecurityScan,
  runSiteScan,
  type Finding,
  type Severity,
} from "modular-check";
import { parseCliArguments, runCli } from "modular-check/cli";
import { runRuntimeBrowserAudit, startRuntimeStaticServer } from "modular-check/runtime";

const severity: Severity = "high";
const finding: Finding = createFinding({
  id: "security.example",
  title: "Typed finding",
  category: "Security",
  severity,
  standards: [{ id: "CWE-79", url: "https://cwe.mitre.org/data/definitions/79.html" }],
});

const scan = buildScanResult({
  mode: "security",
  title: "Typed scan",
  root: ".",
  findings: [finding],
  checks: 1,
  filesScanned: 0,
});
const governed = applyFindingPolicy(scan, {
  suppressions: [{ rule: "security.example", reason: "Accepted in this type-only fixture." }],
});

void createJsonReport([governed], { toolVersion: "1.2.3" });
void createSarifReport([governed], { toolVersion: "1.2.3" });
void fingerprintFindings("security", [finding]);
void collectFiles(".", { maxFiles: 100 });
void detectWebProject({ root: ".", files: [] });
void runSecurityScan({ root: ".", files: [] });
void runSiteScan({ root: ".", files: [] });
const runtimeResult = runRuntimeBrowserAudit({
  enabled: false,
  root: ".",
  viewportPreset: "mobile",
});
void runtimeResult.then((result) => createJsonReport([result]));
void startRuntimeStaticServer({ enabled: true, directory: "dist" });
void parseCliArguments(["check", "all", "--json"]);
void runCli(["--help"], { setExitCode(code) { void code; } });
void EXIT.ok;
void MACHINE_REPORT_LOCK_FILE;
void RUNTIME_VIEWPORTS.mobile.width;
void createScanModuleRegistry(SCAN_MODULES);
void getScanModule("security").capabilities.dependencyAudit;
void getScanModule("mysite").load().then((runner) => runner({ root: "." }));
void findingsAtOrAbove(governed, "high", { regressionsOnly: true });
void parseCliArguments(["check", "all", "--fail-on-incomplete"]).failOnIncomplete;
