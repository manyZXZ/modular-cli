/** Built-in module contract. Registration is explicit; project code is never loaded. */
export function createScanModuleRegistry(definitions) {
  if (!Array.isArray(definitions)) throw new TypeError("Scan module definitions must be an array.");
  const ids = new Set();
  const runners = new Set();
  const files = new Set(["00-overview.md"]);
  return Object.freeze(definitions.map((definition) => {
    if (!definition || !/^[a-z][a-z0-9-]*$/.test(definition.id) || definition.id === "all"
      || ids.has(definition.id) || !Number.isSafeInteger(definition.version) || definition.version < 1
      || typeof definition.title !== "string" || !definition.title.trim()
      || typeof definition.description !== "string" || typeof definition.load !== "function"
      || typeof definition.runnerKey !== "string" || !/^run[A-Z][A-Za-z0-9]*$/.test(definition.runnerKey)
      || runners.has(definition.runnerKey)
      || !Array.isArray(definition.reports) || definition.reports.length !== 2) {
      throw new TypeError("Invalid or duplicate scan module definition.");
    }
    ids.add(definition.id);
    runners.add(definition.runnerKey);
    const reports = definition.reports.map((report) => {
      if (!report || !/^[a-z0-9][a-z0-9-]*\.md$/.test(report.file) || files.has(report.file)
        || typeof report.title !== "string" || !report.title.trim()) throw new TypeError("Invalid or duplicate module report file.");
      files.add(report.file);
      return Object.freeze({ ...report });
    });
    const capabilities = Object.freeze({ website: true, runtime: false, dependencyAudit: false, ...definition.capabilities });
    if (!Object.values(capabilities).every((value) => typeof value === "boolean")) throw new TypeError("Module capabilities must be booleans.");
    return Object.freeze({ ...definition, capabilities, reports: Object.freeze(reports) });
  }));
}

export const SCAN_MODULES = createScanModuleRegistry([
  {
    id: "security", version: 1, title: "Security check",
    description: "Application security, secrets, supply chain and configuration",
    runnerKey: "runSecurityScan",
    capabilities: { dependencyAudit: true },
    reports: [
      { file: "01-security-report.md", title: "Security report" },
      { file: "02-security-action-plan.md", title: "Security action plan" },
    ],
    load: async () => (await import("../scanners/security.js")).runSecurityScan,
  },
  {
    id: "mysite", version: 1, title: "Website check",
    description: "Site quality, UX, accessibility, SEO, AI search and performance",
    runnerKey: "runSiteScan",
    capabilities: { runtime: true },
    reports: [
      { file: "03-site-report.md", title: "Site report" },
      { file: "04-site-action-plan.md", title: "Site action plan" },
    ],
    load: async () => (await import("../scanners/mysite.js")).runSiteScan,
  },
]);

export function getScanModule(id) {
  const module = SCAN_MODULES.find((entry) => entry.id === id);
  if (!module) throw new TypeError(`Unknown scan module: ${id}`);
  return module;
}

export const REPORT_FILES = Object.freeze({
  overview: "00-overview.md",
  ...Object.fromEntries(SCAN_MODULES.map((module) => [module.id, Object.freeze(module.reports.map(({ file }) => file))])),
});

export function generatedReportNames() {
  return [REPORT_FILES.overview, ...SCAN_MODULES.flatMap((module) => module.reports.map(({ file }) => file))];
}
