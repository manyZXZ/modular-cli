import path from "node:path";
import { REPORT_FILES, generatedReportNames } from "./modules.js";
import { REPORT_LOCK_FILE, REPORT_LOCK_MARKER, REPORT_MARKER } from "./reports/constants.js";
import { codeInline, mdInline, renderActionPlan, renderDetailedReport } from "./reports/render.js";
import { renderOverview } from "./reports/overview.js";
import {
  assertOwnedOrMissing,
  commitReportSet,
  prepareOutputDirectory,
  serializeReportSet,
  withReportLock,
} from "./reports/storage.js";

export async function writeScanReports(result, options = {}) {
  const outputDirectory = path.resolve(options.outputDirectory ?? path.join(result.root, "Modular"));
  const names = REPORT_FILES[result.mode];
  if (!names) throw new TypeError(`No report mapping for scan mode: ${result.mode}`);
  return serializeReportSet(outputDirectory, async () => {
    const validateOutput = await prepareOutputDirectory(result.root, outputDirectory);
    return withReportLock(outputDirectory, validateOutput, options, async () => {
      const knownReportPaths = generatedReportNames().map((name) => path.join(outputDirectory, name));
      await Promise.all(knownReportPaths.map(assertOwnedOrMissing));

      const detailedPath = path.join(outputDirectory, names[0]);
      const actionPath = path.join(outputDirectory, names[1]);
      const overviewPath = path.join(outputDirectory, REPORT_FILES.overview);
      const entries = [
        { target: detailedPath, content: renderDetailedReport(result) },
        { target: actionPath, content: renderActionPlan(result) },
        { target: overviewPath, content: await renderOverview(outputDirectory, result, options.overviewResults) },
      ];

      await commitReportSet(entries, validateOutput);
      const additional = options.afterReportCommit
        ? await options.afterReportCommit()
        : [];
      if (!Array.isArray(additional) || additional.some((item) => typeof item !== "string")) {
        throw new TypeError("afterReportCommit must resolve to an array of report paths.");
      }
      return [overviewPath, detailedPath, actionPath, ...additional];
    });
  });
}

export {
  REPORT_FILES,
  REPORT_LOCK_FILE,
  REPORT_LOCK_MARKER,
  REPORT_MARKER,
  codeInline,
  mdInline,
  renderActionPlan,
  renderDetailedReport,
};
