import { promises as fs } from "node:fs";
import path from "node:path";
import { SCAN_MODULES, REPORT_FILES } from "../modules.js";
import { REPORT_MARKER } from "./constants.js";
import { assessmentOf, countLabel, coverageWarnings, mdInline, reviewKind } from "./render.js";

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function overviewResults(latestResult, suppliedResults) {
  const byMode = new Map();
  for (const result of [...(Array.isArray(suppliedResults) ? suppliedResults : []), latestResult]) {
    if (result && REPORT_FILES[result.mode]) byMode.set(result.mode, result);
  }
  return SCAN_MODULES.flatMap(({ id }) => byMode.has(id) ? [byMode.get(id)] : []);
}

export async function renderOverview(outputDirectory, latestResult, suppliedResults) {
  const completedResults = overviewResults(latestResult, suppliedResults);
  const currentModes = new Set(completedResults.map((result) => result.mode));
  const reports = [];
  const earlierReports = [];
  const links = SCAN_MODULES.flatMap((module) => module.reports.map(({ file, title }) => [file, title, module.id]));
  for (const [name, label, mode] of links) {
    if (mode !== latestResult.mode && !await exists(path.join(outputDirectory, name))) continue;
    const row = `- [${label}](./${name})`;
    if (currentModes.has(mode)) reports.push(row);
    else earlierReports.push(row);
  }
  const warnings = [...new Set(completedResults.flatMap((result) => coverageWarnings(result)
    .map((warning) => completedResults.length > 1 ? `${result.title}: ${warning}` : warning)))];
  const otherReportDirectories = [...new Map(completedResults
    .flatMap((result) => result.metadata?.reporting?.otherGeneratedReportDirectories ?? [])
    .map((directory) => {
      const value = String(directory);
      return [process.platform === "win32" ? value.toLowerCase() : value, value];
    })).values()];
  if (otherReportDirectories.length > 0) {
    warnings.push(`${countLabel(otherReportDirectories.length, "other Modular-generated report directory", "other Modular-generated report directories")} ${otherReportDirectories.length === 1 ? "was" : "were"} not updated by this run and may be stale`);
  }
  if (earlierReports.length > 0) {
    warnings.push(`${earlierReports.length} marker-owned report files in this directory were not refreshed by this run`);
  }
  const summaryRows = completedResults.map((result) => {
    const counts = result.summary.counts;
    const assessment = assessmentOf(result);
    return `| ${mdInline(result.title)} | **${result.summary.score}/100** | ${assessment.riskScore}/100 ${mdInline(assessment.riskBand)} | ${assessment.configured} | ${assessment.automatedSignals} / ${assessment.manualReviewItems} | ${result.summary.total} | ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |`;
  });
  const headline = completedResults.length > 1
    ? `> Combined run complete · ${completedResults.map((result) => `**${mdInline(result.title)} ${result.summary.score}/100 ${reviewKind(result)}**`).join(" · ")}`
    : `> Latest scan: **${mdInline(latestResult.title)}** · ${mdInline(reviewKind(latestResult))} **${latestResult.summary.score}/100** · ${countLabel(latestResult.summary.total, "retained finding")}`;
  return [
    REPORT_MARKER,
    "# ◇ MODULAR — Audit overview",
    "",
    headline,
    ...(warnings.length ? [">", `> ⚠ **Coverage & detail notice:** ${mdInline(warnings.join("; "))}.`] : []),
    "",
    "## Scan summary",
    "",
    "| Scan | Review score | Risk indicator | Rule families | Automated / manual signals | Retained findings | Critical | High | Medium | Low | Info |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ...summaryRows,
    "",
    "## Reports",
    "",
    "### Refreshed by this run",
    "",
    ...reports,
    ...(earlierReports.length ? [
      "",
      "### Earlier generated reports — not refreshed",
      "",
      "These marker-owned files remain available, but may describe an older scan and are not included in the summary above.",
      "",
      ...earlierReports,
    ] : []),
    "",
    "## Reading the results",
    "",
    "Start with the action plan to triage potential release blockers. The detailed report explains evidence, impact, exact source locations and likely files to change. A finding is a review signal—not proof of exploitability. The review score groups repeated locations by rule family and scales severity by confidence; it is not a finding count, backlog size, or effort estimate, so a higher detail cap can reveal more locations without changing the score. Even when sampled browser evidence is included, it is not a substitute for professional security review, cross-browser and assistive-technology testing, field performance data, or research with real users.",
    "",
    `Generated ${mdInline(latestResult.generatedAt)} by Modular.`,
    "",
  ].join("\n");
}
