import { redactSensitiveText, sanitizeEvidence } from "../sanitize.js";
import { REPORT_MARKER } from "./constants.js";

const SEVERITY_LABEL = Object.freeze({
  critical: "🔴 Critical",
  high: "🟠 High",
  medium: "🟡 Medium",
  low: "🔵 Low",
  info: "⚪ Info",
});

function singleLine(value, redact = true) {
  const source = redact ? redactSensitiveText(value) : String(value ?? "");
  return source
    .replace(/\r?\n|\r|\u2028|\u2029/g, " ")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, "�")
    .trim();
}

export function mdInline(value, redact = true) {
  return singleLine(value, redact)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\\/g, "\\\\")
    .replace(/([`*_{}\[\]|])/g, "\\$1");
}

export function codeInline(value, redact = true) {
  const safe = singleLine(value, redact);
  if (!safe) return "—";
  const longestRun = Math.max(0, ...(safe.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longestRun + 1);
  const padded = safe.startsWith("`") || safe.endsWith("`") ? ` ${safe} ` : safe;
  return `${fence}${padded}${fence}`;
}

function pathInline(value) {
  return codeInline(redactSensitiveText(value, { redactHighEntropy: false }), false);
}

function standardsInline(standards) {
  if (!Array.isArray(standards) || standards.length === 0) return "";
  return standards.map((standard) => {
    const label = standard.title
      ? `${mdInline(standard.id, false)} — ${mdInline(standard.title)}`
      : mdInline(standard.id, false);
    return standard.url ? `[${label}](${standard.url})` : label;
  }).join(", ");
}

function referencesInline(references) {
  if (!Array.isArray(references) || references.length === 0) return "";
  return references.map((reference, index) => `[Reference ${index + 1}](${reference})`).join(", ");
}

function locationOf(finding) {
  if (!finding.file) return "Project-wide";
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

function categoryGroups(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const current = groups.get(finding.category) ?? [];
    current.push(finding);
    groups.set(finding.category, current);
  }
  return [...groups.entries()].sort(([a], [b]) => (a === b ? 0 : a < b ? -1 : 1));
}

export function countLabel(count, singular, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

function suppressedFindingCount(result) {
  return Object.values(result.metadata?.suppressedByRule ?? {})
    .reduce((total, value) => total + Number(value || 0), 0);
}

function brandedTitle(title) {
  const normalized = singleLine(title) || "Audit report";
  return /^modular(?:\s|$)/i.test(normalized) ? normalized : `Modular ${normalized}`;
}

function severityTable(result) {
  const { counts } = result.summary;
  return [
    "| Critical | High | Medium | Low | Info |",
    "|---:|---:|---:|---:|---:|",
    `| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |`,
  ].join("\n");
}

export function assessmentOf(result) {
  const ruleFamilies = result.metadata?.assessment?.ruleFamilies ?? {};
  const findingSignals = result.metadata?.assessment?.findingSignals ?? {};
  const risk = result.summary?.risk ?? {};
  return {
    configured: Number.isFinite(ruleFamilies.configured) ? ruleFamilies.configured : result.checks,
    automated: Number(ruleFamilies.automated ?? 0),
    manual: Number(ruleFamilies.manual ?? 0),
    unclassified: Number(ruleFamilies.unclassified ?? 0),
    applicable: Number(ruleFamilies.applicable ?? 0),
    notApplicable: Number(ruleFamilies.notApplicable ?? 0),
    skipped: Number(ruleFamilies.skipped ?? 0) + Number(ruleFamilies.optionalChecksSkipped ?? 0),
    applicabilityUnknown: Number(ruleFamilies.applicabilityUnknown ?? result.checks),
    automatedSignals: Number(findingSignals.automated ?? result.findings.filter((finding) => !finding.manual).length),
    manualReviewItems: Number(findingSignals.manualReview ?? result.findings.filter((finding) => finding.manual).length),
    riskScore: Number(risk.riskScore ?? Math.max(0, 100 - result.summary.score)),
    riskBand: singleLine(risk.band ?? "unclassified"),
    model: singleLine(risk.model ?? "legacy"),
    scoredRuleFamilies: Number(risk.scoredRuleFamilies ?? 0),
    repeatedSignalsExcluded: Number(risk.repeatedSignalsExcluded ?? 0),
  };
}

function hasRuntimeEvidence(result) {
  return result.metadata?.runtime?.requested === true
    && Number(result.metadata?.runtime?.metrics?.routesAudited ?? 0) > 0;
}

export function reviewKind(result) {
  return hasRuntimeEvidence(result) ? "combined review" : "static review";
}

function riskKind(result) {
  return hasRuntimeEvidence(result) ? "combined risk" : "static risk";
}

function scoringSection(result) {
  const assessment = assessmentOf(result);
  const combined = hasRuntimeEvidence(result);
  const applicability = `${assessment.applicable} applicable, ${assessment.notApplicable} not applicable, ${assessment.skipped} skipped or optional, ${assessment.applicabilityUnknown} unreported`;
  return [
    "## Assessment model",
    "",
    `> The score is a ${combined ? "static-plus-sampled-runtime" : "static"} triage indicator, not a security, accessibility, SEO, UX, performance, or compliance guarantee.`,
    "",
    `- **${combined ? "Combined" : "Static"} review score:** ${result.summary.score}/100 (higher is better)`,
    `- **${combined ? "Combined" : "Static"} risk indicator:** ${assessment.riskScore}/100 — ${mdInline(assessment.riskBand)} (higher is riskier)`,
    `- **Scoring model:** ${codeInline(assessment.model, false)}`,
    ...(result.summary?.risk?.formula ? [`- **Formula:** ${codeInline(result.summary.risk.formula, false)}`] : []),
    ...(result.summary?.risk?.parameters ? [
      `- **Base severity points:** critical ${Number(result.summary.risk.parameters.severityPoints?.critical ?? 0)}, high ${Number(result.summary.risk.parameters.severityPoints?.high ?? 0)}, medium ${Number(result.summary.risk.parameters.severityPoints?.medium ?? 0)}, low ${Number(result.summary.risk.parameters.severityPoints?.low ?? 0)}, info ${Number(result.summary.risk.parameters.severityPoints?.info ?? 0)}`,
      `- **Confidence/manual multipliers:** high ×${Number(result.summary.risk.parameters.confidenceMultipliers?.high ?? 0)}, medium ×${Number(result.summary.risk.parameters.confidenceMultipliers?.medium ?? 0)}, low ×${Number(result.summary.risk.parameters.confidenceMultipliers?.low ?? 0)}, manual validation ×${Number(result.summary.risk.parameters.manualValidationMultiplier ?? 0)}`,
    ] : []),
    `- **Configured rule families:** ${assessment.configured} (the legacy \`checks\` field refers to rule families, not ${assessment.configured} external tools or browser runs)`,
    `- **Declared execution kind:** ${assessment.automated} automated, ${assessment.manual} manual-only, ${assessment.unclassified} unclassified`,
    `- **Rule applicability:** ${applicability}`,
    `- **Produced review signals:** ${assessment.automatedSignals} automated, ${assessment.manualReviewItems} requiring manual validation`,
    `- **Scoring scope:** strongest scored signal from ${countLabel(assessment.scoredRuleFamilies, "rule family", "rule families")}; ${assessment.repeatedSignalsExcluded} repeated retained signals did not stack`,
    "",
    "Repeated locations from one rule family do not repeatedly reduce the score. Severity is scaled by confidence, and manual-review signals receive reduced weight until a person or runtime test validates them.",
    "",
    "> **Workload note:** The review score is not a fix count or effort estimate. Raising the detail cap can expose many more locations without changing the score because only the strongest signal in each rule family contributes.",
  ].join("\n");
}

function coverageSection(result) {
  const coverage = result.metadata?.coverage;
  if (!coverage) return "";
  const rows = Array.isArray(coverage)
    ? coverage.map((item) => `- ${mdInline(item)}`)
    : Object.entries(coverage).map(([name, value]) => `- **${mdInline(name)}:** ${mdInline(Array.isArray(value) ? value.join(", ") : value)}`);
  return rows.length ? `\n## Coverage\n\n${rows.join("\n")}\n` : "";
}

function ruleLedgerSection(result) {
  const source = Array.isArray(result.metadata?.checkLedger)
    ? result.metadata.checkLedger
    : Array.isArray(result.metadata?.checks) ? result.metadata.checks : [];
  const normalized = source.map((entry) => typeof entry === "string" ? { id: entry } : entry)
    .filter((entry) => entry && typeof entry.id === "string" && entry.id)
    .filter((entry, index, entries) => entries.findIndex((candidate) => candidate.id === entry.id) === index);
  if (normalized.length === 0) return "";
  const rows = normalized.map((entry) => {
    const family = entry.id;
    const kind = entry.kind ?? (entry.manual ? "manual" : "automated");
    const execution = entry.executionStatus ?? entry.status ?? "not reported";
    const applicability = entry.applicability ?? "not separately reported";
    const retained = Number.isFinite(entry.retainedFindings)
      ? Number(entry.retainedFindings)
      : result.findings.filter((finding) => (finding.ruleFamily ?? finding.id) === family).length;
    const suppressed = Number(entry.suppressedFindings ?? 0);
    const signals = suppressed > 0 ? `${retained} retained + ${suppressed} summarized` : String(retained);
    return `| ${codeInline(family, false)} | ${mdInline(kind)} | ${mdInline(execution)} | ${mdInline(applicability)} | ${mdInline(signals)} |`;
  });
  return [
    "## Rule-family execution ledger",
    "",
    "This ledger distinguishes configured coverage from produced findings. A completed family with zero signals is not a certification; applicability may still require project or deployment context.",
    "",
    "| Rule family | Kind | Execution | Applicability | Finding signals |",
    "|---|---|---|---|---:|",
    ...rows,
  ].join("\n");
}

export function coverageWarnings(result) {
  const skipped = result.metadata?.skipped ?? result.metadata?.scope?.skipped ?? {};
  const unreadable = Number(result.metadata?.unreadableFiles ?? result.metadata?.scope?.unreadableFiles ?? 0);
  const suppressed = suppressedFindingCount(result);
  const warnings = [];
  if (Number(skipped.limit ?? 0) > 0) warnings.push(`${Number(skipped.limit)} entries were not visited because the file limit was reached`);
  if (Number(skipped.large ?? 0) > 0) warnings.push(`${Number(skipped.large)} oversized files were inventoried but their contents were not inspected`);
  if (Number(skipped.inaccessible ?? 0) > 0) warnings.push(`${Number(skipped.inaccessible)} filesystem entries were inaccessible`);
  if (Number(skipped.links ?? 0) > 0) warnings.push(`${Number(skipped.links)} symbolic links or junctions were not followed`);
  if (unreadable > 0) warnings.push(`${unreadable} inventoried files could not be read for content checks`);
  if (suppressed > 0) warnings.push(`${suppressed} repeated finding occurrences were summarized beyond per-rule detail limits`);
  const dependencyAudit = result.metadata?.dependencyAudit;
  if (dependencyAudit && dependencyAudit.status !== "completed") {
    if (dependencyAudit.status === "skipped") {
      warnings.push("dependency advisory lookup was skipped (opt in with --dependency-audit)");
    } else if (dependencyAudit.status === "partial") {
      warnings.push("dependency advisory lookup completed for only part of the selected workspaces");
    } else {
      warnings.push(`dependency advisory lookup is ${singleLine(dependencyAudit.status || "unavailable")}`);
    }
  }
  const runtime = result.metadata?.runtime;
  if (runtime?.requested && runtime.status !== "completed") {
    warnings.push(`requested runtime browser audit is ${singleLine(runtime.status || "unavailable")}`);
  }
  const unknownApplicability = Number(result.metadata?.assessment?.ruleFamilies?.applicabilityUnknown ?? 0);
  if (unknownApplicability > 0) {
    warnings.push(`per-rule applicability was not reported for ${unknownApplicability} configured rule families`);
  }
  return warnings;
}

function scopeAndLimitationsSection(result) {
  const scope = result.metadata?.scope;
  const skipped = result.metadata?.skipped ?? scope?.skipped ?? {};
  const rows = [];
  if (scope && typeof scope === "object") {
    for (const [name, value] of Object.entries(scope)) {
      if (name === "skipped" || value === null || typeof value === "object") continue;
      rows.push(`- **${mdInline(name)}:** ${mdInline(value)}`);
    }
  }
  if (Number(skipped.binary ?? 0) > 0) {
    const retained = Number(skipped.assetMetadata ?? 0);
    rows.push(`- **Binary file contents not read:** ${Number(skipped.binary)}${retained > 0 ? ` (${retained} web-asset metadata records retained for size/format checks)` : ""}`);
  }
  if (Number(skipped.large ?? 0) > 0) rows.push(`- **Oversized file contents not inspected:** ${Number(skipped.large)}`);
  if (Number(skipped.inaccessible ?? 0) > 0) rows.push(`- **Inaccessible filesystem entries:** ${Number(skipped.inaccessible)}`);
  if (Number(skipped.links ?? 0) > 0) rows.push(`- **Symbolic links or junctions not followed:** ${Number(skipped.links)}`);
  if (Number(skipped.limit ?? 0) > 0) rows.push(`- **Entries omitted after reaching the file limit:** ${Number(skipped.limit)}`);
  if (!scope && Number.isFinite(result.metadata?.filesConsidered)) rows.push(`- **Files considered:** ${Number(result.metadata.filesConsidered)}`);
  if (!scope && Number.isFinite(result.metadata?.unreadableFiles)) rows.push(`- **Unreadable files:** ${Number(result.metadata.unreadableFiles)}`);
  const dependencyAudit = result.metadata?.dependencyAudit;
  if (dependencyAudit) {
    const reason = dependencyAudit.reason
      ?? dependencyAudit.audits?.map((audit) => audit?.reason).filter(Boolean).join("; ")
      ?? "";
    const detail = reason ? ` — ${sanitizeEvidence(reason, 400)}` : "";
    rows.push(`- **Dependency advisory lookup:** ${mdInline(dependencyAudit.status || "unknown")}${mdInline(detail)}`);
  }
  const reporting = result.metadata?.reporting;
  if (reporting?.outputDirectory) {
    rows.push(`- **Report directory updated by this run:** ${pathInline(reporting.outputDirectory)}`);
  }
  if (Array.isArray(reporting?.otherGeneratedReportDirectories)
    && reporting.otherGeneratedReportDirectories.length > 0) {
    rows.push(`- **Other Modular report directories not updated by this run:** ${reporting.otherGeneratedReportDirectories.map(pathInline).join(", ")}`);
  }
  const policy = result.metadata?.policy;
  if (policy?.baseline?.loaded) {
    rows.push(`- **Baseline comparison:** ${Number(policy.baseline.newFindings ?? 0)} new, ${Number(policy.baseline.unchangedFindings ?? 0)} unchanged finding signals`);
    if (policy.baseline.escalatedFindings > 0) rows.push(`- **Severity increases since baseline:** ${Number(policy.baseline.escalatedFindings)}`);
  }
  if (result.metadata?.sourceCoverage?.requested) {
    rows.push(`- **Requested source coverage:** ${mdInline(result.metadata.sourceCoverage.status)}`);
  }
  if (Number(policy?.suppressions?.configured ?? 0) > 0) {
    rows.push(`- **Auditable suppressions:** ${Number(policy.suppressions.matchedFindings ?? 0)} matched findings; ${Number(policy.suppressions.active ?? 0)} active and ${Number(policy.suppressions.expired ?? 0)} expired policy entries`);
  }

  const limitations = Array.isArray(result.metadata?.limitations)
    ? result.metadata.limitations.map((item) => `- ${mdInline(item)}`)
    : [];
  const suppressedEntries = Object.entries(result.metadata?.suppressedByRule ?? {})
    .filter(([, count]) => Number(count) > 0)
    .sort(([left], [right]) => left.localeCompare(right));
  if (rows.length === 0 && limitations.length === 0 && suppressedEntries.length === 0) return "";
  return [
    "## Scan scope & limitations",
    "",
    ...(rows.length ? rows : ["- No skipped-file metadata was reported."]),
    ...(suppressedEntries.length ? [
      "",
      "### Repeated occurrences summarized",
      "",
      "The detailed cards are capped per rule; these additional matches were counted but omitted. Rerun with a higher `--max-findings-per-rule` value to list more locations.",
      "",
      "| Rule | Additional occurrences | Suppressed severity mix |",
      "|---|---:|---|",
      ...suppressedEntries.map(([rule, count]) => {
        const severityCounts = result.metadata?.suppressedSeverityByRule?.[rule] ?? {};
        const mix = ["critical", "high", "medium", "low", "info"]
          .filter((severity) => Number(severityCounts[severity] ?? 0) > 0)
          .map((severity) => `${severity}: ${Number(severityCounts[severity])}`)
          .join(", ") || "not recorded";
        return `| ${mdInline(rule, false)} | ${Number(count)} | ${mdInline(mix)} |`;
      }),
    ] : []),
    ...(limitations.length ? ["", `### What ${hasRuntimeEvidence(result) ? "this assessment" : "static analysis"} cannot prove`, "", ...limitations] : []),
    "",
  ].join("\n");
}

function runtimeAuditSection(result) {
  const runtime = result.metadata?.runtime;
  if (!runtime?.requested) return "";
  const metrics = runtime.metrics ?? {};
  const playwright = runtime.capabilities?.playwright ?? {};
  const axe = runtime.capabilities?.axe ?? {};
  const routes = Array.isArray(metrics.routes) ? metrics.routes : [];
  const value = (input, digits = 0, suffix = "") => Number.isFinite(input) ? `${Number(input).toFixed(digits)}${suffix}` : "—";
  const routeRows = routes.map((route) => {
    const performance = route.metrics?.performance ?? {};
    const navigation = route.metrics?.navigation ?? {};
    const accessibility = route.accessibility ?? {};
    const axeResult = accessibility.status === "completed"
      ? `${Number(accessibility.violations ?? 0)} / ${Number(accessibility.incomplete ?? 0)}`
      : mdInline(accessibility.status ?? "not run");
    const viewport = route.viewport
      ? `${route.viewport.preset ?? "custom"} ${route.viewport.width}×${route.viewport.height}`
      : "not recorded";
    const longTasks = Number.isFinite(performance.longTaskCount)
      ? `${Number(performance.longTaskCount)} / ${value(performance.longTaskDurationMs, 0, " ms")}`
      : "—";
    const transferBytes = Number(performance.resourceTransferBytes ?? 0) + Number(navigation.transferBytes ?? 0);
    const transfer = transferBytes > 0 ? `${(transferBytes / (1024 * 1024)).toFixed(2)} MiB` : "—";
    return `| ${codeInline(route.url ?? route.finalUrl ?? "unknown")} | ${mdInline(viewport)} | ${mdInline(route.status ?? "unknown")} | ${Number.isFinite(route.httpStatus) ? route.httpStatus : "—"} | ${value(navigation.responseStartMs, 0, " ms")} | ${value(performance.firstContentfulPaintMs, 0, " ms")} | ${value(performance.largestContentfulPaintMs, 0, " ms")} | ${value(performance.cumulativeLayoutShift, 3)} | ${longTasks} | ${transfer} | ${axeResult} | ${Number(route.network?.consoleErrors ?? 0) + Number(route.network?.pageErrors ?? 0)} |`;
  });
  const incompleteStages = Object.entries(runtime.stages ?? {})
    .filter(([, stage]) => !["completed", "not-needed"].includes(stage?.status))
    .map(([name, stage]) => `- ${codeInline(name, false)}: **${mdInline(stage?.status ?? "unknown")}**${stage?.reason ? ` — ${mdInline(stage.reason)}` : ""}`);
  const incompleteRouteStages = routes.flatMap((route) => Object.entries(route.stages ?? {})
    .filter(([, stage]) => !["completed", "not-needed"].includes(stage?.status))
    .map(([name, stage]) => `- ${codeInline(route.url ?? route.finalUrl ?? "unknown")} · ${codeInline(name, false)}: **${mdInline(stage?.status ?? "unknown")}**${stage?.reason ? ` — ${mdInline(stage.reason)}` : ""}`));
  return [
    "## Runtime browser audit",
    "",
    `- **Status:** ${mdInline(runtime.status ?? "unknown")}`,
    `- **Target:** ${codeInline(runtime.target ?? "not recorded")}`,
    `- **Target source:** ${mdInline(runtime.source ?? "explicit runtime target")}`,
    `- **Browser:** ${mdInline(playwright.browserName ?? "unknown")}${playwright.browserChannel ? ` / installed ${mdInline(playwright.browserChannel)} channel` : ""} via ${mdInline(playwright.packageName ?? "Playwright unavailable")}`,
    `- **Viewport:** ${mdInline(result.metadata?.runtime?.viewport?.preset ?? runtime.viewport?.preset ?? "not recorded")} ${Number(result.metadata?.runtime?.viewport?.width ?? runtime.viewport?.width ?? 0) || "—"}×${Number(result.metadata?.runtime?.viewport?.height ?? runtime.viewport?.height ?? 0) || "—"} CSS px`,
    `- **Rendered accessibility engine:** ${axe.available ? mdInline(axe.packageName ?? axe.engine ?? "available") : "unavailable"}`,
    `- **Route coverage:** ${Number(metrics.routesAudited ?? 0)}/${Number(metrics.routesRequested ?? 0)} requested routes audited; ${Number(metrics.routesCompleted ?? 0)} complete, ${Number(metrics.routesPartial ?? 0)} partial, ${Number(metrics.routesFailed ?? 0)} failed`,
    `- **Observed network/browser events:** ${Number(metrics.blockedRequests ?? 0)} blocked requests, ${Number(metrics.blockedEgressAttempts ?? 0)} blocked worker/browser-transport attempts, ${Number(metrics.requestFailures ?? 0)} failed requests, ${Number(metrics.consoleErrors ?? 0)} console errors, ${Number(metrics.pageErrors ?? 0)} page errors`,
    `- **Runtime isolation:** repository scripts executed = ${runtime.policy?.repositoryScriptsExecuted === true ? "yes" : "no"}; remote traffic allowed = ${runtime.policy?.allowRemote === true ? "yes" : "no"}`,
    ...(routeRows.length ? [
      "",
      "| Route | Viewport | Status | HTTP | TTFB | FCP | Lab LCP | Lab CLS | Long tasks / total | Transfer | Axe violations / incomplete | Browser errors |",
      "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
      ...routeRows,
    ] : []),
    ...(incompleteStages.length || incompleteRouteStages.length ? [
      "",
      "### Incomplete runtime stages",
      "",
      ...incompleteStages,
      ...incompleteRouteStages,
    ] : []),
    "",
    "> Runtime timings are single-run laboratory observations from the selected local browser context. They are not field Core Web Vitals.",
  ].join("\n");
}

export function renderDetailedReport(result) {
  const assessment = assessmentOf(result);
  const findingSections = categoryGroups(result.findings).map(([category, findings]) => {
      const cards = findings.map((finding, index) => {
      const suggestions = finding.suggestedFiles?.length
        ? `\n- **Likely files to change:** ${finding.suggestedFiles.map(pathInline).join(", ")}`
        : "";
      const evidence = finding.evidence ? `\n- **Evidence:** ${codeInline(sanitizeEvidence(finding.evidence))}` : "";
      const review = finding.manual ? "\n- **Validation:** Manual review required; this signal cannot be proven reliably from source alone." : "";
      const baseline = finding.baselineState ? `\n- **Baseline state:** ${mdInline(finding.baselineState)}` : "";
      const regression = finding.baselineChange === "severity-increased"
        ? `\n- **Baseline change:** Severity increased from ${mdInline(finding.previousSeverity)} to ${mdInline(finding.severity)}` : "";
      const suppression = finding.suppression?.status === "accepted"
        ? `\n- **Policy:** Accepted suppression — ${mdInline(finding.suppression.reason)}${finding.suppression.expires ? ` (valid through ${codeInline(finding.suppression.expires, false)})` : ""}`
        : "";
      const standards = standardsInline(finding.standards);
      const references = referencesInline(finding.references);
      return [
        `### ${index + 1}. ${mdInline(finding.title)}`,
        "",
        `- **Severity:** ${SEVERITY_LABEL[finding.severity]}`,
        `- **Rule:** ${codeInline(finding.id, false)}`,
        `- **Confidence:** ${mdInline(finding.confidence)}`,
        `- **Location:** ${pathInline(locationOf(finding))}`,
        `- **Why it matters:** ${mdInline(finding.description) || "No description supplied."}`,
        `- **Recommended change:** ${mdInline(finding.recommendation) || "Review and resolve this finding."}`,
        ...(standards ? [`- **Standards:** ${standards}`] : []),
        ...(references ? [`- **References:** ${references}`] : []),
        suggestions,
        evidence,
        review,
        baseline,
        regression,
        suppression,
      ].filter(Boolean).join("\n");
    });
    return `## ${mdInline(category)}\n\n${cards.join("\n\n")}`;
  });

  const noFindings = [
    "## No findings",
    "",
    `No findings were produced by the enabled ${hasRuntimeEvidence(result) ? "static and requested runtime" : "static"} checks. This is not a guarantee that the application is defect-free; continue with dependency, browser/device and human testing.`,
  ].join("\n");

  return [
    REPORT_MARKER,
    `# ${mdInline(brandedTitle(result.title))}`,
    "",
    `> **${hasRuntimeEvidence(result) ? "Combined" : "Static"} review score: ${result.summary.score}/100** · ${riskKind(result)} **${assessment.riskScore}/100 (${mdInline(assessment.riskBand)})** · ${countLabel(result.summary.total, "retained finding")} · ${countLabel(result.filesScanned, "file")} · ${countLabel(assessment.configured, "rule family", "rule families")}`,
    "",
    severityTable(result),
    "",
    scoringSection(result),
    "",
    ruleLedgerSection(result),
    "",
    "## Scan details",
    "",
    `- **Repository:** ${pathInline(result.root)}`,
    `- **Generated:** ${codeInline(result.generatedAt)}`,
    `- **Recorded scanner duration:** ${(result.durationMs / 1000).toFixed(2)} seconds (may exclude repository discovery and report writing)`,
    `- **Mode:** ${codeInline(result.mode)}`,
    coverageSection(result),
    runtimeAuditSection(result),
    scopeAndLimitationsSection(result),
    result.findings.length ? findingSections.join("\n\n---\n\n") : noFindings,
    "",
    "---",
    "",
    `_Modular uses deterministic static heuristics${hasRuntimeEvidence(result) ? " plus explicitly requested sampled browser evidence" : ""}. Its score measures review priority, not verified product quality. Verify high-impact findings and run authenticated browser, penetration, assistive-technology and user testing before release._`,
    "",
  ].join("\n");
}

function phaseFor(finding) {
  if (finding.manual) return "Validate — human or browser review";
  if (finding.severity === "critical" || finding.severity === "high") return "Now — triage potential release blockers";
  if (finding.severity === "medium") return "Next — important improvements";
  return "Later — hardening and polish";
}

function rerunInstruction(result) {
  if (result.metadata?.runtime?.requested === true) {
    return `rerun the original ${codeInline(`modular check ${result.mode} --runtime …`)} invocation, preserving its target, route, browser and network-permission options`;
  }
  return `rerun ${codeInline(`modular check ${result.mode}`)}`;
}

export function renderActionPlan(result) {
  const suppressed = suppressedFindingCount(result);
  const policySuppressed = result.findings.filter((finding) => finding.suppression?.status === "accepted");
  const phases = new Map();
  for (const finding of result.findings.filter((item) => item.suppression?.status !== "accepted")) {
    const phase = phaseFor(finding);
    const list = phases.get(phase) ?? [];
    list.push(finding);
    phases.set(phase, list);
  }
  const order = [
    "Now — triage potential release blockers",
    "Next — important improvements",
    "Later — hardening and polish",
    "Validate — human or browser review",
  ];
  const sections = order.flatMap((phase) => {
    const findings = phases.get(phase);
    if (!findings?.length) return [];
    const tasks = findings.map((finding) => {
      const location = locationOf(finding);
      const files = finding.suggestedFiles?.length ? ` Suggested: ${finding.suggestedFiles.map(pathInline).join(", ")}.` : "";
      return `- [ ] **${mdInline(finding.title)}** (${SEVERITY_LABEL[finding.severity]}) — ${mdInline(finding.recommendation)} Location: ${pathInline(location)}.${files}`;
    });
    return [`## ${phase}`, "", ...tasks, ""];
  });

  if (!sections.length) {
    sections.push("## Maintain", "", "- [ ] Keep automated checks in CI and repeat the scan after material changes.", "");
  }

  return [
    REPORT_MARKER,
    `# ${mdInline(result.title)} — Action plan`,
    "",
    `This plan turns the ${countLabel(result.summary.total, "retained finding")} in the detailed report into an ordered checklist. The ${reviewKind(result)} score prioritizes investigation; it does not certify product quality or estimate workload. Triage higher-severity automated signals first, validate manual-review items, then ${rerunInstruction(result)} to compare the result.`,
    "",
    "> Findings are review signals, not confirmed defects. Verify the cited code and runtime context before editing source, rotating credentials, or changing security controls; record a justified false-positive decision instead of changing correct behavior merely to clear a report.",
    ...(suppressed > 0 ? [
      "",
      `> **Detail-cap notice:** ${countLabel(suppressed, "additional matching location")} ${suppressed === 1 ? "is" : "are"} included in the detailed report totals, but ${suppressed === 1 ? "its source path is" : "their source paths are"} not expanded in either report. Rerun with a higher ${codeInline("--max-findings-per-rule", false)} value when every location is needed for a migration.`,
    ] : []),
    ...(policySuppressed.length > 0 ? [
      "",
      `> **Accepted-risk policy:** ${countLabel(policySuppressed.length, "finding is", "findings are")} documented as suppressed and omitted from the remediation checklist. They remain visible in the detailed and machine-readable reports; expired suppressions reactivate automatically.`,
    ] : []),
    "",
    ...sections,
    "## Definition of done",
    "",
    "- [ ] The affected behavior has an automated regression test where practical.",
    "- [ ] Critical and high findings were reviewed by a person, even if marked as false positives.",
    "- [ ] Runtime/browser checks were completed for behavior static analysis cannot observe.",
    "- [ ] Modular was rerun and the report was reviewed before release.",
    "",
  ].join("\n");
}
