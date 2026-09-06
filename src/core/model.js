import { redactSensitiveText } from "./sanitize.js";

export const SEVERITIES = Object.freeze(["critical", "high", "medium", "low", "info"]);

export const SEVERITY_WEIGHT = Object.freeze({
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
});

const SEVERITY_RISK_POINTS = Object.freeze({
  critical: 75,
  high: 30,
  medium: 12,
  low: 4,
  info: 0,
});

const CONFIDENCE_WEIGHT = Object.freeze({
  high: 1,
  medium: 0.65,
  low: 0.35,
});

const MANUAL_VALIDATION_WEIGHT = 0.5;
const RISK_CURVE_BUDGET = 60;
const CONFIDENCE_LEVELS = new Set(["high", "medium", "low"]);
const MAX_FINDING_REFERENCES = 20;
const MAX_FINDING_STANDARDS = 20;
const APPLICABLE_STATUSES = new Set(["applicable", "completed", "evaluated", "failed", "finding", "no-findings", "passed"]);
const NOT_APPLICABLE_STATUSES = new Set(["not-applicable", "not_applicable", "n/a"]);
const SKIPPED_STATUSES = new Set(["disabled", "skipped", "unavailable"]);

const SAFE_METADATA_IDENTIFIER_KEYS = new Set([
  "applicability",
  "category",
  "checks",
  "executionStatus",
  "id",
  "kind",
  "mode",
  "model",
  "scanner",
  "status",
  "type",
]);

function redactStructuredValue(value, seen = new WeakMap(), fieldName = null) {
  // Nested runtime findings use the same validated public-reference contract
  // as top-level findings; path length must not corrupt standards URLs.
  if (Array.isArray(value) && (fieldName === "standards" || fieldName === "references")) {
    try {
      return fieldName === "standards" ? normalizeStandards(value) : normalizeReferences(value);
    } catch {
      // Arbitrary metadata can reuse these names without the finding schema.
      // Preserve that data and apply ordinary recursive redaction below.
    }
  }
  if (typeof value === "string") {
    if (fieldName === "fingerprint" && /^[a-f0-9]{64}$/.test(value)) return value;
    const identifier = SAFE_METADATA_IDENTIFIER_KEYS.has(fieldName)
      && /^[A-Za-z0-9_.:/@+ -]{1,180}$/.test(value)
      && (value.length < 32 || /[-.:/@+ ]/.test(value));
    return redactSensitiveText(value, identifier ? { redactHighEntropy: false } : {});
  }
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return seen.get(value);
  if (Array.isArray(value)) {
    const output = [];
    seen.set(value, output);
    value.forEach((item) => output.push(redactStructuredValue(item, seen, fieldName)));
    return output;
  }
  const output = {};
  seen.set(value, output);
  for (const [key, item] of Object.entries(value)) output[key] = redactStructuredValue(item, seen, key);
  return output;
}

function normalizedReferenceUrl(value, fieldName) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2_048) {
    throw new TypeError(`Finding ${fieldName} must contain non-empty URL strings no longer than 2048 characters.`);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`Finding ${fieldName} contains an invalid URL.`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new TypeError(`Finding ${fieldName} URLs must use HTTPS and must not contain credentials.`);
  }
  return parsed.href;
}

function normalizeReferences(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new TypeError("Finding references must be an array when provided.");
  if (value.length > MAX_FINDING_REFERENCES) {
    throw new TypeError(`Finding references cannot contain more than ${MAX_FINDING_REFERENCES} entries.`);
  }
  return [...new Set(value.map((reference) => normalizedReferenceUrl(reference, "references")))];
}

function normalizeStandards(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new TypeError("Finding standards must be an array when provided.");
  if (value.length > MAX_FINDING_STANDARDS) {
    throw new TypeError(`Finding standards cannot contain more than ${MAX_FINDING_STANDARDS} entries.`);
  }
  const standards = value.map((standard) => {
    if (!standard || typeof standard !== "object" || Array.isArray(standard)) {
      throw new TypeError("Each finding standard must be an object with an id.");
    }
    if (typeof standard.id !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9 .:_/()+-]{0,119}$/.test(standard.id)) {
      throw new TypeError("Finding standard ids must be stable identifiers no longer than 120 characters.");
    }
    if (standard.title !== undefined
      && (typeof standard.title !== "string" || standard.title.length === 0 || standard.title.length > 240)) {
      throw new TypeError("Finding standard titles must be non-empty strings no longer than 240 characters.");
    }
    return {
      id: standard.id,
      ...(standard.title ? { title: redactSensitiveText(standard.title) } : {}),
      ...(standard.url ? { url: normalizedReferenceUrl(standard.url, "standards") } : {}),
    };
  });
  return [...new Map(standards.map((standard) => [standard.id, standard])).values()];
}

export function createFinding(input) {
  if (!input?.id || !input?.title || !input?.category || !input?.severity) {
    throw new TypeError("A finding requires id, title, category and severity.");
  }

  for (const field of ["id", "title", "category", "severity"]) {
    if (typeof input[field] !== "string") throw new TypeError(`Finding ${field} must be a string.`);
  }

  if (!SEVERITIES.includes(input.severity)) {
    throw new TypeError(`Unknown finding severity: ${input.severity}`);
  }
  for (const field of ["ruleFamily", "scoreFamily"]) {
    if (input[field] !== undefined && (typeof input[field] !== "string" || input[field].length === 0)) {
      throw new TypeError(`Finding ${field} must be a non-empty string when provided.`);
    }
  }

  const finding = {
    confidence: "high",
    description: "",
    recommendation: "",
    evidence: "",
    file: null,
    line: null,
    suggestedFiles: [],
    tags: [],
    standards: [],
    references: [],
    manual: false,
    ...input,
  };
  if (!CONFIDENCE_LEVELS.has(finding.confidence)) {
    throw new TypeError("Finding confidence must be high, medium or low.");
  }
  if (typeof finding.manual !== "boolean") throw new TypeError("Finding manual must be a boolean.");
  if (finding.file !== null && (typeof finding.file !== "string" || finding.file.length === 0)) {
    throw new TypeError("Finding file must be a non-empty string or null.");
  }
  if (finding.line !== null && (!Number.isSafeInteger(finding.line) || finding.line < 1)) {
    throw new TypeError("Finding line must be a positive integer or null.");
  }
  for (const field of ["title", "category", "description", "recommendation", "action", "evidence"]) {
    if (typeof finding[field] === "string") finding[field] = redactSensitiveText(finding[field]);
  }
  finding.suggestedFiles = Array.isArray(finding.suggestedFiles)
    ? [...finding.suggestedFiles]
    : [];
  finding.tags = Array.isArray(finding.tags) ? [...finding.tags] : [];
  if (!finding.suggestedFiles.every((value) => typeof value === "string" && value.length > 0)) {
    throw new TypeError("Finding suggestedFiles must contain non-empty strings.");
  }
  if (!finding.tags.every((value) => typeof value === "string" && value.length > 0)) {
    throw new TypeError("Finding tags must contain non-empty strings.");
  }
  finding.suggestedFiles = [...new Set(finding.suggestedFiles)];
  finding.tags = [...new Set(finding.tags)];
  finding.standards = normalizeStandards(finding.standards);
  finding.references = normalizeReferences(finding.references);
  return finding;
}

export function findingKey(finding) {
  return JSON.stringify([finding.id, finding.file ?? null, finding.line ?? null, finding.evidence ?? null]);
}

export function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = findingKey(finding);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function confidenceWeight(confidence) {
  if (confidence === undefined || confidence === null || confidence === "") return 1;
  return CONFIDENCE_WEIGHT[String(confidence).toLowerCase()] ?? 0.5;
}

function riskBand(riskScore) {
  if (riskScore === 0) return "none observed";
  if (riskScore < 20) return "low";
  if (riskScore < 40) return "guarded";
  if (riskScore < 60) return "elevated";
  if (riskScore < 80) return "high";
  return "severe";
}

/**
 * Produces a project-size-independent static risk indicator.
 *
 * Only the strongest signal in each rule family contributes. Confidence scales
 * the contribution and a manual-review signal receives half weight because it
 * is a hypothesis awaiting validation, not a confirmed defect. The rational
 * curve approaches, but never reaches, 100 risk for finite input.
 */
export function summarizeFindings(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  for (const finding of findings) {
    if (!SEVERITIES.includes(finding.severity)) {
      throw new TypeError(`Unknown finding severity: ${finding.severity}`);
    }
    counts[finding.severity] += 1;
  }

  const strongestByRule = new Map();
  for (const finding of findings) {
    const ruleFamily = finding.scoreFamily ?? finding.ruleFamily ?? finding.id;
    const basePoints = SEVERITY_RISK_POINTS[finding.severity];
    const points = basePoints
      * confidenceWeight(finding.confidence)
      * (finding.manual ? MANUAL_VALIDATION_WEIGHT : 1);
    const candidate = {
      id: ruleFamily,
      signalId: finding.id,
      severity: finding.severity,
      confidence: String(finding.confidence ?? "unknown"),
      validation: finding.manual ? "manual" : "automated",
      points: Number(points.toFixed(2)),
    };
    const current = strongestByRule.get(ruleFamily);
    if (!current || candidate.points > current.points) strongestByRule.set(ruleFamily, candidate);
  }

  const contributions = [...strongestByRule.values()]
    .filter(({ points }) => points > 0)
    .sort((left, right) => right.points - left.points || left.id.localeCompare(right.id));
  const rawPoints = Number(contributions.reduce((total, item) => total + item.points, 0).toFixed(2));
  const riskScore = rawPoints === 0
    ? 0
    : Math.min(99, Math.floor((100 * rawPoints) / (rawPoints + RISK_CURVE_BUDGET)));
  const automatedSignals = findings.filter((finding) => !finding.manual).length;
  const manualReviewItems = findings.length - automatedSignals;

  return {
    counts,
    score: 100 - riskScore,
    total: findings.length,
    risk: {
      model: "rule-family-confidence-v2",
      riskScore,
      band: riskBand(riskScore),
      rawPoints,
      scoredRuleFamilies: contributions.length,
      signaledRuleFamilies: strongestByRule.size,
      repeatedSignalsExcluded: Math.max(0, findings.length - strongestByRule.size),
      automatedSignals,
      manualReviewItems,
      contributions,
      explanation: "Only the strongest signal per rule family is scored; severity is scaled by confidence and manual-review signals receive half weight.",
      formula: "risk=floor(100*rawPoints/(rawPoints+60)), capped at 99; score=100-risk",
      parameters: {
        severityPoints: { ...SEVERITY_RISK_POINTS },
        confidenceMultipliers: { ...CONFIDENCE_WEIGHT, unknown: 0.5 },
        manualValidationMultiplier: MANUAL_VALIDATION_WEIGHT,
      },
    },
  };
}

function normalizedRuleDescriptor(value) {
  if (typeof value === "string") return { id: value, kind: "automated", status: "unknown" };
  if (!value || typeof value !== "object") return null;
  const id = typeof value.id === "string" && value.id ? value.id : null;
  if (!id) return null;
  const kindValue = String(value.kind ?? value.type ?? "").toLowerCase();
  const kind = value.manual === true || /manual|human/.test(kindValue) ? "manual" : "automated";
  return { id, kind, status: String(value.status ?? "unknown").toLowerCase() };
}

/** Summarizes what the scanner actually declared without inventing applicability. */
export function summarizeRuleFamilies(checks, metadata, findings) {
  const descriptors = Array.isArray(metadata?.checks)
    ? metadata.checks.map(normalizedRuleDescriptor).filter(Boolean)
    : [];
  const unique = [...new Map(descriptors.map((descriptor) => [descriptor.id, descriptor])).values()];
  const configured = Math.max(checks, unique.length);
  const status = { applicable: 0, notApplicable: 0, skipped: 0, applicabilityUnknown: 0 };
  const kind = { automated: 0, manual: 0, unclassified: Math.max(0, configured - unique.length) };
  for (const descriptor of unique) {
    kind[descriptor.kind] += 1;
    if (APPLICABLE_STATUSES.has(descriptor.status)) status.applicable += 1;
    else if (NOT_APPLICABLE_STATUSES.has(descriptor.status)) status.notApplicable += 1;
    else if (SKIPPED_STATUSES.has(descriptor.status)) status.skipped += 1;
    else status.applicabilityUnknown += 1;
  }
  status.applicabilityUnknown += kind.unclassified;

  const dependencyStatus = String(metadata?.dependencyAudit?.status ?? "").toLowerCase();
  const optionalChecksSkipped = dependencyStatus === "skipped" ? 1 : 0;
  const automatedFindings = findings.filter((finding) => !finding.manual).length;
  const manualReviewItems = findings.length - automatedFindings;
  return {
    terminology: "The legacy checks count represents configured rule families, not separate external tools or browser runs.",
    ruleFamilies: {
      configured,
      described: unique.length,
      ...kind,
      ...status,
      optionalChecksSkipped,
    },
    findingSignals: {
      automated: automatedFindings,
      manualReview: manualReviewItems,
    },
  };
}

export function sortFindings(findings) {
  const rank = Object.fromEntries(SEVERITIES.map((severity, index) => [severity, index]));
  const compareText = (a, b) => (a === b ? 0 : a < b ? -1 : 1);
  return [...findings].sort((a, b) => {
    const severity = rank[a.severity] - rank[b.severity];
    if (severity !== 0) return severity;
    const category = compareText(a.category, b.category);
    if (category !== 0) return category;
    return compareText(a.file ?? "", b.file ?? "") || (a.line ?? 0) - (b.line ?? 0);
  });
}

export function buildScanResult({ mode, title, root, findings, checks, filesScanned, startedAt, metadata = {} }) {
  for (const [name, value] of [["mode", mode], ["title", title], ["root", root]]) {
    if (typeof value !== "string" || value.length === 0) throw new TypeError(`Scan ${name} must be a non-empty string.`);
  }
  for (const [name, value] of [["checks", checks], ["filesScanned", filesScanned]]) {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`Scan ${name} must be a non-negative integer.`);
  }
  if (!Array.isArray(findings)) throw new TypeError("Scan findings must be an array.");
  const normalizedFindings = findings.map((finding) => createFinding(finding));
  const unique = sortFindings(deduplicateFindings(normalizedFindings));
  const summary = summarizeFindings(unique);
  const finishedAt = Date.now();
  const start = Number.isFinite(startedAt) ? startedAt : finishedAt;
  // Derive counters before descriptive metadata is redacted; otherwise long,
  // identifier-shaped rule ids can collapse into the same redaction marker.
  const assessment = summarizeRuleFamilies(checks, metadata, unique);
  const safeMetadata = redactStructuredValue(metadata);
  return {
    schemaVersion: 1,
    mode,
    title: redactSensitiveText(title),
    root,
    generatedAt: new Date(finishedAt).toISOString(),
    durationMs: Math.max(0, finishedAt - start),
    filesScanned,
    checks,
    findings: unique,
    summary,
    metadata: {
      ...safeMetadata,
      assessment: {
        ...(safeMetadata?.assessment && typeof safeMetadata.assessment === "object" ? safeMetadata.assessment : {}),
        ...assessment,
      },
    },
  };
}
