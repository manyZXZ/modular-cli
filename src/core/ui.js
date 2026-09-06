import path from "node:path";
import { MODULAR_BRAILLE_LOGO } from "./logo.js";

const ANSI = Object.freeze({
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
  cyan: "\u001b[38;5;51m",
  blue: "\u001b[38;5;75m",
  purple: "\u001b[38;5;141m",
  green: "\u001b[38;5;84m",
  yellow: "\u001b[38;5;220m",
  red: "\u001b[38;5;203m",
  gray: "\u001b[38;5;245m",
  white: "\u001b[97m",
});

function paint(enabled, value, ...codes) {
  return enabled ? `${codes.join("")}${value}${ANSI.reset}` : value;
}

function stripAnsi(value) {
  return String(value).replace(/\u001b\[[0-9;]*m/g, "");
}

function terminalText(value) {
  return String(value ?? "")
    .replace(/\r?\n|\r/g, " ")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, "�");
}

function truncateMiddle(value, width) {
  if (value.length <= width) return value;
  if (width < 12) return value.slice(0, Math.max(1, width));
  const left = Math.ceil((width - 1) * 0.38);
  const right = width - left - 1;
  return `${value.slice(0, left)}…${value.slice(-right)}`;
}

function plural(number, singular, pluralForm = `${singular}s`) {
  return number === 1 ? singular : pluralForm;
}

export class TerminalUI {
  constructor({
    stream = process.stdout,
    errorStream = stream,
    color = true,
    quiet = false,
    environment = process.env,
  } = {}) {
    this.stream = stream;
    this.errorStream = errorStream;
    const terminalIsDumb = String(environment?.TERM ?? "").toLowerCase() === "dumb";
    const colorEnabled = Boolean(color && !environment?.NO_COLOR && !terminalIsDumb);
    this.interactive = Boolean(stream.isTTY && !terminalIsDumb);
    this.color = Boolean(colorEnabled && this.interactive);
    this.errorColor = Boolean(colorEnabled && errorStream.isTTY && !terminalIsDumb);
    this.quiet = quiet;
    this.progressLines = 0;
    this.lastDrawAt = 0;
    this.lastBucket = -1;
    this.lastPhase = null;
  }

  banner() {
    if (this.quiet) return;
    if (!this.interactive) {
      this.stream.write("M O D U L A R — Repository intelligence\n\n");
      return;
    }
    const indent = 4;
    const logoWidth = Math.max(...MODULAR_BRAILLE_LOGO.map((line) => [...line].length));
    const centered = (value) => `${" ".repeat(indent + Math.max(0, Math.floor((logoWidth - [...value].length) / 2)))}${value}`;
    this.stream.write("\n");
    MODULAR_BRAILLE_LOGO.forEach((line) => {
      this.stream.write(`${paint(this.color, `${" ".repeat(indent)}${line}`, ANSI.bold, ANSI.white)}\n`);
    });
    this.stream.write(`${paint(this.color, centered("M O D U L A R"), ANSI.bold)}\n`);
    this.stream.write(`${paint(this.color, centered("Repository intelligence"), ANSI.dim, ANSI.gray)}\n\n`);
  }

  heading(title, subtitle) {
    if (this.quiet) return;
    this.clearProgress();
    this.stream.write(`${paint(this.color, "◆", ANSI.cyan)} ${paint(this.color, terminalText(title), ANSI.bold)}\n`);
    if (subtitle) this.stream.write(`  ${paint(this.color, terminalText(subtitle), ANSI.dim, ANSI.gray)}\n`);
  }

  info(message) {
    if (this.quiet) return;
    this.clearProgress();
    this.stream.write(`${paint(this.color, "i", ANSI.blue, ANSI.bold)} ${terminalText(message)}\n`);
  }

  success(message) {
    if (this.quiet) return;
    this.clearProgress();
    this.stream.write(`${paint(this.color, "✓", ANSI.green, ANSI.bold)} ${terminalText(message)}\n`);
  }

  warning(message) {
    if (this.quiet) return;
    this.clearProgress();
    this.stream.write(`${paint(this.color, "!", ANSI.yellow, ANSI.bold)} ${terminalText(message)}\n`);
  }

  failure(message) {
    this.clearProgress();
    this.errorStream.write(`${paint(this.errorColor, "✕", ANSI.red, ANSI.bold)} ${terminalText(message)}\n`);
  }

  progress({ current = 0, total = 0, file = "Preparing…", phase = "Scanning", check = "" } = {}) {
    if (this.quiet) return;
    const safeTotal = Math.max(total, 1);
    const safeCurrent = Math.max(0, Math.min(current, safeTotal));
    const percentage = Math.round((safeCurrent / safeTotal) * 100);
    const now = Date.now();
    const safePhase = terminalText(phase);
    const phaseChanged = safePhase !== this.lastPhase;
    this.lastPhase = safePhase;

    if (!this.interactive) {
      const bucket = Math.floor(percentage / 10);
      if (!phaseChanged && bucket === this.lastBucket && current !== total && current !== 1) return;
      this.lastBucket = bucket;
      const suffix = file ? ` — ${terminalText(file)}` : "";
      this.stream.write(`[${String(percentage).padStart(3)}%] ${safePhase}${suffix}\n`);
      return;
    }

    if (!phaseChanged && current !== total && now - this.lastDrawAt < 24) return;
    this.lastDrawAt = now;
    this.clearProgress();

    const terminalWidth = Math.max(1, Number.isFinite(this.stream.columns) ? Math.floor(this.stream.columns) : 88);
    if (terminalWidth < 48) {
      const normalized = file ? terminalText(file).split(path.sep).join("/") : "Preparing…";
      const lineOne = truncateMiddle(`${percentage}% ${safePhase}`, terminalWidth);
      const lineTwo = truncateMiddle(normalized, terminalWidth);
      this.stream.write(`\r\u001b[2K${paint(this.color, lineOne, ANSI.bold)}\n\r\u001b[2K${lineTwo}\n`);
      this.progressLines = 2;
      return;
    }
    const barWidth = Math.max(14, Math.min(42, terminalWidth - 38));
    const complete = Math.round((percentage / 100) * barWidth);
    const empty = Math.max(0, barWidth - complete);
    const bar = `${paint(this.color, "━".repeat(complete), ANSI.cyan)}${paint(this.color, "─".repeat(empty), ANSI.dim, ANSI.gray)}`;
    const counter = `${String(safeCurrent).padStart(String(total).length)}/${total}`;
    const percentageLabel = `${percentage}%`;
    const phaseWidth = Math.max(4, terminalWidth - (1 + 2 + barWidth + 2 + percentageLabel.length + 2 + counter.length));
    const displayedPhase = truncateMiddle(safePhase, phaseWidth);
    const lineOne = ` ${paint(this.color, displayedPhase, ANSI.bold)}  ${bar}  ${paint(this.color, percentageLabel, ANSI.bold)}  ${paint(this.color, counter, ANSI.dim, ANSI.gray)}`;
    const normalized = file ? terminalText(file).split(path.sep).join("/") : "Preparing…";
    const contentWidth = Math.max(12, terminalWidth - 3);
    let suffix = check ? ` · ${terminalText(check)}` : "";
    if (suffix.length > Math.floor(contentWidth * 0.42) || contentWidth - suffix.length < 12) suffix = "";
    const fileWidth = Math.max(12, contentWidth - suffix.length);
    const lineTwo = ` ${paint(this.color, "↳", ANSI.purple)} ${truncateMiddle(normalized, fileWidth)}${suffix ? paint(this.color, suffix, ANSI.dim, ANSI.gray) : ""}`;
    this.stream.write(`\r\u001b[2K${lineOne}\n\r\u001b[2K${lineTwo}\n`);
    this.progressLines = 2;
  }

  clearProgress() {
    if (!this.progressLines || !this.interactive) return;
    this.stream.write("\u001b[2A\r\u001b[2K\u001b[1B\r\u001b[2K\u001b[1A\r");
    this.progressLines = 0;
  }

  scanComplete(result) {
    this.clearProgress();
    if (this.quiet) return;
    const { counts } = result.summary;
    const assessment = result.metadata?.assessment ?? {};
    const ruleFamilies = assessment.ruleFamilies ?? {};
    const findingSignals = assessment.findingSignals ?? {};
    const configuredRules = Number.isFinite(ruleFamilies.configured) ? ruleFamilies.configured : result.checks;
    const automatedSignals = Number(findingSignals.automated ?? result.findings.filter((finding) => !finding.manual).length);
    const manualReviewItems = Number(findingSignals.manualReview ?? result.findings.filter((finding) => finding.manual).length);
    const riskScore = Number(result.summary.risk?.riskScore ?? Math.max(0, 100 - result.summary.score));
    const riskBand = terminalText(result.summary.risk?.band ?? "unclassified");
    const unknownApplicability = Number(ruleFamilies.applicabilityUnknown ?? 0);
    const skippedRules = Number(ruleFamilies.skipped ?? 0) + Number(ruleFamilies.optionalChecksSkipped ?? 0);
    const scoreColor = result.summary.score >= 80 ? ANSI.green : result.summary.score >= 55 ? ANSI.yellow : ANSI.red;
    const combined = result.metadata?.runtime?.requested === true
      && Number(result.metadata?.runtime?.metrics?.routesAudited ?? 0) > 0;
    const reviewLabel = combined ? "combined review" : "static review";
    const riskLabel = combined ? "combined risk" : "static risk";
    this.stream.write("\n");
    this.stream.write(`${paint(this.color, "Scan complete", ANSI.bold)}  ${paint(this.color, `${result.summary.score}/100 ${reviewLabel}`, ANSI.bold, scoreColor)}  ${paint(this.color, `· ${riskScore}/100 ${riskBand} ${riskLabel}`, ANSI.dim, ANSI.gray)}\n`);
    this.stream.write(`${paint(this.color, `${result.filesScanned} ${plural(result.filesScanned, "file")} · ${configuredRules} rule ${plural(configuredRules, "family", "families")} · ${(result.durationMs / 1000).toFixed(1)}s recorded scanner time`, ANSI.dim, ANSI.gray)}\n`);
    this.stream.write(`${paint(this.color, `${automatedSignals} automated ${plural(automatedSignals, "signal")} · ${manualReviewItems} manual-review ${plural(manualReviewItems, "item")}${unknownApplicability > 0 ? ` · applicability unreported for ${unknownApplicability}` : ""}${skippedRules > 0 ? ` · ${skippedRules} skipped/optional` : ""}`, ANSI.dim, ANSI.gray)}\n`);
    this.stream.write(
      `${paint(this.color, String(counts.critical), ANSI.red, ANSI.bold)} critical  ` +
      `${paint(this.color, String(counts.high), ANSI.red)} high  ` +
      `${paint(this.color, String(counts.medium), ANSI.yellow)} medium  ` +
      `${paint(this.color, String(counts.low), ANSI.blue)} low  ` +
      `${paint(this.color, String(counts.info), ANSI.gray)} info\n\n`,
    );
  }

  reportPaths(paths, root) {
    if (this.quiet) return;
    this.stream.write(`${paint(this.color, "Reports", ANSI.bold)}\n`);
    for (const reportPath of paths) {
      const relative = terminalText(path.relative(root, reportPath).split(path.sep).join("/"));
      this.stream.write(`  ${paint(this.color, "→", ANSI.cyan)} ${relative}\n`);
    }
    this.stream.write("\n");
  }
}

export function plainLength(value) {
  return stripAnsi(value).length;
}

export { terminalText };
