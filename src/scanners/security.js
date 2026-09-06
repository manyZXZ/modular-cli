import path from "node:path";
import { createFinding, buildScanResult } from "../core/model.js";
import { createFindingIndex } from "../core/policy.js";
import { readTextFile, lineOf, isSourceFile, isStyleFile, isTestFile } from "../core/files.js";
import { detectWebProject } from "../core/project.js";
import { findSensitiveAssignments, isSensitiveCredentialName, sanitizeEvidence } from "../core/sanitize.js";
import { securityCheckDescriptors, securityStandards } from "./security-catalog.js";
import { normalizeName, unique, truncate, packageLine } from "./security/shared.js";
import { runDependencyAudit } from "./security/dependency-audit.js";
import {
  configurationSecuritySignals,
  isLikelyServerSource,
  jwtValidationSignals,
  lockfileSecuritySignals,
  serverDataFlowSignals,
  workflowSecuritySignals,
} from "./security-dataflow.js";

const LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
]);
const SEVERITY_RANK = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });
const CONFIDENCE_RANK = Object.freeze({ high: 0, medium: 1, low: 2 });

const GENERATED_AUDIT_DIRECTORIES = new Set([
  ".lhci",
  ".lighthouseci",
  "blob-report",
  "coverage",
  "lighthouse-report",
  "lighthouse-reports",
  "playwright-report",
  "test-results",
]);

const SECURITY_CHECKS = Object.freeze(securityCheckDescriptors());

const KNOWN_SECRET_PATTERNS = Object.freeze([
  {
    label: "AWS access key",
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    severity: "critical",
  },
  {
    label: "GitHub access token",
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g,
    severity: "critical",
  },
  {
    label: "GitLab access token",
    regex: /\bglpat-[A-Za-z0-9_-]{20,255}\b/g,
    severity: "critical",
  },
  {
    label: "Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g,
    severity: "critical",
  },
  {
    label: "Stripe live secret key",
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b/g,
    severity: "critical",
  },
  {
    label: "npm access token",
    regex: /\bnpm_[A-Za-z0-9]{20,255}\b/g,
    severity: "critical",
  },
  {
    label: "Google API key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "high",
  },
  {
    label: "JSON Web Token",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    severity: "high",
    validate: (value) => isSyntacticallyValidJwt(value),
  },
  {
    label: "OpenAI API key",
    regex: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{24,255}\b/g,
    severity: "critical",
  },
  {
    label: "Anthropic API key",
    regex: /\bsk-ant-api\d{2}-[A-Za-z0-9_-]{32,255}\b/g,
    severity: "critical",
  },
  {
    label: "SendGrid API key",
    regex: /\bSG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{40,50}\b/g,
    severity: "critical",
  },
  {
    label: "Google OAuth client secret",
    regex: /\bGOCSPX-[A-Za-z0-9_-]{20,64}\b/g,
    severity: "critical",
  },
  {
    label: "Twilio API key",
    regex: /\bSK[a-fA-F0-9]{32}\b/g,
    severity: "high",
  },
]);

const WEB_DEPENDENCIES = new Set([
  "next", "nuxt", "vite", "react", "react-dom", "vue", "@angular/core", "svelte",
  "@sveltejs/kit", "astro", "gatsby", "solid-js", "@remix-run/react", "express",
]);

function normalizedRelative(file) {
  return String(file?.relative ?? "").replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();
}

const AUXILIARY_TOP_LEVEL_DIRECTORIES = new Set([
  ".storybook", "coverage", "demo", "demos", "docs", "documentation", "example", "examples",
  "fixture", "fixtures", "generated", "mocks", "spec", "specs", "stories", "storybook",
  "test", "tests", "testing",
]);

function candidateWorkspaceRoots(files) {
  const roots = new Set([""]);
  for (const file of files) {
    const relative = normalizedRelative(file);
    if (path.posix.basename(relative) !== "package.json") continue;
    const directory = path.posix.dirname(relative);
    if (directory === ".") continue;
    const firstSegment = directory.split("/")[0];
    if (!AUXILIARY_TOP_LEVEL_DIRECTORIES.has(firstSegment)) roots.add(directory);
  }
  return roots;
}

function isProductionFrameworkRoute(file, workspaceRoots = new Set([""])) {
  const relative = normalizedRelative(file);
  const scopedPaths = [relative];
  for (const root of workspaceRoots) {
    if (!root) continue;
    const prefix = `${root.replace(/\/$/, "")}/`;
    if (relative.startsWith(prefix)) scopedPaths.push(relative.slice(prefix.length));
  }
  const conventionalWorkspace = relative.match(/^(?:apps|packages|sites)\/[^/]+\/(.+)$/)?.[1];
  if (conventionalWorkspace) scopedPaths.push(conventionalWorkspace);
  return scopedPaths.some((candidate) => /^(?:src\/)?(?:app|pages|routes)(?:\/|$)/.test(candidate));
}

function isDocumentationFile(file, workspaceRoots) {
  if (isProductionFrameworkRoute(file, workspaceRoots)) return false;
  return /(^|\/)(?:docs?|documentation|examples?)(\/|$)/i.test(file.relative)
    || /\.(?:md|mdx|rst|adoc)$/i.test(file.relative);
}

function isGeneratedAuditArtifact(file) {
  const relative = normalizedRelative(file);
  return relative.split("/").some((segment) => GENERATED_AUDIT_DIRECTORIES.has(segment));
}

function isGeneratedFile(file, workspaceRoots) {
  const relative = normalizedRelative(file);
  if (/(?:\.min\.(?:js|css)|\.map)$/i.test(file.relative)) return true;
  if (isProductionFrameworkRoute(file, workspaceRoots)) return false;
  if (isGeneratedAuditArtifact(file)) return true;
  return /(?:^|\/)(?:generated|fixtures?|snapshots?)(?:\/|$)/i.test(file.relative);
}

function isLikelyTestArtifact(file, workspaceRoots) {
  if (/\.(?:test|spec)\.[^/]+$/i.test(file.relative)) return true;
  const sourceName = path.posix.basename(normalizedRelative(file));
  const sourceStem = sourceName.replace(/\.(?:[cm]?[jt]sx?|json|ya?ml)$/i, "");
  if (sourceStem !== sourceName && /(?:^|[._-])(?:mock|fixture)(?:[._-]|$)/i.test(sourceStem)) return true;
  if (/(?:^|\/)\.env\.(?:test|testing)(?:\.local)?$/i.test(file.relative)) return true;
  if (/(?:^|\/)[^/]+\.(?:test|spec|fixture)\.(?:json|ya?ml|toml|ini|conf|config)$/i.test(file.relative)) return true;
  if (isProductionFrameworkRoute(file, workspaceRoots)) return false;
  return isTestFile(file);
}

function credentialSignatureContext(file, workspaceRoots, originalSeverity) {
  const environment = isEnvironmentFile(file)
    && !/\.env\.(?:example|sample|template|defaults?)(?:\.|$)/i.test(file.relative);
  const fixture = isLikelyTestArtifact(file, workspaceRoots)
    || /(?:^|\/)fixtures?(?:\/|$)/i.test(normalizedRelative(file));
  if (fixture) {
    return {
      fixture: true,
      severity: originalSeverity === "critical" ? "medium" : "low",
      confidence: "medium",
      manual: true,
    };
  }
  return {
    fixture: false,
    environment,
    severity: environment ? "medium" : originalSeverity,
    confidence: environment ? "medium" : "high",
    manual: environment,
  };
}

function isEnvironmentFile(file) {
  return /(?:^|\/)\.env(?:\.[^/]+)?$/i.test(file.relative);
}

function publicConfigurationOnly(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() && !/^\s*#/.test(line));
  return lines.length > 0 && lines.every((line) => {
    const match = /^\s*(?:export\s+)?((?:VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)[A-Z0-9_]+)\s*=\s*([^#\r\n]*)/.exec(line);
    if (!match || isSecretValueName(match[1])) return false;
    const value = match[2].trim().replace(/^(["'])(.*)\1$/, "$2");
    if (matchesKnownSecretSignature(value)) return false;
    if (/^(?:true|false|\d{1,5}|development|production|test)$/i.test(value)) return true;
    if (/^\/[A-Za-z0-9_./-]*$/.test(value)) return true;
    try {
      const url = new URL(value);
      return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password && !url.search && !url.hash;
    } catch { return false; }
  });
}

function gitignoreGlobSource(pattern) {
  let source = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*" && pattern[index + 1] === "*") {
      if (pattern[index + 2] === "/") {
        source += "(?:.*/)?";
        index += 2;
      } else {
        source += ".*";
        index += 1;
      }
    } else if (character === "*") {
      source += "[^/]*";
    } else if (character === "?") {
      source += "[^/]";
    } else {
      source += escapeRegex(character);
    }
  }
  return source;
}

function gitignoreRuleMatches(relative, rawPattern) {
  let pattern = rawPattern;
  const anchored = pattern.startsWith("/");
  if (anchored) pattern = pattern.slice(1);
  const directoryOnly = pattern.endsWith("/");
  if (directoryOnly) pattern = pattern.slice(0, -1);
  if (!pattern) return false;
  const source = gitignoreGlobSource(pattern);
  const prefix = anchored || pattern.includes("/") ? "^" : "(?:^|/)";
  const suffix = directoryOnly ? "(?:/|$)" : "$";
  return new RegExp(`${prefix}${source}${suffix}`, process.platform === "win32" ? "i" : "").test(relative);
}

function environmentIgnoreState(environmentFile, gitignores) {
  const relative = String(environmentFile.relative ?? "").replace(/\\/g, "/").replace(/^\.\//, "");
  const applicable = gitignores
    .map((entry) => {
      const ignorePath = String(entry.file.relative ?? "").replace(/\\/g, "/").replace(/^\.\//, "");
      const directory = path.posix.dirname(ignorePath);
      const root = directory === "." ? "" : directory;
      if (root && relative !== root && !relative.startsWith(`${root}/`)) return null;
      return {
        ...entry,
        root,
        target: root ? relative.slice(root.length + 1) : relative,
      };
    })
    .filter(Boolean)
    .sort((left, right) => left.root.split("/").filter(Boolean).length - right.root.split("/").filter(Boolean).length
      || left.root.localeCompare(right.root));
  let ignored = false;
  let source = null;
  for (const entry of applicable) {
    for (const rawLine of entry.text.split(/\r?\n/)) {
      let line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const negated = line.startsWith("!");
      if (negated) line = line.slice(1);
      if (!line || !gitignoreRuleMatches(entry.target, line)) continue;
      ignored = !negated;
      source = entry.file;
    }
  }
  return { ignored, source };
}

function isSecurityConfigFile(file) {
  const name = normalizeName(file);
  if (isEnvironmentFile(file)) return true;
  if ([
    "package.json", ".npmrc", ".yarnrc", ".yarnrc.yml", ".gitignore", "dockerfile",
    "vercel.json", "netlify.toml", "firebase.json", "wrangler.toml", "nginx.conf",
    "httpd.conf", ".htaccess", "_headers", "headers.json", "manifest.json",
  ].includes(name)) return true;
  return /(?:^|\/)(?:next|nuxt|vite|webpack|rollup|astro|svelte|remix|gatsby|angular|vue|server|security|headers|csp)[^/]*\.(?:js|cjs|mjs|ts|cts|mts|json|ya?ml|toml)$/i.test(file.relative)
    || /\.(?:json|ya?ml|toml|ini|conf|config|tf|tfvars)$/i.test(file.relative);
}

function isHeaderConfigFile(file) {
  const name = normalizeName(file);
  if ([
    "vercel.json", "netlify.toml", "firebase.json", "wrangler.toml", "nginx.conf",
    "httpd.conf", ".htaccess", "_headers", "headers.json", "dockerfile",
  ].includes(name)) return true;
  if (/^dockerfile(?:[._-]|$)/i.test(name)) return true;
  return /(?:^|\/)(?:next|nuxt|astro|svelte|remix|gatsby)[^/]*\.config\.(?:js|cjs|mjs|ts|cts|mts)$/i.test(file.relative)
    || /(?:^|\/)(?:server|middleware|headers)\.(?:js|cjs|mjs|ts|cts|mts)$/i.test(file.relative);
}

function isRelevantFile(file, options, workspaceRoots) {
  if (!file?.relative || LOCKFILE_NAMES.has(normalizeName(file))) return false;
  if (isDocumentationFile(file, workspaceRoots)) return false;
  if (isGeneratedFile(file, workspaceRoots) && options.includeGenerated !== true) return false;
  if (isLikelyTestArtifact(file, workspaceRoots) && options.includeTests !== true) return false;
  return isSourceFile(file) || isStyleFile(file) || isSecurityConfigFile(file);
}

function isLocalizationResource(file) {
  const relative = normalizedRelative(file);
  return /(?:^|\/)(?:i18n|locales?|translations?)(?:\/|$)/i.test(relative)
    || /(?:^|\/)(?:messages?|strings?)(?:\.[A-Za-z]{2}(?:-[A-Za-z0-9]+)?)?\.json$/i.test(relative);
}

function supportsGenericSecretAssignments(file, options, workspaceRoots) {
  if (!file?.relative || LOCKFILE_NAMES.has(normalizeName(file))) return false;
  const relative = normalizedRelative(file);
  if (isGeneratedAuditArtifact(file) || isLocalizationResource(file)) return false;
  if (/(?:\.min\.(?:js|css)|\.map)$/i.test(relative)
    || relative.split("/").some((segment) => ["generated", "snapshot", "snapshots"].includes(segment))) return false;
  if ((isLikelyTestArtifact(file, workspaceRoots) || /(?:^|\/)e2e(?:\/|$)/i.test(relative))
    && options.includeTests !== true) return false;
  if (isDocumentationFile(file, workspaceRoots)) return false;
  return isSourceFile(file) || isSecurityConfigFile(file) || isEnvironmentFile(file);
}

function findingSourcePriority(finding, relevantPaths, filesByPath, workspaceRoots) {
  const relative = String(finding.file ?? "");
  const file = filesByPath.get(relative);
  if (!file) return 3;
  if (isGeneratedFile(file, workspaceRoots)) return 4;
  if (isLocalizationResource(file)) return 3;
  if (isLikelyTestArtifact(file, workspaceRoots)) return 2;
  if (relevantPaths.has(relative) || isEnvironmentFile(file) || isSecurityConfigFile(file)) return 0;
  return 1;
}

function compareFindingPriority(left, right, relevantPaths, filesByPath, workspaceRoots) {
  const severity = (SEVERITY_RANK[left.severity] ?? 99) - (SEVERITY_RANK[right.severity] ?? 99);
  if (severity !== 0) return severity;
  const confidence = (CONFIDENCE_RANK[left.confidence] ?? 99) - (CONFIDENCE_RANK[right.confidence] ?? 99);
  if (confidence !== 0) return confidence;
  const source = findingSourcePriority(left, relevantPaths, filesByPath, workspaceRoots)
    - findingSourcePriority(right, relevantPaths, filesByPath, workspaceRoots);
  if (source !== 0) return source;
  if (left.manual !== right.manual) return left.manual ? 1 : -1;
  const file = String(left.file ?? "").localeCompare(String(right.file ?? ""));
  if (file !== 0) return file;
  return Number(left.line ?? 0) - Number(right.line ?? 0);
}

function lineTextAt(text, index) {
  const start = text.lastIndexOf("\n", Math.max(0, index - 1)) + 1;
  const endIndex = text.indexOf("\n", index);
  const end = endIndex === -1 ? text.length : endIndex;
  return text.slice(start, end).trim();
}

function localEvidenceAt(text, index) {
  const tail = text.slice(index, Math.min(text.length, index + 160));
  const lineEnd = tail.search(/[\r\n]/);
  const statementEnd = tail.indexOf(";");
  const candidates = [lineEnd, statementEnd === -1 ? -1 : statementEnd + 1].filter((value) => value > 0);
  const end = candidates.length > 0 ? Math.min(...candidates) : Math.min(tail.length, 96);
  return tail.slice(0, end).trim();
}

function isInsideRegexLiteral(text, index) {
  const lineStart = text.lastIndexOf("\n", Math.max(0, index - 1)) + 1;
  const lineEndIndex = text.indexOf("\n", index);
  const lineEnd = lineEndIndex === -1 ? text.length : lineEndIndex;
  const line = text.slice(lineStart, lineEnd);
  const column = index - lineStart;

  for (let cursor = 0; cursor < line.length; cursor += 1) {
    if (line[cursor] !== "/" || line[cursor + 1] === "/" || line[cursor + 1] === "*") continue;
    let previous = cursor - 1;
    while (previous >= 0 && /\s/.test(line[previous])) previous -= 1;
    if (previous >= 0 && !/[=(:,!&|?{;\[]/.test(line[previous])) continue;

    let escaped = false;
    let characterClass = false;
    for (let end = cursor + 1; end < line.length; end += 1) {
      const character = line[end];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        continue;
      }
      if (character === "[") characterClass = true;
      else if (character === "]") characterClass = false;
      else if (character === "/" && !characterClass) {
        if (column >= cursor && column <= end) return true;
        cursor = end;
        break;
      }
    }
  }
  return false;
}

function isCommentOnlyMatch(text, index) {
  const line = lineTextAt(text, index);
  return /^(?:\/\/|\/\*|\*|<!--|#(?![A-Fa-f0-9]{3,8}\b))/.test(line)
    || isInsideRegexLiteral(text, index);
}

function stripCommentsForHeaderDetection(value) {
  const text = String(value ?? "");
  let output = "";
  let quote = null;
  let escaped = false;
  let lineOnlyWhitespace = true;

  for (let index = 0; index < text.length;) {
    const character = text[index];
    if (quote) {
      output += character;
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      if (character === "\n") lineOnlyWhitespace = true;
      else if (!/\s/.test(character)) lineOnlyWhitespace = false;
      index += 1;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
      output += character;
      lineOnlyWhitespace = false;
      index += 1;
      continue;
    }
    if (text.startsWith("<!--", index)) {
      const end = text.indexOf("-->", index + 4);
      const comment = text.slice(index, end === -1 ? text.length : end + 3);
      output += comment.replace(/[^\r\n]/g, " ");
      lineOnlyWhitespace = /(?:^|\n)[\t ]*$/.test(output);
      index += comment.length;
      continue;
    }
    if (text.startsWith("/*", index)) {
      const end = text.indexOf("*/", index + 2);
      const comment = text.slice(index, end === -1 ? text.length : end + 2);
      output += comment.replace(/[^\r\n]/g, " ");
      lineOnlyWhitespace = /(?:^|\n)[\t ]*$/.test(output);
      index += comment.length;
      continue;
    }
    if (text.startsWith("//", index) || (character === "#" && lineOnlyWhitespace)) {
      const end = text.indexOf("\n", index);
      const commentEnd = end === -1 ? text.length : end;
      output += text.slice(index, commentEnd).replace(/[^\r\n]/g, " ");
      index = commentEnd;
      continue;
    }
    output += character;
    if (character === "\n") lineOnlyWhitespace = true;
    else if (!/\s/.test(character)) lineOnlyWhitespace = false;
    index += 1;
  }
  return output;
}

function maskCommentsForSast(value, file) {
  const text = String(value ?? "");
  const extension = String(file?.extension ?? path.extname(file?.relative ?? "")).toLowerCase();
  const markupMode = [".html", ".htm", ".svg", ".xml"].includes(extension);
  const supportsLineComments = ![".css", ".html", ".htm", ".svg", ".xml"].includes(extension);
  let output = "";
  let quote = null;
  let escaped = false;
  let inTag = false;

  function maskThrough(start, terminator) {
    const terminatorIndex = text.indexOf(terminator, start);
    const end = terminatorIndex === -1 ? text.length : terminatorIndex + terminator.length;
    output += text.slice(start, end).replace(/[^\r\n]/g, " ");
    return end;
  }

  for (let index = 0; index < text.length;) {
    const character = text[index];
    if (quote) {
      output += character;
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      index += 1;
      continue;
    }
    if (text.startsWith("<!--", index)) {
      index = maskThrough(index, "-->");
      continue;
    }
    if (text.startsWith("/*", index)) {
      index = maskThrough(index, "*/");
      continue;
    }
    if (supportsLineComments && text.startsWith("//", index)) {
      const prefix = text.slice(Math.max(0, index - 48), index);
      const isProtocolSeparator = /[A-Za-z][A-Za-z0-9+.-]*:$/.test(prefix);
      if (!isProtocolSeparator) {
        const newline = text.indexOf("\n", index);
        const end = newline === -1 ? text.length : newline;
        output += text.slice(index, end).replace(/[^\r\n]/g, " ");
        index = end;
        continue;
      }
    }
    if (markupMode) {
      if (character === "<") inTag = true;
      else if (character === ">") inTag = false;
    }
    if ((!markupMode || inTag) && (character === "\"" || character === "'" || character === "`")) {
      quote = character;
      output += character;
      index += 1;
      continue;
    }
    output += character;
    index += 1;
  }
  return output;
}

function matchingBlockEnd(text, openingBrace) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let index = openingBrace; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "{") depth += 1;
    else if (character === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function isDevelopmentOnlyCondition(value) {
  const condition = String(value ?? "").trim().replace(/^\((.*)\)$/s, "$1");
  if (/^(?:import\.meta\.env\.DEV|!\s*import\.meta\.env\.PROD)(?:\s*&&[\s\S]+)?$/.test(condition)) return true;
  const environmentComparison = /(?:\b(?:[A-Za-z_$][\w$]*\.)*(?:nodeEnv|NODE_ENV)\b|\bprocess\.env\.NODE_ENV\b)\s*={2,3}\s*["'](?:development|test)["']/gi;
  const hasEnvironmentComparison = environmentComparison.test(condition);
  environmentComparison.lastIndex = 0;
  const remainder = condition
    .replace(environmentComparison, "")
    .replace(/[()\s|]/g, "");
  return remainder === "" && hasEnvironmentComparison;
}

function isInsideDevelopmentGuard(text, index) {
  const guard = /\bif\s*\(/g;
  for (const match of text.matchAll(guard)) {
    if (match.index > index) break;
    const openingParenthesis = match.index + match[0].lastIndexOf("(");
    const conditionEnd = readBalancedEnd(text, openingParenthesis);
    if (conditionEnd <= openingParenthesis || !isDevelopmentOnlyCondition(text.slice(openingParenthesis + 1, conditionEnd - 1))) continue;
    let openingBrace = conditionEnd;
    while (openingBrace < text.length && /\s/.test(text[openingBrace])) openingBrace += 1;
    if (text[openingBrace] !== "{") continue;
    const closingBrace = matchingBlockEnd(text, openingBrace);
    if (closingBrace >= index) return true;
  }
  const developmentTernary = /\bimport\.meta\.env\.DEV\s*\?/g;
  for (const match of text.matchAll(developmentTernary)) {
    if (match.index > index) break;
    let valueStart = match.index + match[0].length;
    while (valueStart < text.length && /\s/.test(text[valueStart])) valueStart += 1;
    if (!["\"", "'", "`"].includes(text[valueStart])) continue;
    const valueEnd = readQuotedEnd(text, valueStart);
    if (valueStart <= index && index < valueEnd && /^\s*:/.test(text.slice(valueEnd, valueEnd + 20))) return true;
  }
  return false;
}

function isXmlNamespaceReference(text, index) {
  const lineStart = text.lastIndexOf("\n", Math.max(0, index - 1)) + 1;
  const lineEndIndex = text.indexOf("\n", index);
  const lineEnd = lineEndIndex === -1 ? text.length : lineEndIndex;
  const line = text.slice(lineStart, lineEnd);
  const namespace = /\bxmlns(?::[A-Za-z_][\w.-]*)?\s*=\s*["'](https?:\/\/[^"']+)["']/gi;
  for (const match of line.matchAll(namespace)) {
    const valueOffset = match[0].lastIndexOf(match[1]);
    const valueStart = lineStart + match.index + valueOffset;
    if (valueStart <= index && index < valueStart + match[1].length) return true;
  }
  return false;
}

function isInternalProxyUrl(text, index, url) {
  if (!/\bproxy_pass\s+/i.test(lineTextAt(text, index))) return false;
  const hostname = /^https?:\/\/(\[[^\]]+\]|[^/:;]+)/i.exec(url)?.[1]?.replace(/^\[|\]$/g, "").toLowerCase();
  if (!hostname) return false;
  return !hostname.includes(".")
    || hostname === "localhost"
    || hostname === "::1"
    || /^127\./.test(hostname)
    || /^10\./.test(hostname)
    || /^192\.168\./.test(hostname)
    || /^172\.(?:1[6-9]|2\d|3[01])\./.test(hostname);
}

function isInternalContainerUrl(file, text, index, url) {
  if (!/^docker-compose(?:[._-][^/]*)?\.ya?ml$/i.test(normalizeName(file))) return false;
  if (!/\b(?:health(?:check)?(?:_url)?|readiness|readyz|curl|wget)\b/i.test(lineTextAt(text, index))) return false;
  const hostname = /^https?:\/\/(\[[^\]]+\]|[^/:;]+)/i.exec(url)?.[1]?.replace(/^\[|\]$/g, "").toLowerCase();
  return Boolean(hostname) && !hostname.includes(".") && hostname !== "localhost";
}

function isInsideNetworkCall(text, start, end) {
  const networkCall = /\b(?:fetch|request|got|axios\s*\.\s*(?:get|post|put|patch|delete|request)|(?:http|https)\s*\.\s*(?:get|request))\s*\(/g;
  for (const match of text.matchAll(networkCall)) {
    if (match.index > start) break;
    const opening = match.index + match[0].lastIndexOf("(");
    const callEnd = readBalancedEnd(text, opening);
    if (opening < start && end <= callEnd) return true;
  }
  return false;
}

function isUrlParserReference(text, index) {
  const constructor = /\bnew\s+URL\s*\(/g;
  for (const match of text.matchAll(constructor)) {
    if (match.index > index) break;
    const openingParenthesis = match.index + match[0].lastIndexOf("(");
    const callEnd = readBalancedEnd(text, openingParenthesis);
    if (!(openingParenthesis < index && index < callEnd)) continue;

    let argumentIndex = 0;
    let depth = 0;
    let quote = null;
    let escaped = false;
    for (let cursor = openingParenthesis + 1; cursor < index; cursor += 1) {
      const character = text[cursor];
      if (quote) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === quote) quote = null;
        continue;
      }
      if (character === "\"" || character === "'" || character === "`") {
        quote = character;
        continue;
      }
      if (character === "(" || character === "[" || character === "{") depth += 1;
      else if (character === ")" || character === "]" || character === "}") depth = Math.max(0, depth - 1);
      else if (character === "," && depth === 0) argumentIndex += 1;
    }

    // URL construction inside a network sink remains transport evidence even
    // when the plaintext string is the base argument or a parsed component is
    // selected before the call.
    if (isInsideNetworkCall(text, match.index, callEnd)) return false;

    // Outside network use, a base argument or component read is parser and
    // normalization context rather than proof of a request.
    if (argumentIndex > 0) return true;
    const suffix = text.slice(callEnd, callEnd + 80);
    if (/^\s*\.\s*(?:host|hostname|origin|pathname|port|protocol|search|searchParams|username|password)\b/.test(suffix)) return true;

    const lineStart = text.lastIndexOf("\n", Math.max(0, match.index - 1)) + 1;
    const declarationPrefix = text.slice(lineStart, match.index);
    const assignedName = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*$/.exec(declarationPrefix)?.[1];
    if (assignedName) {
      const reference = new RegExp(String.raw`\b${escapeRegex(assignedName)}\b`, "g");
      const remainder = text.slice(callEnd);
      let parserReads = 0;
      let hasNonParserUse = false;
      for (const use of remainder.matchAll(reference)) {
        const following = remainder.slice(use.index + use[0].length);
        if (/^\s*\.\s*(?:host|hostname|origin|pathname|port|protocol|search|searchParams|username|password)\b/.test(following)) {
          parserReads += 1;
        } else {
          hasNonParserUse = true;
          break;
        }
      }
      if (!hasNonParserUse) return true;
    }
  }
  return false;
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function expressionAt(text, start, { commaTerminates = false } = {}) {
  let cursor = start;
  while (cursor < text.length && /[ \t]/.test(text[cursor])) cursor += 1;
  const expressionStart = cursor;
  const stack = [];
  let quote = null;
  let escaped = false;
  for (; cursor < text.length; cursor += 1) {
    const character = text[cursor];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "(" || character === "[" || character === "{") {
      stack.push(character);
      continue;
    }
    if (character === ")" || character === "]" || character === "}") {
      if (stack.length === 0) break;
      stack.pop();
      continue;
    }
    if (stack.length === 0 && (character === ";" || character === "\r" || character === "\n" || (commaTerminates && character === ","))) break;
  }
  return text.slice(expressionStart, cursor).trim();
}

function domPurifySanitizerCallees(text) {
  const bindings = new Set();
  for (const match of text.matchAll(/\bimport\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}\r\n]*\})?\s+from\s*["']dompurify["']/g)) bindings.add(match[1]);
  for (const match of text.matchAll(/\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*["']dompurify["']/g)) bindings.add(match[1]);
  for (const match of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']dompurify["']\s*\)/g)) bindings.add(match[1]);
  return new Set([...bindings].map((binding) => `${binding}.sanitize`));
}

function sanitizerCallSource(callees) {
  const sources = [...callees].map(escapeRegex);
  return sources.length > 0 ? `(?:${sources.join("|")})` : "(?!)";
}

function exactSanitizerCallExpression(expression, callees) {
  let candidate = String(expression ?? "").trim().replace(/;\s*$/, "").trim();
  while (candidate.startsWith("(") && readBalancedEnd(candidate, 0) === candidate.length) candidate = candidate.slice(1, -1).trim();
  const call = new RegExp(String.raw`^(?:await\s+)?${sanitizerCallSource(callees)}\s*\(`, "i").exec(candidate);
  if (!call) return false;
  const openingParenthesis = call[0].lastIndexOf("(");
  return readBalancedEnd(candidate, openingParenthesis) === candidate.length;
}

function namedFunctionBlocks(text) {
  const blocks = [];
  const declarations = /\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)(?:\s*:\s*[^\{\r\n]+)?\s*\{/g;
  for (const match of text.matchAll(declarations)) {
    const openingBrace = match.index + match[0].lastIndexOf("{");
    const closingBrace = matchingBlockEnd(text, openingBrace);
    if (closingBrace !== -1) blocks.push({ name: match[1], start: openingBrace, end: closingBrace, body: text.slice(openingBrace + 1, closingBrace) });
  }
  const arrows = /\bconst\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{/g;
  for (const match of text.matchAll(arrows)) {
    const openingBrace = match.index + match[0].lastIndexOf("{");
    const closingBrace = matchingBlockEnd(text, openingBrace);
    if (closingBrace !== -1) blocks.push({ name: match[1], start: openingBrace, end: closingBrace, body: text.slice(openingBrace + 1, closingBrace) });
  }
  return blocks;
}

function verifiedHtmlSanitizerNames(text, directCallees, functionBlocks) {
  const names = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    const callees = new Set([...directCallees, ...names]);
    for (const block of functionBlocks) {
      if (names.has(block.name)) continue;
      const returns = [...block.body.matchAll(/\breturn\s+/g)];
      if (returns.length === 0) continue;
      if (!returns.every((match) => exactSanitizerCallExpression(expressionAt(block.body, match.index + match[0].length), callees))) continue;
      names.add(block.name);
      changed = true;
    }
  }
  return names;
}

function providerFunctionAt(functionBlocks, index) {
  return functionBlocks
    .filter((block) => block.start < index && index < block.end)
    .sort((left, right) => right.start - left.start)[0]?.name ?? null;
}

function addSanitizedProperty(properties, property, sourceFile, provider) {
  if (!provider) return;
  const normalized = property.toLowerCase();
  const contracts = properties.get(normalized) ?? [];
  if (!contracts.some((contract) => contract.sourceFile === sourceFile && contract.provider === provider)) {
    contracts.push({ sourceFile, provider });
  }
  properties.set(normalized, contracts);
}

function lexicalScopeAt(text, index) {
  let best = { start: 0, end: text.length };
  for (let cursor = 0; cursor < index; cursor += 1) {
    if (text[cursor] !== "{") continue;
    const end = matchingBlockEnd(text, cursor);
    if (end >= index && cursor >= best.start) best = { start: cursor, end };
  }
  return best;
}

function sanitizedVariableVisible(variables, name, index) {
  return variables.some((variable) => variable.name === name
    && variable.index < index
    && variable.scope.start < index
    && index < variable.scope.end);
}

function sanitizedHtmlContracts(scannedContents) {
  const variablesByFile = new Map();
  const calleesByFile = new Map();
  const properties = new Map();
  for (const { file, text } of scannedContents) {
    const analysisText = maskCommentsForSast(text, file);
    const functionBlocks = namedFunctionBlocks(analysisText);
    const directCallees = domPurifySanitizerCallees(analysisText);
    const sanitizers = verifiedHtmlSanitizerNames(analysisText, directCallees, functionBlocks);
    const callees = new Set([...directCallees, ...sanitizers]);
    calleesByFile.set(file.relative, callees);

    const variables = [];
    const assignment = /\bconst\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*/g;
    for (const match of analysisText.matchAll(assignment)) {
      const expression = expressionAt(analysisText, match.index + match[0].length);
      if (exactSanitizerCallExpression(expression, callees)) {
        variables.push({ name: match[1], index: match.index, scope: lexicalScopeAt(analysisText, match.index) });
      }
    }
    variablesByFile.set(file.relative, variables);

    const directProperty = /\b([A-Za-z_$][\w$]*(?:html|markup)[\w$]*)\s*:\s*/gi;
    for (const match of analysisText.matchAll(directProperty)) {
      const expression = expressionAt(analysisText, match.index + match[0].length, { commaTerminates: true });
      if (exactSanitizerCallExpression(expression, callees)) {
        addSanitizedProperty(properties, match[1], file.relative, providerFunctionAt(functionBlocks, match.index));
      }
    }

    const aliasedProperty = /\b([A-Za-z_$][\w$]*(?:html|markup)[\w$]*)\s*:\s*([A-Za-z_$][\w$]*)\s*(?=[,}\r\n])/gi;
    for (const match of analysisText.matchAll(aliasedProperty)) {
      if (sanitizedVariableVisible(variables, match[2], match.index)) {
        addSanitizedProperty(properties, match[1], file.relative, providerFunctionAt(functionBlocks, match.index));
      }
    }
  }
  return { variablesByFile, calleesByFile, properties };
}

function normalizedModuleReference(value) {
  return String(value ?? "")
    .replace(/\\/g, "/")
    .replace(/^(?:~|@)?\//, "")
    .replace(/^(?:\.\.\/|\.\/)+/, "")
    .replace(/\.(?:[cm]?[jt]sx?)$/i, "");
}

function moduleReferenceMatchesSource(reference, sourceFile, consumerFile) {
  const rawReference = String(reference ?? "").replace(/\\/g, "/");
  const source = normalizedRelative({ relative: sourceFile }).replace(/\.(?:[cm]?[jt]sx?)$/i, "");
  const consumer = normalizedRelative({ relative: consumerFile });
  let resolved;
  if (/^\.\.?\//.test(rawReference)) {
    resolved = path.posix.normalize(path.posix.join(path.posix.dirname(consumer), rawReference));
  } else if (/^(?:~|@)\//.test(rawReference)) {
    const sourceRootIndex = consumer.lastIndexOf("/src/");
    const sourceRoot = sourceRootIndex === -1 ? "src" : consumer.slice(0, sourceRootIndex + 4);
    resolved = path.posix.join(sourceRoot, rawReference.slice(2));
  } else {
    resolved = normalizedModuleReference(rawReference);
  }
  resolved = resolved.replace(/\.(?:[cm]?[jt]sx?)$/i, "");
  return resolved === source || `${resolved}/index` === source;
}

function importedProviderCallees(text, sourceFile, providers, consumerFile) {
  const callees = new Set();
  const imports = /\bimport\s+([^;\r\n]+?)\s+from\s*["'`]([^"'`]+)["'`]/g;
  for (const match of text.matchAll(imports)) {
    if (!moduleReferenceMatchesSource(match[2], sourceFile, consumerFile)) continue;
    const clause = match[1].trim();
    const namespace = /\*\s+as\s+([A-Za-z_$][\w$]*)/.exec(clause)?.[1];
    if (namespace) for (const provider of providers) callees.add(`${namespace}.${provider}`);
    const named = /\{([^}]*)\}/.exec(clause)?.[1];
    if (!named) continue;
    for (const item of named.split(",")) {
      const parts = item.trim().replace(/^type\s+/, "").split(/\s+as\s+/i);
      const imported = parts[0]?.trim();
      const local = parts[1]?.trim() ?? imported;
      if (providers.has(imported) && /^[A-Za-z_$][\w$]*$/.test(local)) callees.add(local);
    }
  }
  return callees;
}

function rootReceivesProviderValue(text, root, callees) {
  const escapedRoot = escapeRegex(root);
  const stateSetter = new RegExp(String.raw`\[\s*${escapedRoot}\s*,\s*([A-Za-z_$][\w$]*)\s*\]\s*=\s*(?:React\s*\.\s*)?useState\b`).exec(text)?.[1] ?? null;
  for (const callee of callees) {
    const escapedCallee = escapeRegex(callee).replace(/\\\./g, String.raw`\s*\.\s*`);
    const direct = new RegExp(String.raw`\bconst\s+${escapedRoot}(?:\s*:[^=;\r\n]+)?\s*=\s*(?:await\s+)?${escapedCallee}\s*\(`);
    if (direct.test(text)) return true;
    if (!stateSetter) continue;
    const invocation = new RegExp(String.raw`\b${escapedCallee}\s*\(`, "g");
    for (const match of text.matchAll(invocation)) {
      const openingParenthesis = match.index + match[0].lastIndexOf("(");
      const callEnd = readBalancedEnd(text, openingParenthesis);
      const chain = text.slice(callEnd, callEnd + 900);
      const callback = /\.\s*then\s*\(\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>[\s\S]{0,700}/.exec(chain);
      if (!callback) continue;
      const setter = new RegExp(String.raw`\b${escapeRegex(stateSetter)}\s*\(\s*${escapeRegex(callback[1])}\s*\)`).test(callback[0]);
      if (setter) return true;
    }
  }
  return false;
}

function htmlSinkExpression(text, index, label) {
  const nearby = text.slice(index, Math.min(text.length, index + 600));
  if (label === "dangerouslySetInnerHTML") return /__html\s*:\s*([^}\r\n,]+)/i.exec(nearby)?.[1]?.trim() ?? "";
  if (label === "innerHTML/outerHTML assignment") return /(?:innerHTML|outerHTML)\s*=\s*([^;\r\n]+)/i.exec(nearby)?.[1]?.trim() ?? "";
  if (label === "insertAdjacentHTML") return /insertAdjacentHTML\s*\([^,\r\n]+,\s*([^;)\r\n]+)/i.exec(nearby)?.[1]?.trim() ?? "";
  if (label === "v-html") return /v-html\s*=\s*["'{]\s*([^"'}\r\n]+)/i.exec(nearby)?.[1]?.trim() ?? "";
  if (label === "Svelte @html") return /\{@html\s+([^}\r\n]+)/i.exec(nearby)?.[1]?.trim() ?? "";
  return "";
}

function hasSanitizedHtmlContract({ file, text, index, label }, contracts) {
  const expression = htmlSinkExpression(text, index, label);
  if (!expression) return false;
  if (exactSanitizerCallExpression(expression, contracts.calleesByFile.get(file.relative) ?? new Set())) return true;

  const reference = /^([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)$/.exec(expression)?.[1]?.replace(/\s/g, "");
  if (!reference) return false;
  if (!reference.includes(".")) return sanitizedVariableVisible(contracts.variablesByFile.get(file.relative) ?? [], reference, index);

  const root = reference.split(".")[0];
  const property = reference.split(".").at(-1).toLowerCase();
  const propertyContracts = contracts.properties.get(property);
  if (!propertyContracts) return false;
  const grouped = new Map();
  for (const contract of propertyContracts) {
    const providers = grouped.get(contract.sourceFile) ?? new Set();
    providers.add(contract.provider);
    grouped.set(contract.sourceFile, providers);
  }
  for (const [sourceFile, providers] of grouped) {
    const callees = sourceFile === file.relative ? providers : importedProviderCallees(text, sourceFile, providers, file.relative);
    if (rootReceivesProviderValue(text, root, callees)) return true;
  }
  return false;
}

function sanitizeHtmlBindings(text) {
  const bindings = new Set();
  for (const match of text.matchAll(/\bimport\s+([A-Za-z_$][\w$]*)\s+from\s*["']sanitize-html["']/g)) bindings.add(match[1]);
  for (const match of text.matchAll(/\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*["']sanitize-html["']/g)) bindings.add(match[1]);
  for (const match of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']sanitize-html["']\s*\)/g)) bindings.add(match[1]);
  return bindings;
}

function storageKeysIn(text) {
  const keys = new Set();
  const storagePath = /\bpath\s*\.\s*(?:join|resolve)\s*\(\s*process\s*\.\s*cwd\s*\(\s*\)\s*,\s*["']([^"']{2,80})["']/g;
  for (const match of text.matchAll(storagePath)) keys.add(match[1].replace(/\\/g, "/").replace(/^\/+|\/+$/g, "").toLowerCase());
  return keys;
}

function propertyObject(value, property) {
  const marker = new RegExp(String.raw`(?:["']${escapeRegex(property)}["']|\b${escapeRegex(property)}\b)\s*:\s*\{`, "i").exec(value);
  if (!marker) return null;
  const openingBrace = marker.index + marker[0].lastIndexOf("{");
  const end = readBalancedEnd(value, openingBrace);
  return end > openingBrace ? value.slice(openingBrace, end) : null;
}

function verifiedLinkIsolationOptions(text, bindings) {
  const options = new Map();
  const optionDeclaration = /\bconst\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*\{/g;
  for (const declaration of text.matchAll(optionDeclaration)) {
    const openingBrace = declaration.index + declaration[0].lastIndexOf("{");
    const end = readBalancedEnd(text, openingBrace);
    if (end <= openingBrace) continue;
    const object = text.slice(openingBrace, end);
    const transforms = propertyObject(object, "transformTags");
    const attributes = propertyObject(object, "allowedAttributes");
    if (!transforms || !attributes) continue;
    const allowedAnchor = /(?:["']a["']|\ba\b)\s*:\s*\[([^\]]*)\]/i.exec(attributes)?.[1] ?? "";
    if (!/["']rel["']/i.test(allowedAnchor)) continue;

    for (const binding of bindings) {
      const anchorTransform = new RegExp(
        String.raw`(?:["']a["']|\ba\b)\s*:\s*${escapeRegex(binding)}\s*\.\s*simpleTransform\s*\(`,
        "g",
      );
      for (const transform of transforms.matchAll(anchorTransform)) {
        const opening = transform.index + transform[0].lastIndexOf("(");
        const callEnd = readBalancedEnd(transforms, opening);
        const call = transforms.slice(transform.index, callEnd);
        if (/simpleTransform\s*\(\s*["']a["']/i.test(call)
          && /\btarget\s*:\s*["']_blank["']/i.test(call)
          && /\brel\s*:\s*["'][^"']*\b(?:noopener|noreferrer)\b[^"']*["']/i.test(call)) {
          options.set(declaration[1], binding);
          break;
        }
      }
    }
  }
  return options;
}

function exactSanitizeHtmlCall(expression, binding, option) {
  const candidate = String(expression ?? "").trim().replace(/;\s*$/, "").trim();
  const call = new RegExp(String.raw`^(?:await\s+)?${escapeRegex(binding)}\s*\(`).exec(candidate);
  if (!call) return false;
  const opening = call[0].lastIndexOf("(");
  const end = readBalancedEnd(candidate, opening);
  if (end !== candidate.length) return false;
  const argumentsText = candidate.slice(opening + 1, end - 1);
  return new RegExp(String.raw`,\s*${escapeRegex(option)}\s*$`).test(argumentsText);
}

function returnedSanitizedValue(expression, variable) {
  const candidate = String(expression ?? "").trim().replace(/;\s*$/, "").trim();
  if (candidate === variable) return true;
  if (/^`[\s\S]*`$/.test(candidate)) {
    const interpolations = [...candidate.matchAll(/\$\{([^}]*)\}/g)].map((match) => match[1].trim());
    return interpolations.length > 0 && interpolations.every((value) => value === variable);
  }
  const ternary = topLevelTernaryParts(candidate);
  return Boolean(ternary)
    && returnedSanitizedValue(ternary.whenTrue, variable)
    && returnedSanitizedValue(ternary.whenFalse, variable);
}

function verifiedLinkIsolationSanitizers(text, optionBindings) {
  const wrappers = new Set();
  for (const block of namedFunctionBlocks(text)) {
    for (const [option, binding] of optionBindings) {
      const directReturns = [...block.body.matchAll(/\breturn\s+/g)]
        .map((match) => expressionAt(block.body, match.index + match[0].length));
      if (directReturns.length > 0 && directReturns.every((expression) => exactSanitizeHtmlCall(expression, binding, option))) {
        wrappers.add(block.name);
        continue;
      }

      const results = new Set();
      const assignments = /\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*/g;
      for (const assignment of block.body.matchAll(assignments)) {
        const expression = expressionAt(block.body, assignment.index + assignment[0].length);
        if (exactSanitizeHtmlCall(expression, binding, option)) results.add(assignment[1]);
      }
      if (results.size === 0 || directReturns.length === 0) continue;
      if ([...results].some((result) => directReturns.every((expression) => returnedSanitizedValue(expression, result)))) wrappers.add(block.name);
    }
  }

  const arrows = /\bconst\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*/g;
  for (const declaration of text.matchAll(arrows)) {
    const expression = expressionAt(text, declaration.index + declaration[0].length);
    for (const [option, binding] of optionBindings) {
      if (exactSanitizeHtmlCall(expression, binding, option)) wrappers.add(declaration[1]);
    }
  }
  return wrappers;
}

function nestedFunctionRanges(text) {
  const ranges = [];
  const functions = /\bfunction(?:\s+[A-Za-z_$][\w$]*)?\s*\([^)]*\)(?:\s*:\s*[^\{\r\n]+)?\s*\{|=>\s*\{/g;
  for (const match of text.matchAll(functions)) {
    const openingBrace = match.index + match[0].lastIndexOf("{");
    const end = matchingBlockEnd(text, openingBrace);
    if (end !== -1) ranges.push({ start: openingBrace, end });
  }
  return ranges;
}

function insideFunctionRange(index, ranges) {
  return ranges.some((range) => range.start < index && index < range.end);
}

function storageBasesIn(text) {
  const bases = new Map();
  const declaration = /\bconst\s+([A-Za-z_$][\w$]*)[^=;\r\n]*=\s*path\s*\.\s*(?:join|resolve)\s*\(\s*process\s*\.\s*cwd\s*\(\s*\)\s*,\s*["']([^"']{2,80})["']/g;
  for (const match of text.matchAll(declaration)) {
    bases.set(match[1], match[2].replace(/\\/g, "/").replace(/^\/+|\/+$/g, "").toLowerCase());
  }
  return bases;
}

function readPathStorageKey(text, pathName, routeParameter) {
  const bases = storageBasesIn(text);
  for (const [base, key] of bases) {
    const assignment = new RegExp(
      String.raw`\bconst\s+${escapeRegex(pathName)}[^=;\r\n]*=\s*path\s*\.\s*(?:join|resolve)\s*\(\s*${escapeRegex(base)}\s*,[^;\r\n]{0,400}\b${escapeRegex(routeParameter)}\b`,
      "i",
    );
    if (assignment.test(text)) return key;
  }
  return null;
}

function externalLinkIsolationContracts(contents) {
  const contracts = [];
  for (const { file, text } of contents) {
    const analysisText = maskCommentsForSast(text, file);
    const bindings = sanitizeHtmlBindings(analysisText);
    if (bindings.size === 0) continue;
    const options = verifiedLinkIsolationOptions(analysisText, bindings);
    const wrappers = verifiedLinkIsolationSanitizers(analysisText, options);
    if (wrappers.size === 0) continue;

    const routes = /\.\s*(?:get|route)\s*\(\s*["']([^"']+\/:([A-Za-z_$][\w$]*))["'][\s\S]{0,800}?=>\s*\{/g;
    for (const route of analysisText.matchAll(routes)) {
      const openingBrace = route.index + route[0].lastIndexOf("{");
      const closingBrace = matchingBlockEnd(analysisText, openingBrace);
      if (closingBrace === -1) continue;
      const body = analysisText.slice(openingBrace + 1, closingBrace);
      const nested = nestedFunctionRanges(body);
      const reads = /\b(?:let|const|var)\s+([A-Za-z_$][\w$]*)[^=;\r\n]*=\s*(?:await\s+)?(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:readFile|readFileSync)\s*\(\s*([A-Za-z_$][\w$]*)/g;
      for (const read of body.matchAll(reads)) {
        if (insideFunctionRange(read.index, nested)) continue;
        const contentName = read[1];
        const storageKey = readPathStorageKey(body, read[2], route[2]);
        if (!storageKey) continue;
        for (const wrapper of wrappers) {
          const sanitize = new RegExp(String.raw`\b${escapeRegex(contentName)}\s*=\s*(?:await\s+)?${escapeRegex(wrapper)}\s*\(\s*${escapeRegex(contentName)}\s*\)`, "g");
          const sanitizeMatch = [...body.matchAll(sanitize)].find((match) => match.index > read.index && !insideFunctionRange(match.index, nested));
          if (!sanitizeMatch) continue;
          const send = new RegExp(String.raw`\.\s*send\s*\(\s*${escapeRegex(contentName)}\s*\)`, "g");
          const sendMatch = [...body.matchAll(send)].find((match) => match.index > sanitizeMatch.index && !insideFunctionRange(match.index, nested));
          if (!sendMatch) continue;
          const routePrefix = route[1].slice(0, -(route[2].length + 2));
          const topic = path.posix.basename(routePrefix).replace(/s$/i, "").toLowerCase();
          if (topic.length >= 3) contracts.push({ topic, storageKey, sourceFile: file.relative });
          break;
        }
      }
    }
  }
  return contracts;
}

function activeStringStartsAt(text, target) {
  const stack = [{ type: "code" }];
  for (let index = 0; index < target; index += 1) {
    const frame = stack.at(-1);
    const character = text[index];
    if (frame.type === "string") {
      if (character === "\\") index += 1;
      else if (character === frame.quote) stack.pop();
      continue;
    }
    if (frame.type === "template") {
      if (character === "\\") index += 1;
      else if (character === "`") stack.pop();
      else if (character === "$" && text[index + 1] === "{") {
        stack.push({ type: "template-expression", braces: 1 });
        index += 1;
      }
      continue;
    }
    if (character === "\"" || character === "'") stack.push({ type: "string", quote: character, start: index });
    else if (character === "`") stack.push({ type: "template", start: index });
    else if (frame.type === "template-expression" && character === "{") frame.braces += 1;
    else if (frame.type === "template-expression" && character === "}") {
      frame.braces -= 1;
      if (frame.braces === 0) stack.pop();
    }
  }
  return stack.filter((frame) => Number.isSafeInteger(frame.start)).map((frame) => frame.start);
}

function linkBelongsToWrittenContent(text, linkIndex, contentName) {
  const assignment = new RegExp(String.raw`\b${escapeRegex(contentName)}\s*(?:\+?=)\s*$`);
  return activeStringStartsAt(text, linkIndex).some((start) => assignment.test(text.slice(Math.max(0, start - 500), start)));
}

function hasDownstreamLinkIsolationContract(link, contracts) {
  if (contracts.length === 0) return false;
  const bases = storageBasesIn(link.text);
  const writes = /\b(?:await\s+)?(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\b/g;
  for (const write of link.text.matchAll(writes)) {
    if (write.index < link.index || !linkBelongsToWrittenContent(link.text, link.index, write[2])) continue;
    for (const [base, storageKey] of bases) {
      const fileName = /\bconst\s+([A-Za-z_$][\w$]*)[^=;\r\n]*=\s*(`[^`]{1,1000}\.html`)/gi;
      for (const candidate of link.text.matchAll(fileName)) {
        if (candidate.index > write.index) continue;
        const pathAssignment = new RegExp(
          String.raw`\bconst\s+${escapeRegex(write[1])}[^=;\r\n]*=\s*path\s*\.\s*(?:join|resolve)\s*\(\s*${escapeRegex(base)}\s*,\s*${escapeRegex(candidate[1])}\b`,
          "i",
        );
        if (!pathAssignment.test(link.text.slice(0, write.index))) continue;
        for (const contract of contracts) {
          if (contract.storageKey !== storageKey) continue;
          if (new RegExp(String.raw`^\`${escapeRegex(contract.topic)}-\$\{`, "i").test(candidate[2])) return true;
        }
      }
    }
  }
  return false;
}

function readQuotedEnd(text, start) {
  const quote = text[start];
  let escaped = false;
  for (let index = start + 1; index < text.length; index += 1) {
    const character = text[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === quote) return index + 1;
  }
  return text.length;
}

function readBalancedEnd(text, start) {
  const open = text[start];
  const close = open === "[" ? "]" : open === "{" ? "}" : open === "(" ? ")" : null;
  if (!close) return start;
  let depth = 1;
  let quote = null;
  let escaped = false;
  for (let index = start + 1; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === open) depth += 1;
    else if (character === close) {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  return text.length;
}

function fixedDynamicImportBridge(text, index) {
  const openingParenthesis = text.indexOf("(", index);
  if (openingParenthesis === -1) return false;
  const callEnd = readBalancedEnd(text, openingParenthesis);
  const constructorArguments = text.slice(openingParenthesis + 1, Math.max(openingParenthesis + 1, callEnd - 1));
  const bridge = /^\s*(["'])specifier\1\s*,\s*(["'])\s*return\s+import\s*\(\s*specifier\s*\)\s*;?\s*\2\s*$/.exec(constructorArguments);
  if (!bridge) return false;

  const lineStart = text.lastIndexOf("\n", Math.max(0, index - 1)) + 1;
  const declaration = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$/.exec(text.slice(lineStart, index));
  if (!declaration) return false;
  const name = declaration[1];
  const reference = new RegExp(String.raw`\b${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\b`, "g");
  const remainder = text.slice(callEnd);
  let invocations = 0;
  for (const match of remainder.matchAll(reference)) {
    let cursor = match.index + match[0].length;
    while (cursor < remainder.length && /\s/.test(remainder[cursor])) cursor += 1;
    if (remainder[cursor] !== "(") return false;
    const invocationEnd = readBalancedEnd(remainder, cursor);
    const argument = remainder.slice(cursor + 1, Math.max(cursor + 1, invocationEnd - 1)).trim();
    if (!/^(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?![^`]*\$\{)(?:\\.|[^`\\])*`)$/s.test(argument)) return false;
    invocations += 1;
  }
  return invocations > 0;
}

function isNonSecurityFingerprintHash(file, text, index) {
  const start = Math.max(0, index - 900);
  const end = Math.min(text.length, index + 1_600);
  const context = text.slice(start, end);
  const statement = lineTextAt(text, index);
  if (!/\bcreateHash\s*\(\s*["'](?:md5|sha-?1)["']\s*\)\s*\.\s*update\s*\(/i.test(statement)) return false;
  if (/\b(?:password|passphrase|credential|signature|signing|hmac|authentication|authorization|accessToken|refreshToken|sessionToken|privateKey|secretKey)\b/i.test(context)) return false;
  if (/\b(?:cache|cached|cacheKey|redis|dedup(?:e|lication)?|duplicate|fingerprint|repeat(?:ed)?|cooldown|contentHash)\b/i.test(context)) return true;
  return /(?:^|\/)(?:moderation|xp)(?:\/|$)/i.test(normalizedRelative(file))
    && /\.update\s*\(\s*(?:JSON\.stringify\s*\()?\s*(?:content|input|text|imageUrl)\b/i.test(statement)
    && /\b(?:cache|redis|duplicate|repeat)\b/i.test(text);
}

function cookieCallAt(text, index) {
  const openingParenthesis = text.indexOf("(", index);
  if (openingParenthesis === -1) return null;
  const end = readBalancedEnd(text, openingParenthesis);
  if (end <= openingParenthesis) return null;
  const call = text.slice(index, end);
  const firstArgument = call.slice(call.indexOf("(") + 1).trimStart();
  const literalName = /^(?:"([^"\r\n]+)"|'([^'\r\n]+)'|`([^`$\r\n]+)`)/.exec(firstArgument);
  const identifierName = /^([A-Za-z_$][\w$]*)/.exec(firstArgument);
  return {
    call,
    name: literalName ? (literalName[1] ?? literalName[2] ?? literalName[3]) : (identifierName?.[1] ?? ""),
  };
}

function productionBooleanBefore(text, index, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const declaration = new RegExp(
    String.raw`\bconst\s+${escaped}\s*=\s*(?:(?:[A-Za-z_$][\w$]*\.)*(?:nodeEnv|NODE_ENV)|process\.env\.NODE_ENV)\s*={2,3}\s*["']production["']`,
    "gi",
  );
  let found = false;
  for (const match of text.slice(0, index).matchAll(declaration)) found = Boolean(match);
  return found;
}

function hasProductionSecureCookieOption(text, index, call) {
  if (/\bsecure\s*:\s*true\b/i.test(call)) return true;
  if (/\bsecure\s*:\s*(?:(?:[A-Za-z_$][\w$]*\.)*(?:nodeEnv|NODE_ENV)|process\.env\.NODE_ENV)\s*={2,3}\s*["']production["']/i.test(call)) return true;
  const assigned = /\bsecure\s*:\s*([A-Za-z_$][\w$]*)\b/i.exec(call)?.[1];
  if (assigned && productionBooleanBefore(text, index, assigned)) return true;
  if (/(?:^|[{,])\s*secure\s*(?=[,}])/i.test(call) && productionBooleanBefore(text, index, "secure")) return true;
  return false;
}

function hasProtectiveSameSiteOption(call) {
  const explicit = /\bsameSite\s*:\s*([^,}\r\n]+)/i.exec(call);
  if (explicit) return !/^\s*(?:false|null|undefined)\b/i.test(explicit[1]);
  return /(?:^|[{,])\s*sameSite\s*(?=[,}])/i.test(call);
}

function isCsrfCookieName(value) {
  return /(?:csrf|xsrf|anti[_-]?forgery)/i.test(String(value ?? ""));
}

function readValueRange(text, start) {
  let valueStart = start;
  while (valueStart < text.length && /\s/.test(text[valueStart])) valueStart += 1;
  if (valueStart >= text.length) return null;
  const character = text[valueStart];
  if (character === "\"" || character === "'" || character === "`") {
    return { start: valueStart, end: readQuotedEnd(text, valueStart) };
  }
  if (character === "[" || character === "{" || character === "(") {
    return { start: valueStart, end: readBalancedEnd(text, valueStart) };
  }
  const remainder = text.slice(valueStart);
  const terminator = remainder.search(/[;,\r\n]/);
  return { start: valueStart, end: terminator === -1 ? text.length : valueStart + terminator };
}

function enclosingQuoteRange(text, index) {
  let quote = null;
  let quoteStart = -1;
  let escaped = false;
  for (let cursor = 0; cursor < index; cursor += 1) {
    const character = text[cursor];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) {
        quote = null;
        quoteStart = -1;
      }
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      quoteStart = cursor;
    }
  }
  if (!quote || quoteStart < 0) return null;
  return { start: quoteStart, end: readQuotedEnd(text, quoteStart) };
}

function enclosingObjectRange(text, index) {
  const stack = [];
  let quote = null;
  let escaped = false;
  for (let cursor = 0; cursor <= index; cursor += 1) {
    const character = text[cursor];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "{") stack.push(cursor);
    else if (character === "}") stack.pop();
  }
  const start = stack.at(-1);
  if (start === undefined) return null;
  return { start, end: readBalancedEnd(text, start) };
}

function cspPolicyRanges(value) {
  const text = stripCommentsForHeaderDetection(value);
  const ranges = [];
  const marker = /\b(?:Content-Security-Policy|contentSecurityPolicy|content_security_policy)\b/gi;
  let match;
  while ((match = marker.exec(text)) !== null) {
    const lineStart = text.lastIndexOf("\n", Math.max(0, match.index - 1)) + 1;
    const lineEndIndex = text.indexOf("\n", match.index);
    const lineEnd = lineEndIndex === -1 ? text.length : lineEndIndex;
    const previousTagEnd = text.lastIndexOf(">", match.index);
    const tagStart = text.lastIndexOf("<", match.index);
    const tagEnd = text.indexOf(">", match.index);
    if (tagStart > previousTagEnd && tagEnd !== -1 && /^<meta\b/i.test(text.slice(tagStart, match.index))) {
      ranges.push({ start: tagStart, end: tagEnd + 1, text: text.slice(tagStart, tagEnd + 1) });
      continue;
    }

    const quoteRange = enclosingQuoteRange(text, match.index);
    if (quoteRange) {
      const quotedPolicy = text.slice(quoteRange.start, quoteRange.end);
      if (/\b(?:default-src|script-src|style-src|object-src|frame-ancestors)\b/i.test(quotedPolicy)) {
        ranges.push({ ...quoteRange, text: quotedPolicy });
        continue;
      }
    }

    const line = text.slice(lineStart, lineEnd);
    if (/\b(?:default-src|script-src|style-src|object-src|frame-ancestors)\b/i.test(line)) {
      ranges.push({ start: lineStart, end: lineEnd, text: line });
      continue;
    }

    let cursor = quoteRange?.end ?? match.index + match[0].length;
    while (cursor < text.length && /\s/.test(text[cursor])) cursor += 1;
    if (text[cursor] === ":" || text[cursor] === "=") {
      const range = readValueRange(text, cursor + 1);
      if (range) ranges.push({ ...range, text: text.slice(range.start, range.end) });
      continue;
    }

    const objectRange = enclosingObjectRange(text, match.index);
    if (!objectRange) continue;
    const afterMarker = text.slice(match.index + match[0].length, objectRange.end);
    const valueProperty = /\bvalue\s*:\s*/i.exec(afterMarker);
    if (!valueProperty) continue;
    const valueStart = match.index + match[0].length + valueProperty.index + valueProperty[0].length;
    const range = readValueRange(text, valueStart);
    if (range && range.end <= objectRange.end) {
      ranges.push({ ...range, text: text.slice(range.start, range.end) });
    }
  }
  return { text, ranges };
}

function cspWeaknesses(value) {
  const { ranges } = cspPolicyRanges(value);

  const results = [];
  const seen = new Set();
  for (const declaration of ranges) {
    const patterns = [
      {
        regex: /['"]?unsafe-eval['"]?/i,
        token: "'unsafe-eval'",
        severity: "high",
        description: "'unsafe-eval' permits string-to-code execution and substantially weakens CSP's XSS containment.",
        recommendation: "Remove string-to-code execution and omit 'unsafe-eval' from the deployed policy. Keep script-src limited to reviewed sources with nonces or hashes where inline scripts are unavoidable.",
      },
      {
        regex: /\bscript-src\b[^;\r\n]{0,500}(?:\s\*|\bdata:|\bhttps?:)(?=\s|[;'"`]|$)/i,
        token: "a wildcard, data:, or scheme-wide script-src source",
        severity: "high",
        description: "script-src trusts an open-ended source class, allowing scripts from far more locations than the application requires.",
        recommendation: "Replace open-ended script sources with the exact reviewed origins the application needs and use nonces or hashes for intentional inline scripts.",
      },
      {
        regex: /\b(?:default-src|object-src|frame-ancestors)\b[^;\r\n]{0,500}\s\*(?=\s|[;'"`]|$)/i,
        token: "a wildcard security boundary directive",
        severity: "medium",
        description: "A wildcard in default-src, object-src, or frame-ancestors leaves an important CSP boundary broadly permissive.",
        recommendation: "Replace the wildcard with explicit origins; use object-src 'none' and restrict frame-ancestors to the site's intended embedding policy.",
      },
      {
        regex: /\b(?:script-src(?:-elem|-attr)?|default-src)\b[^;\r\n]{0,500}['"]?unsafe-inline['"]?/i,
        token: "script-src 'unsafe-inline'",
        severity: "high",
        description: "'unsafe-inline' in a script policy permits inline JavaScript and substantially weakens CSP's XSS containment.",
        recommendation: "Remove script-src 'unsafe-inline' and authorize each required inline script with a per-response nonce or a reviewed content hash.",
      },
      {
        regex: /\bstyle-src(?:-elem|-attr)?\b[^;\r\n]{0,500}['"]?unsafe-inline['"]?/i,
        token: "style-src 'unsafe-inline'",
        severity: "low",
        description: "'unsafe-inline' in a style policy permits inline CSS. This is weaker than a nonce- or hash-based style policy, but it does not authorize inline JavaScript.",
        recommendation: "Move inline CSS to reviewed stylesheets where practical, or adopt style nonces or hashes before removing style-src 'unsafe-inline'. Verify framework compatibility in report-only mode first.",
      },
    ];
    for (const pattern of patterns) {
      const weakness = pattern.regex.exec(declaration.text);
      if (!weakness) continue;
      const policy = declaration.text.toLowerCase().replace(/\s+/g, " ").trim();
      const fingerprint = `${pattern.token}\u0000${policy}`;
      if (seen.has(fingerprint)) continue;
      seen.add(fingerprint);
      results.push({
        ...pattern,
        index: declaration.start + weakness.index,
      });
    }
  }
  return results;
}

function isBrowserUrlExtraction(value) {
  const referencesBrowserUrl = /(?:\b(?:window\.)?location\.(?:search|hash|href)\b|\bdocument\.(?:URL|referrer)\b)/i.test(value);
  const extractsDestination = /(?:\bnew\s+URLSearchParams\s*\(|\.searchParams\.get\s*\(|\b(?:decodeURIComponent|decodeURI)\s*\(|\b(?:window\.)?location\.(?:search|hash)\s*\.\s*(?:slice|substring|replace)\s*\(|\bdocument\.referrer\b)/i.test(value);
  return referencesBrowserUrl && extractsDestination;
}

function hasNavigationValidation(value, variable = "") {
  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const variableValidation = escaped
    ? new RegExp(`(?:\\b${escaped}\\s*\\.\\s*startsWith\\s*\\(\\s*["'\x60]\\/|\\ballowed(?:Origins?|Redirects?|Urls?)?\\s*\\.\\s*includes\\s*\\(\\s*${escaped}\\b|\\b(?:assert|ensure|sanitize|validate)(?:Redirect|Url|Navigation)\\s*\\(\\s*${escaped}\\b|\\.test\\s*\\(\\s*${escaped}\\s*\\))`, "i")
    : null;
  return /(?:allowed(?:Origins?|Redirects?|Urls?)?\.includes|(?:assert|ensure|sanitize|validate)(?:Redirect|Url|Navigation)|\.origin\s*===?\s*(?:window\.)?location\.origin|\.startsWith\s*\(\s*["'`]\/)/i.test(value)
    || variableValidation?.test(value) === true;
}

function isDirectlyUrlControlledNavigation(line) {
  const hasNavigationSink = /(?:\b(?:window\.)?location(?:\.href)?\s*=|\b(?:window\.)?location\.(?:assign|replace)\s*\(|\bwindow\.open\s*\()/i.test(line);
  if (!hasNavigationSink) return false;
  return isBrowserUrlExtraction(line) && !hasNavigationValidation(line);
}

function navigationSinkForVariable(line, variable) {
  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const sink = new RegExp(`(?:\\b(?:window\\.)?location(?:\\.href)?\\s*=\\s*${escaped}\\b|\\b(?:window\\.)?location\\.(?:assign|replace)\\s*\\(\\s*${escaped}\\b|\\bwindow\\.open\\s*\\(\\s*${escaped}\\b)`, "i");
  return sink.exec(line);
}

function untrustedNavigationMatches(value) {
  const text = stripCommentsForHeaderDetection(value);
  const lines = [];
  for (let start = 0; start < text.length;) {
    const newline = text.indexOf("\n", start);
    const end = newline === -1 ? text.length : newline;
    lines.push({ start, text: text.slice(start, end).replace(/\r$/, "") });
    start = newline === -1 ? text.length : newline + 1;
  }

  const results = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (isDirectlyUrlControlledNavigation(line.text)) {
      const sink = /(?:\b(?:window\.)?location(?:\.href)?\s*=|\b(?:window\.)?location\.(?:assign|replace)\s*\(|\bwindow\.open\s*\()/i.exec(line.text);
      if (sink) results.push({ index: line.start + sink.index, opensPopup: /window\.open/i.test(sink[0]), throughVariable: false });
    }

    const assignment = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\r\n]+)/.exec(line.text);
    if (!assignment || !isBrowserUrlExtraction(assignment[2]) || hasNavigationValidation(line.text, assignment[1])) continue;
    const variable = assignment[1];
    for (let candidateIndex = index + 1; candidateIndex < Math.min(lines.length, index + 7); candidateIndex += 1) {
      const candidate = lines[candidateIndex];
      if (!candidate.text.trim()) continue;
      if (hasNavigationValidation(candidate.text, variable)) break;
      const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      if (new RegExp(`(?:^|[^\\w$])${escaped}\\s*=(?!=)`).test(candidate.text)) break;
      const sink = navigationSinkForVariable(candidate.text, variable);
      if (!sink) continue;
      results.push({
        index: candidate.start + sink.index,
        opensPopup: /window\.open/i.test(sink[0]),
        throughVariable: true,
      });
      break;
    }
  }
  return results;
}

function openingTagAttributes(markup) {
  const attributes = new Map();
  let index = 1;
  while (index < markup.length && !/[\s/>]/.test(markup[index])) index += 1;
  while (index < markup.length) {
    while (index < markup.length && /\s/.test(markup[index])) index += 1;
    if (index >= markup.length || markup[index] === ">" || markup[index] === "/") break;
    if (markup[index] === "{") {
      const end = readBalancedEnd(markup, index);
      index = end > index ? end : index + 1;
      continue;
    }

    const nameStart = index;
    while (index < markup.length && !/[\s=/>]/.test(markup[index])) index += 1;
    const name = markup.slice(nameStart, index).toLowerCase();
    while (index < markup.length && /\s/.test(markup[index])) index += 1;
    let value = "";
    let dynamic = false;
    if (markup[index] === "=") {
      index += 1;
      while (index < markup.length && /\s/.test(markup[index])) index += 1;
      const opener = markup[index];
      if (opener === "\"" || opener === "'" || opener === "`") {
        const end = readQuotedEnd(markup, index);
        value = markup.slice(index + 1, Math.max(index + 1, end - 1));
        index = end;
      } else if (opener === "{") {
        const end = readBalancedEnd(markup, index);
        const expression = markup.slice(index + 1, Math.max(index + 1, end - 1)).trim();
        const literal = /^(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`)$/.exec(expression);
        if (literal) value = literal[1] ?? literal[2] ?? literal[3] ?? "";
        else {
          value = expression;
          dynamic = true;
        }
        index = end;
      } else {
        const valueStart = index;
        while (index < markup.length && !/[\s>]/.test(markup[index])) index += 1;
        value = markup.slice(valueStart, index);
      }
    }
    if (name) attributes.set(name, { name, value, dynamic, index: nameStart });
  }
  return attributes;
}

function forEachMatch(text, regex, callback) {
  regex.lastIndex = 0;
  let match;
  while ((match = regex.exec(text)) !== null) {
    callback(match);
    if (match[0].length === 0) regex.lastIndex += 1;
  }
}

function isSyntacticallyValidJwt(value) {
  const segments = String(value ?? "").split(".");
  if (segments.length !== 3) return false;
  try {
    const decode = (segment) => JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    const header = decode(segments[0]);
    const payload = decode(segments[1]);
    return Boolean(
      header && typeof header === "object" && !Array.isArray(header)
      && typeof header.alg === "string" && header.alg.length > 0
      && payload && typeof payload === "object" && !Array.isArray(payload),
    );
  } catch {
    return false;
  }
}

function matchesKnownSecretSignature(value) {
  const candidate = String(value ?? "");
  return KNOWN_SECRET_PATTERNS.some((pattern) => {
    pattern.regex.lastIndex = 0;
    const match = pattern.regex.exec(candidate);
    pattern.regex.lastIndex = 0;
    return Boolean(match && match[0] === candidate && (!pattern.validate || pattern.validate(candidate)));
  });
}

function looksLikePlaceholder(value) {
  const normalized = String(value).trim().toLowerCase();
  if (!normalized || normalized.length < 8) return true;
  if (/^(?:true|false|null|undefined|none)$/.test(normalized)) return true;
  if (/\$\{|process\.env|import\.meta\.env|env\[|secret\(|vault|keychain/.test(normalized)) return true;
  return /(?:example|sample|placeholder|changeme|change_me|replace[_ -]?me|your[_ -]|dummy|mock|fake|test(?:ing)?|todo|xxx+|<[^>]+>)/i.test(normalized);
}

function isSecretValueName(value) {
  const name = String(value ?? "");
  if (!isSensitiveCredentialName(name)) return false;
  if (/^(?:include|omit|same-origin|use)-credentials$/i.test(name)) return false;
  if (/^(?:GOOGLE_APPLICATION_CREDENTIALS|AWS_SHARED_CREDENTIALS_FILE)$/i.test(name)) return false;
  if (/(?:^|[_.-])(?:description|file|hint|label|level|message|path|placeholder|prefix|reason|role|state|status|system|systems|text|title|mode|policy|provider|authority|endpoint|timeout|ttl|type|name|strategy|algorithm|enabled|expired|lifetime|expiry|expires|max[_-]?age)$/i.test(name)) return false;
  if (/(?:Description|File|Hint|Label|Level|Message|Path|Placeholder|Prefix|Reason|Role|State|Status|System|Systems|Text|Title|Mode|Policy|Provider|Authority|Endpoint|Timeout|TTL|Type|Name|Strategy|Algorithm|Enabled|Expired|Lifetime|Expiry|Expires|MaxAge)$/.test(name)) return false;
  return true;
}

function looksLikeSymbolicCredentialDescriptor(value) {
  const normalized = String(value ?? "").trim();
  if (/^__[A-Za-z0-9_-]+__$/.test(normalized)) return true;
  if (/^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/.test(normalized)) return true;
  return /^(?:authenticated|unauthenticated|primary|secondary|two[_-]?factor|permissions?|expired|document|collection|root)$/i.test(normalized);
}

function isRejectedProductionCredentialDefault(text, assignment) {
  if (!/^(?:DEV|DEVELOPMENT|LOCAL|TEST)[_.-]/i.test(assignment.field)) return false;
  const escaped = assignment.field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const rejectsDefault = new RegExp(
    String.raw`\bif\s*\([^)]*(?:===|==)\s*${escaped}\b[^)]*\)\s*\{[\s\S]{0,800}?\b(?:addIssue|throw|error)\b`,
    "i",
  ).test(text);
  return rejectsDefault && /\b(?:NODE_ENV|nodeEnv)\b[^\r\n]{0,100}["']production["']/i.test(text);
}

function isTernaryLiteralPair(text, assignment) {
  if (!assignment.quoted) return false;
  const lineStart = text.lastIndexOf("\n", Math.max(0, assignment.index - 1)) + 1;
  const prefix = text.slice(lineStart, assignment.index);
  const question = prefix.lastIndexOf("?");
  const objectBoundary = Math.max(prefix.lastIndexOf("{"), prefix.lastIndexOf("["));
  return question > objectBoundary;
}

function literalCredentialValues(assignment) {
  if (assignment.quoted) return [assignment.value.slice(1, -1)];
  // Object/function containers commonly hold provider metadata and dynamic
  // references. Their sensitive nested properties are discovered separately;
  // only a direct token/credential array is treated as a literal container.
  if (!assignment.structured || !assignment.value.startsWith("[")) return [];
  return [...assignment.value.matchAll(/"((?:\\.|[^"\\\r\n])*)"|'((?:\\.|[^'\\\r\n])*)'|`((?:\\.|[^`\\\r\n])*)`/g)]
    .map((match) => match[1] ?? match[2] ?? match[3] ?? "")
    .filter((value) => !isSensitiveCredentialName(value));
}

function topLevelTernaryParts(expression) {
  let question = -1;
  let colon = -1;
  const stack = [];
  let quote = null;
  let escaped = false;
  for (let index = 0; index < expression.length; index += 1) {
    const character = expression[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "(" || character === "[" || character === "{") stack.push(character);
    else if (character === ")" || character === "]" || character === "}") stack.pop();
    else if (stack.length === 0 && character === "?" && expression[index + 1] !== "?" && question === -1) question = index;
    else if (stack.length === 0 && character === ":" && question !== -1) {
      colon = index;
      break;
    }
  }
  if (question === -1 || colon === -1) return null;
  return {
    condition: expression.slice(0, question).trim(),
    whenTrue: expression.slice(question + 1, colon).trim(),
    whenFalse: expression.slice(colon + 1).trim(),
  };
}

function literalStringValue(expression) {
  let value = String(expression ?? "").trim();
  while (value.startsWith("(") && readBalancedEnd(value, 0) === value.length) value = value.slice(1, -1).trim();
  const match = /^(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|`((?![^`]*\$\{)(?:\\.|[^`\\])*)`)$/s.exec(value);
  return match ? (match[1] ?? match[2] ?? match[3] ?? "") : null;
}

function nonProductionTernaryBranch(condition) {
  const normalized = String(condition ?? "").replace(/[()\s]/g, "");
  if (/^(?:process\.env\.)?NODE_ENV={2,3}["']production["']$/i.test(normalized)
    || /^(?:[A-Za-z_$][\w$]*\.)*nodeEnv={2,3}["']production["']$/.test(normalized)
    || /^(?:import\.meta\.env\.)?PROD$/.test(normalized)) return "false";
  if (/^(?:process\.env\.)?NODE_ENV!={1,2}["']production["']$/i.test(normalized)
    || /^(?:[A-Za-z_$][\w$]*\.)*nodeEnv!={1,2}["']production["']$/.test(normalized)
    || /^!(?:import\.meta\.env\.)?PROD$/.test(normalized)
    || /^(?:import\.meta\.env\.)?DEV$/.test(normalized)) return "true";
  return null;
}

function credentialFallbackLiteralValues(text, assignment) {
  const expression = expressionAt(text, assignment.valueStart, { commaTerminates: true });
  if (!/\bprocess\s*\.\s*env(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[)/.test(expression)) return [];
  const values = [];
  const fallback = /(?:\|\||\?\?)\s*("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|`(?![^`]*\$\{)(?:\\.|[^`\\\r\n])*`)/g;
  for (const match of expression.matchAll(fallback)) {
    const value = literalStringValue(match[1]);
    if (value !== null) values.push(value);
  }

  const ternary = topLevelTernaryParts(expression);
  if (ternary) {
    const nonProductionBranch = nonProductionTernaryBranch(ternary.condition);
    const trueValue = literalStringValue(ternary.whenTrue);
    const falseValue = literalStringValue(ternary.whenFalse);
    if (trueValue !== null && nonProductionBranch !== "true") values.push(trueValue);
    if (falseValue !== null && nonProductionBranch !== "false") values.push(falseValue);
  }
  return unique(values);
}

function relativeDirectory(file) {
  const relative = String(file?.relative ?? "").replace(/\\/g, "/");
  const directory = path.posix.dirname(relative);
  return directory === "." ? "" : directory;
}

function relativeJoin(directory, name) {
  return directory ? path.posix.join(directory, name) : name;
}

function frameworkConfigSuggestions(dependencies, files) {
  const records = files
    .map((file) => ({
      name: normalizeName(file),
      relative: String(file?.relative ?? "").replace(/\\/g, "/"),
    }))
    .filter(({ relative }) => relative)
    .sort((left, right) => left.relative.localeCompare(right.relative));
  const matchingPaths = (pattern) => records
    .filter(({ name }) => pattern.test(name))
    .map(({ relative }) => relative);
  const suggestions = [];
  if (dependencies.has("next")) {
    const configs = matchingPaths(/^next\.config\./);
    suggestions.push(...(configs.length > 0 ? configs : ["next.config.js"]));
  }
  if (dependencies.has("nuxt")) {
    const configs = matchingPaths(/^nuxt\.config\./);
    suggestions.push(...(configs.length > 0 ? configs : ["nuxt.config.ts"]));
  }
  if (dependencies.has("@sveltejs/kit")) {
    const hooks = matchingPaths(/^hooks\.server\.[cm]?[jt]s$/);
    const configs = matchingPaths(/^svelte\.config\./);
    suggestions.push(...(hooks.length > 0
      ? hooks
      : configs.length > 0
        ? configs.map((relative) => path.posix.join(path.posix.dirname(relative), "src/hooks.server.js"))
        : ["src/hooks.server.js"]));
  }
  if (dependencies.has("express")) {
    const servers = matchingPaths(/^(?:server|app)\.[cm]?[jt]s$/);
    suggestions.push(servers[0] ?? "server.js");
  }
  suggestions.push(...matchingPaths(/^vercel\.json$/));
  suggestions.push(...matchingPaths(/^netlify\.toml$/));
  suggestions.push(...matchingPaths(/^_headers$/));
  suggestions.push(...matchingPaths(/^dockerfile(?:[._-]|$)/));
  return unique(suggestions).slice(0, 4);
}

/**
 * Run dependency/configuration checks and lightweight frontend SAST over a collected repository.
 */
export async function runSecurityScan({ root = process.cwd(), files = [], skipped = {}, onProgress, options = {} } = {}) {
  const startedAt = Date.now();
  const inputFiles = (Array.isArray(files) ? files : [])
    .slice()
    .sort((left, right) => String(left?.relative ?? left?.absolute ?? "")
      .localeCompare(String(right?.relative ?? right?.absolute ?? "")));
  // `webDetection` is descriptive metadata from an earlier pipeline stage, not
  // authority to bypass the public scanner API's website-only contract.
  const project = await detectWebProject({ root, files: inputFiles });
  if (!project?.isWebsite) {
    const reason = project?.reasons?.length ? ` ${project.reasons.join(" ")}` : "";
    const error = new Error(`Modular could not verify that this repository contains a website.${reason}`);
    error.code = "NOT_A_WEBSITE";
    error.details = project;
    throw error;
  }

  const findings = [];
  const findingCounts = new Map();
  const observedFindingCounts = new Map();
  const suppressedByRule = {};
  const suppressedSeverityByRule = {};
  const requestedFindingLimit = Number(options.maxFindingsPerRule ?? 50);
  const maxFindingsPerRule = Number.isFinite(requestedFindingLimit)
    ? Math.max(1, Math.floor(requestedFindingLimit))
    : 50;
  const workspaceRoots = candidateWorkspaceRoots(inputFiles);
  const relevantFiles = inputFiles.filter((file) => isRelevantFile(file, options, workspaceRoots));
  const relevantPaths = new Set(relevantFiles.map((file) => file.relative));
  const filesByPath = new Map(inputFiles.map((file) => [file.relative, file]));
  // The public scanner API accepts caller-supplied descriptors, so repeat the
  // collector's audit-artifact exclusion here. Otherwise a Playwright HTML
  // report can be recursively scanned as if it were application source.
  const inspectionFiles = inputFiles.filter((file) => (
    file?.relative && file.contentReadable !== false && !isGeneratedAuditArtifact(file)
  ));
  const scannedContents = [];
  const allReadableContents = [];
  const pendingHtmlSinks = [];
  const pendingBlankLinks = [];
  let unreadableFiles = 0;

  const findingIndex = createFindingIndex("security");
  function addFinding(ruleId, input) {
    const mapping = securityStandards(ruleId);
    const candidate = createFinding({
      id: `security.${ruleId}`,
      confidence: "high",
      description: "",
      recommendation: "",
      evidence: "",
      suggestedFiles: input.file ? [input.file] : [],
      tags: ["security"],
      standards: mapping.standards,
      references: mapping.references,
      ...input,
      evidence: sanitizeEvidence(input.evidence),
      suggestedFiles: unique(input.suggestedFiles ?? (input.file ? [input.file] : [])),
      tags: unique(["security", ...(input.tags ?? [])]),
      standards: input.standards ?? mapping.standards,
      references: unique([...mapping.references, ...(input.references ?? [])]),
    });
    findingIndex.record(candidate);
    observedFindingCounts.set(ruleId, (observedFindingCounts.get(ruleId) ?? 0) + 1);
    const count = findingCounts.get(ruleId) ?? 0;
    if (count >= maxFindingsPerRule) {
      suppressedByRule[ruleId] = (suppressedByRule[ruleId] ?? 0) + 1;
      const retainedIndices = findings.flatMap((finding, index) => (
        finding.id === candidate.id ? [index] : []
      ));
      const lowestPriorityIndex = retainedIndices.reduce((selected, index) => (
        selected === null || compareFindingPriority(
          findings[index],
          findings[selected],
          relevantPaths,
          filesByPath,
          workspaceRoots,
        ) > 0
          ? index
          : selected
      ), null);
      const replaceRetained = lowestPriorityIndex !== null
        && compareFindingPriority(
          candidate,
          findings[lowestPriorityIndex],
          relevantPaths,
          filesByPath,
          workspaceRoots,
        ) < 0;
      const suppressedSeverity = replaceRetained ? findings[lowestPriorityIndex].severity : candidate.severity;
      suppressedSeverityByRule[ruleId] ??= {};
      suppressedSeverityByRule[ruleId][suppressedSeverity] = (suppressedSeverityByRule[ruleId][suppressedSeverity] ?? 0) + 1;
      if (replaceRetained) findings[lowestPriorityIndex] = candidate;
      return;
    }
    findingCounts.set(ruleId, count + 1);
    findings.push(candidate);
  }

  function addAt(ruleId, file, text, index, input) {
    addFinding(ruleId, {
      file: file.relative,
      line: lineOf(text, index),
      evidence: localEvidenceAt(text, index),
      suggestedFiles: [file.relative],
      ...input,
    });
  }

  for (let index = 0; index < inspectionFiles.length; index += 1) {
    const file = inspectionFiles[index];
    if (onProgress) {
      await Promise.resolve(onProgress({
        phase: "security",
        current: index + 1,
        total: inspectionFiles.length,
        file: file.relative,
        check: "static-analysis",
      }));
    }

    let text = await readTextFile(file, { root });
    if (text === null) {
      unreadableFiles += 1;
      continue;
    }
    allReadableContents.push({ file, text });

    const credentialSignatureRanges = [];
    for (const pattern of KNOWN_SECRET_PATTERNS) {
      forEachMatch(text, pattern.regex, (match) => {
        if (pattern.validate && !pattern.validate(match[0])) return;
        credentialSignatureRanges.push({ start: match.index, end: match.index + match[0].length });
        const context = credentialSignatureContext(file, workspaceRoots, pattern.severity);
        addAt("embedded-secrets", file, text, match.index, {
          title: context.fixture
            ? `${pattern.label}-shaped value appears in a test or fixture`
            : context.environment ? `${pattern.label}-shaped value appears in a local environment file`
              : `${pattern.label}-shaped value appears in scanned source`,
          category: "Secrets",
          severity: context.severity,
          confidence: context.confidence,
          manual: context.manual,
          description: context.fixture
            ? "A credential-shaped value is present in test or fixture code. It may be intentionally synthetic; static matching cannot establish whether it is active or was exposed."
            : context.environment
              ? "A provider-shaped credential is present in a local environment file. Its presence does not establish whether it is tracked, bundled, deployed, or previously exposed."
              : "A credential-shaped value is present in scanned source. Static matching cannot establish whether the value is active, tracked, bundled, or previously exposed.",
          recommendation: context.fixture
            ? "Confirm that the fixture is synthetic and cannot authenticate anywhere. Replace it with an unmistakable non-secret fixture if practical; rotate only if it is confirmed to be a real exposed credential."
            : "Verify the value's provenance and whether it was committed, published, logged, or bundled. If it is a real exposed credential, revoke and rotate it, remove it from history, and load the replacement from a trusted secret store.",
          evidence: `${pattern.label} detected: <redacted>`,
          tags: context.fixture ? ["credential", "secret", "fixture", "manual-review"] : ["credential", "secret"],
        });
      });
    }

    forEachMatch(text, /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g, (match) => {
      const context = credentialSignatureContext(file, workspaceRoots, "critical");
      addAt("embedded-secrets", file, text, match.index, {
        title: context.fixture ? "Private-key marker appears in a test or fixture" : "Private-key marker appears in scanned source",
        category: "Secrets",
        severity: context.severity,
        confidence: context.confidence,
        manual: context.manual,
        description: context.fixture
          ? "A PEM private-key marker was found in test or fixture code. The marker may wrap synthetic data; static matching cannot establish that it is a usable key."
          : "A PEM private-key marker was found in scanned source. Static matching cannot establish whether the material is usable, tracked, or exposed.",
        recommendation: context.fixture
          ? "Confirm the fixture is deliberately synthetic. If it contains a real private key, determine exposure and replace it; otherwise keep the fixture visibly non-production."
          : "Verify whether this is valid private-key material and whether it was committed or shared. If exposure is confirmed, revoke or replace it, store the replacement in a secret manager, and purge exposed history.",
        evidence: "Private key material detected: <redacted>",
        tags: context.fixture ? ["credential", "private-key", "fixture", "manual-review"] : ["credential", "private-key"],
      });
    });

    if (supportsGenericSecretAssignments(file, options, workspaceRoots)) {
      for (const assignment of findSensitiveAssignments(text)) {
        if (!isSecretValueName(assignment.field)) continue;
        if (isTernaryLiteralPair(text, assignment)) continue;
        if (isRejectedProductionCredentialDefault(text, assignment)) continue;
        const directLiteralValues = literalCredentialValues(assignment)
          .filter((value) => !looksLikePlaceholder(value) && !looksLikeSymbolicCredentialDescriptor(value));
        const fallbackLiteralValues = credentialFallbackLiteralValues(text, assignment)
          .filter((value) => !looksLikePlaceholder(value) && !looksLikeSymbolicCredentialDescriptor(value));
        const literalValues = unique([...directLiteralValues, ...fallbackLiteralValues])
          .filter((value) => !matchesKnownSecretSignature(value));
        if (literalValues.length === 0) continue;
        const environmentFallback = directLiteralValues.length === 0 && fallbackLiteralValues.length > 0;
        addAt("embedded-secrets", file, text, assignment.index, {
          title: environmentFallback ? "Environment-backed credential has a literal fallback" : "Credential-like value is hardcoded",
          category: "Secrets",
          severity: /pass(?:word|phrase|code)|private|signing|secret|credential|jwt|auth|cookie/i.test(assignment.field) ? "high" : "medium",
          confidence: Math.max(...literalValues.map((value) => value.length)) >= 16 ? "high" : "medium",
          description: environmentFallback
            ? `${assignment.field} falls back from process.env to literal credential material when the environment value is absent.`
            : `The value assigned to ${assignment.field} looks like credential material and may be committed or shipped to the browser.`,
          recommendation: environmentFallback
            ? "Fail closed when the environment value is missing in production. Keep development defaults inside an explicit non-production branch and use an unmistakably synthetic value."
            : "Verify that the value is genuine and reaches a credential boundary. If it is real and was exposed, rotate it; then remove it from source and retrieve the replacement only in trusted server-side code from environment or secret storage.",
          evidence: `${assignment.field} = <redacted>${environmentFallback ? " (environment fallback)" : ""}`,
          tags: environmentFallback ? ["credential", "hardcoded", "environment", "fallback"] : ["credential", "hardcoded"],
        });
      }
    }

    if (isEnvironmentFile(file)) {
      const dotenvSecret = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*([^#\r\n]*)[^\r\n]*$/gm;
      forEachMatch(text, dotenvSecret, (match) => {
        const value = match[2].trim().replace(/^(["'])(.*)\1$/, "$2");
        const valueStart = match.index + match[0].indexOf(match[2]);
        if (credentialSignatureRanges.some((range) => range.start >= valueStart && range.end <= valueStart + match[2].length)) return;
        if (!isSecretValueName(match[1]) || looksLikePlaceholder(value) || matchesKnownSecretSignature(value)) return;
        addAt("embedded-secrets", file, text, match.index, {
          title: "Environment file contains a non-placeholder credential value",
          category: "Secrets",
          severity: "medium",
          confidence: "medium",
          manual: true,
          description: `${match[1]} contains a non-placeholder value in a local environment file. Its presence in the scan root does not prove that the file is tracked, deployed, or previously exposed.`,
          recommendation: "Verify whether the value is real and whether the file is ignored, tracked, copied into an image, logged, or present in repository history. Rotate only if exposure is confirmed; keep real environment files out of version control and examples placeholder-only.",
          evidence: `${match[1]}=<redacted>`,
          tags: ["credential", "environment", "manual-review"],
        });
      });
    }

    if (!relevantPaths.has(file.relative)) continue;
    text = maskCommentsForSast(text, file);
    scannedContents.push({ file, text });

    for (const signal of [
      ...configurationSecuritySignals(file, text),
      ...serverDataFlowSignals(file, text),
      ...workflowSecuritySignals(file, text),
      ...jwtValidationSignals(file, text),
    ]) {
      addAt(signal.ruleId, file, text, signal.index, signal);
    }

    const publicEnv = /\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|PRIVATE|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|REFRESH_TOKEN|SIGNING_KEY)[A-Z0-9_]*)\b/gi;
    forEachMatch(text, publicEnv, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      const publicApiIdentifier = /API_KEY/i.test(match[1]) && !/(?:SECRET|PRIVATE|TOKEN|PASSWORD|PASSWD)/i.test(match[1]);
      addAt("public-env-secrets", file, text, match.index, {
        title: "Sensitive environment variable is exposed to client code",
        category: "Secrets",
        severity: publicApiIdentifier ? "medium" : "high",
        confidence: publicApiIdentifier ? "medium" : "high",
        description: `${match[1]} uses a framework prefix that deliberately embeds its value in browser-delivered code.`,
        recommendation: publicApiIdentifier
          ? "Confirm that this key is intentionally public, apply provider-side origin/API/quota restrictions, and move privileged API calls to a server endpoint."
          : "Rename and consume the variable only in server-side code. Expose a narrow server endpoint when the browser needs a privileged operation.",
        evidence: `Public client environment variable: ${match[1]}`,
        tags: ["environment", "client-bundle"],
      });
    });

    const htmlSinks = [
      { regex: /\.innerHTML\s*=|\.outerHTML\s*=/g, label: "innerHTML/outerHTML assignment" },
      { regex: /\.insertAdjacentHTML\s*\(/g, label: "insertAdjacentHTML" },
      { regex: /\bdangerouslySetInnerHTML\s*=/g, label: "dangerouslySetInnerHTML" },
      { regex: /\bv-html\s*=/g, label: "v-html" },
      { regex: /\{@html\s+/g, label: "Svelte @html" },
    ];
    for (const sink of htmlSinks) {
      forEachMatch(text, sink.regex, (match) => {
        if (isCommentOnlyMatch(text, match.index)) return;
        pendingHtmlSinks.push({ file, text, index: match.index, label: sink.label });
      });
    }

    forEachMatch(text, /\bdocument\.(?:write|writeln)\s*\(/g, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      addAt("dom-xss", file, text, match.index, {
        title: "document.write can inject active content",
        category: "Application Security",
        severity: "high",
        description: "document.write parses its argument as HTML and can turn untrusted data into executable markup.",
        recommendation: "Replace document.write with safe DOM construction and assign dynamic values through textContent or escaped framework templates.",
        tags: ["xss", "dom"],
      });
    });

    const dynamicCodePatterns = [
      { regex: /(^|[^.\w])eval\s*\(/gm, label: "eval" },
      { regex: /\bnew\s+Function\s*\(/g, label: "new Function" },
      { regex: /\b(?:setTimeout|setInterval)\s*\(\s*["'`]/g, label: "string-based timer" },
    ];
    for (const dynamicCode of dynamicCodePatterns) {
      forEachMatch(text, dynamicCode.regex, (match) => {
        const actualIndex = match.index + (match[1]?.length ?? 0);
        if (isCommentOnlyMatch(text, actualIndex)) return;
        const fixedImportBridge = dynamicCode.label === "new Function" && fixedDynamicImportBridge(text, actualIndex);
        addAt("dynamic-code", file, text, actualIndex, {
          title: fixedImportBridge ? "Dynamic-import compatibility bridge compiles a fixed string" : "Dynamic code execution is enabled",
          category: "Application Security",
          severity: fixedImportBridge ? "low" : "high",
          confidence: fixedImportBridge ? "medium" : "high",
          manual: fixedImportBridge,
          description: fixedImportBridge
            ? "The Function body is fixed and every visible bridge invocation uses a string literal, so no data-driven injection path is visible. It still relies on string code generation, which conflicts with strict browser CSP unsafe-eval restrictions and hardened runtimes that disable code generation from strings."
            : `${dynamicCode.label} executes a string as code, turning an injection bug into script execution and forcing weaker CSP settings.`,
          recommendation: fixedImportBridge
            ? "Confirm this module is server-only and permitted by the deployed runtime. Prefer native import(), an ESM boundary, or supported CommonJS interoperability so the application can run without unsafe-eval or string code-generation allowances."
            : "Replace string evaluation with explicit functions, structured data parsing, or a small allowlist of supported operations.",
          tags: fixedImportBridge ? ["csp", "runtime-hardening", "interop", "manual-review"] : ["code-injection", "csp"],
        });
      });
    }

    forEachMatch(text, /\b(?:http|ws):\/\/[^\s"'`<>)]+/gi, (match) => {
      const url = match[0];
      if (isCommentOnlyMatch(text, match.index)) return;
      if (isInsideDevelopmentGuard(text, match.index)) return;
      if (isXmlNamespaceReference(text, match.index)) return;
      if (isUrlParserReference(text, match.index)) return;
      if (/^(?:http|ws):\/\/(?:localhost|127(?:\.\d+){3}|0\.0\.0\.0|\[::1\])(?::(?:\d+|\*))?(?:\/|$)/i.test(url)) return;
      if (/^http:\/\/(?:www\.)?(?:w3\.org|schema\.org|purl\.org|xmlns\.com|sitemaps\.org)\//i.test(url)) return;
      const internalProxy = isInternalProxyUrl(text, match.index, url);
      const internalContainer = isInternalContainerUrl(file, text, match.index, url);
      const internalTransport = internalProxy || internalContainer;
      addAt("insecure-transport", file, text, match.index, {
        title: internalTransport
          ? internalProxy ? "Internal reverse proxy uses plaintext transport" : "Internal container healthcheck uses plaintext transport"
          : url.toLowerCase().startsWith("ws:") ? "Unencrypted WebSocket endpoint is used" : "Unencrypted HTTP endpoint is used",
        category: "Transport Security",
        severity: internalTransport ? "low" : "medium",
        confidence: internalTransport ? "medium" : "high",
        manual: internalTransport,
        description: internalTransport
          ? internalProxy
            ? "A reverse proxy forwards traffic to a private service name over HTTP. Whether this crosses an untrusted network boundary depends on the deployment topology."
            : "A container healthcheck contacts a service name over HTTP. This is normally confined to the Compose network, but static analysis cannot prove the deployed network boundary."
          : "Traffic to this endpoint can be read or modified in transit and may be blocked as mixed content on HTTPS pages.",
        recommendation: internalTransport
          ? "Confirm the upstream is isolated to a trusted loopback, pod, or container network. Use authenticated TLS when traffic crosses hosts or any shared/untrusted network."
          : `Use ${url.toLowerCase().startsWith("ws:") ? "wss://" : "https://"} and verify that the destination has a valid certificate.`,
        tags: internalTransport
          ? ["transport", internalProxy ? "reverse-proxy" : "container-network", "manual-review"]
          : ["transport", "mixed-content"],
      });
    });

    const disabledTls = /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b|\brejectUnauthorized\s*:\s*false\b|\bstrict-ssl\s*=\s*false\b|\b(?:curl|wget)\b[^\r\n]*(?:\s-k\b|--insecure\b|--no-check-certificate\b)/gi;
    forEachMatch(text, disabledTls, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      addAt("insecure-transport", file, text, match.index, {
        title: "TLS certificate verification is disabled",
        category: "Transport Security",
        severity: "high",
        description: "This setting accepts untrusted certificates and permits an active network attacker to impersonate dependencies or APIs.",
        recommendation: "Remove the bypass and install the correct trusted CA certificate for the target service.",
        tags: ["tls", "configuration"],
      });
    });

    const tokenStorage = /\b(?:localStorage|sessionStorage)\s*(?:\.setItem\s*\(\s*["'`][^"'`]*(?:token|jwt|auth|session|credential|password)[^"'`]*["'`]|\[[^\]\r\n]*(?:token|jwt|auth|session|credential|password)[^\]\r\n]*\]\s*=|\.[A-Za-z_$][\w$]*(?:token|jwt|auth|session|credential|password)[\w$]*\s*=)/gi;
    forEachMatch(text, tokenStorage, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      if (isInsideDevelopmentGuard(text, match.index)) return;
      addAt("browser-storage", file, text, match.index, {
        title: "Authentication material is stored in Web Storage",
        category: "Authentication",
        severity: "high",
        description: "Any script running in the origin can read localStorage and sessionStorage, so an XSS flaw can directly steal the stored credential.",
        recommendation: "Prefer a short-lived, Secure, HttpOnly, SameSite cookie issued by the server. Keep access tokens in memory when cookie-based sessions are not possible.",
        evidence: "Sensitive Web Storage operation detected; key and value redacted.",
        tags: ["authentication", "xss"],
      });
    });

    const weakHashes = /\b(?:createHash\s*\(\s*["'](?:md5|sha-?1)["']|CryptoJS\.(?:MD5|SHA1)\s*\(|subtle\.digest\s*\(\s*["']SHA-?1["'])/gi;
    forEachMatch(text, weakHashes, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      const fingerprint = isNonSecurityFingerprintHash(file, text, match.index);
      addAt("weak-cryptography", file, text, match.index, {
        title: fingerprint ? "Collision-prone hash is used for a cache or deduplication fingerprint" : "Weak cryptographic hash is used",
        category: "Cryptography",
        severity: fingerprint ? "low" : "medium",
        confidence: fingerprint ? "medium" : "high",
        manual: fingerprint,
        description: fingerprint
          ? "MD5 or SHA-1 is used as a short non-secret fingerprint for cache lookup or duplicate detection. This is not password hashing or authentication, but collisions can still merge otherwise distinct entries."
          : "MD5 and SHA-1 are collision-broken and are unsuitable for signatures, integrity decisions, or password storage.",
        recommendation: fingerprint
          ? "Confirm that collisions cannot bypass a security decision. Prefer SHA-256 for new fingerprints; changing an existing cache key may cause a temporary cache miss or deduplication reset at deployment."
          : "Use SHA-256 or stronger for integrity, HMAC for authentication, and a password-specific KDF such as Argon2id, scrypt, or bcrypt for passwords.",
        tags: fingerprint ? ["cryptography", "hash", "cache", "manual-review"] : ["cryptography", "hash"],
      });
    });

    const weakRandom = /(?:\b(?:token|nonce|otp|password|secret|session|auth|csrf|reset|verification|salt|signingKey|encryptionKey)\w*[^\r\n]{0,100}\bMath\.random\s*\(|\bMath\.random\s*\(\)[^\r\n]{0,100}\b(?:token|nonce|otp|password|secret|session|auth|csrf|reset|verification|salt|signingKey|encryptionKey)\w*)/gi;
    forEachMatch(text, weakRandom, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      addAt("weak-cryptography", file, text, match.index, {
        title: "Math.random is used for a security-sensitive value",
        category: "Cryptography",
        severity: "high",
        description: "Math.random is predictable and must not generate tokens, nonces, reset codes, secrets, or cryptographic keys.",
        recommendation: "Use crypto.randomUUID() for identifiers or crypto.getRandomValues() / node:crypto randomBytes() for unpredictable bytes.",
        tags: ["cryptography", "randomness"],
      });
    });

    forEachMatch(text, /\.postMessage\s*\([^;\r\n]{0,500},\s*["'`]\*["'`]\s*\)/g, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      addAt("cross-window-messaging", file, text, match.index, {
        title: "postMessage sends data to every origin",
        category: "Browser Security",
        severity: "high",
        description: "Using '*' as targetOrigin can disclose the message to an attacker-controlled page if the target window navigates.",
        recommendation: "Pass the exact expected HTTPS origin as targetOrigin and keep the permitted origin in reviewed configuration.",
        tags: ["postmessage", "origin"],
      });
    });

    const messageListeners = [];
    forEachMatch(text, /(?:addEventListener\s*\(\s*["']message["']|\b(?:window|self|globalThis)\s*\.\s*onmessage\s*=)/g, (match) => messageListeners.push(match));
    if (messageListeners.length > 0 && !/\b(?:event|e|evt|messageEvent)\.origin\b|\borigin\s*(?:===|!==|==|!=)|allowedOrigins?\b/i.test(text)) {
      for (const match of messageListeners) {
        if (isCommentOnlyMatch(text, match.index)) continue;
        addAt("cross-window-messaging", file, text, match.index, {
          title: "Message event handler has no visible origin check",
          category: "Browser Security",
          severity: "medium",
          confidence: "medium",
          manual: true,
          description: "The file receives cross-window messages but does not visibly compare event.origin with an allowlisted origin.",
          recommendation: "Reject unexpected event.origin values before reading event.data, validate the message schema, and verify event.source where practical.",
          tags: ["postmessage", "origin", "manual-review"],
        });
      }
    }

    forEachMatch(text, /<a\b[^>]*\btarget\s*=\s*["']_blank["'][^>]*>/gi, (match) => {
      if (isCommentOnlyMatch(text, match.index) || /\brel\s*=\s*["'][^"']*\b(?:noopener|noreferrer)\b/i.test(match[0])) return;
      pendingBlankLinks.push({ file, text, index: match.index });
    });

    forEachMatch(text, /(?:href\s*=\s*["']\s*javascript:|(?:window\.)?location(?:\.href)?\s*=\s*["']\s*javascript:)/gi, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      addAt("external-navigation", file, text, match.index, {
        title: "javascript: URL executes script from navigation",
        category: "Browser Security",
        severity: "high",
        description: "javascript: navigation mixes executable code with URL data and can become an XSS path when values are modified dynamically.",
        recommendation: "Use a real event handler and allow only expected https: or relative URL schemes for navigable values.",
        tags: ["xss", "url"],
      });
    });

    for (const navigation of untrustedNavigationMatches(text)) {
      addAt("untrusted-navigation", file, text, navigation.index, {
        title: navigation.opensPopup ? "Popup destination comes from browser-controlled URL data" : "Redirect destination comes from browser-controlled URL data",
        category: "Browser Security",
        severity: "high",
        confidence: "medium",
        manual: true,
        description: `A query parameter, decoded URL fragment, or document referrer flows ${navigation.throughVariable ? "through a local variable " : ""}into a navigation sink. An attacker may be able to send visitors through a trusted site to a phishing or credential-capture destination.`,
        recommendation: "Resolve the candidate against the site's own origin, require an approved https: origin or a single-slash relative path, and fall back to a fixed safe route when validation fails.",
        tags: ["open-redirect", "navigation", "url-validation", "manual-review"],
      });
    }

    const wildcardCors = /(?:Access-Control-Allow-Origin["'`\s,:=]+\*|\borigin\s*:\s*["'`]\*["'`]|\bcors\s*\(\s*\{[^}\r\n]*origin\s*:\s*(?:true|["'`]\*["'`]))/gi;
    forEachMatch(text, wildcardCors, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      addAt("cors", file, text, match.index, {
        title: "Cross-origin access is allowed from every origin",
        category: "Security Configuration",
        severity: /credentials\s*:\s*true/i.test(lineTextAt(text, match.index)) ? "critical" : "high",
        description: "A wildcard CORS policy lets arbitrary websites read eligible responses and is especially dangerous around authenticated or sensitive endpoints.",
        recommendation: "Return Access-Control-Allow-Origin only for an explicit allowlist of trusted HTTPS origins and do not combine broad origins with credentials.",
        tags: ["cors", "origin"],
      });
    });

    const hardcodedAuthorization = /(?:["'`](?:Authorization|Proxy-Authorization)["'`]|\b(?:Authorization|Proxy-Authorization)\b)\s*[:=]\s*["'`](?:(?:Bearer|Basic)\s+)?([^"'`\s]{8,})["'`]/gi;
    forEachMatch(text, hardcodedAuthorization, (match) => {
      if (isCommentOnlyMatch(text, match.index) || looksLikePlaceholder(match[1])) return;
      addAt("hardcoded-auth", file, text, match.index, {
        title: "Authorization credential is hardcoded",
        category: "Authentication",
        severity: "critical",
        description: "A literal authorization credential is included in source or configuration and may be committed or shipped to users.",
        recommendation: "Verify that the literal is a real active credential. If it was exposed, revoke it and remove it from history; inject its replacement on a trusted server using a secret store.",
        evidence: "Authorization: <redacted>",
        tags: ["authentication", "credential"],
      });
    });

    forEachMatch(text, /https?:\/\/([^\s/@:"']+):([^\s/@"']+)@[^\s"'`<>)]+/gi, (match) => {
      if (isCommentOnlyMatch(text, match.index) || looksLikePlaceholder(match[2])) return;
      addAt("hardcoded-auth", file, text, match.index, {
        title: "URL contains embedded credentials",
        category: "Authentication",
        severity: "critical",
        description: "Credentials embedded in a URL leak through logs, browser history, referrers, process listings, and repository history.",
        recommendation: "Rotate the credential, remove it from the URL and supply authentication through a protected server-side mechanism.",
        evidence: "Credential-bearing URL: <redacted>",
        tags: ["authentication", "url", "credential"],
      });
    });

    const documentCookie = /\bdocument\.cookie\s*=/gi;
    forEachMatch(text, documentCookie, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      if (isInsideDevelopmentGuard(text, match.index)) return;
      const statement = text.slice(match.index, Math.min(text.length, match.index + 500)).split(/\r?\n/)[0];
      const sensitive = /token|auth|session|jwt|sid|credential/i.test(statement);
      const missing = [
        !/;\s*secure\b/i.test(statement) ? "Secure" : null,
        !/;\s*samesite\s*=/i.test(statement) ? "SameSite" : null,
        "HttpOnly (cannot be set by browser JavaScript)",
      ].filter(Boolean);
      addAt("cookie-flags", file, text, match.index, {
        title: sensitive ? "Authentication cookie is created in client JavaScript" : "Cookie is created without server-only protection",
        category: "Authentication",
        severity: sensitive ? "high" : "low",
        description: `The cookie is script-readable and is missing or cannot use: ${missing.join(", ")}.`,
        recommendation: "For session or authentication data, have the server issue a Secure, HttpOnly, SameSite=Lax/Strict cookie with a narrow Path and appropriate lifetime.",
        evidence: "Client-side cookie assignment detected; cookie payload redacted.",
        tags: ["cookie", "authentication"],
      });
    });

    const serverCookie = /\b(?:(?:res|response)\s*\.\s*cookie|(?:[A-Za-z_$][\w$]*\s*\.\s*)?setCookie|(?:ctx\s*\.\s*)?cookies\s*(?:\(\s*\))?\s*\.\s*set)\s*\(/g;
    forEachMatch(text, serverCookie, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      const parsed = cookieCallAt(text, match.index);
      if (!parsed) return;
      const statement = parsed.call;
      const csrfCookie = isCsrfCookieName(parsed.name);
      if (!/token|auth|session|jwt|sid|credential|csrf|xsrf/i.test(`${parsed.name} ${statement.slice(0, 250)}`)) return;
      const missing = [
        !csrfCookie && !/\bhttpOnly\s*:\s*true/i.test(statement) ? "HttpOnly" : null,
        !hasProductionSecureCookieOption(text, match.index, statement) ? "Secure" : null,
        !hasProtectiveSameSiteOption(statement) ? "SameSite" : null,
      ].filter(Boolean);
      if (missing.length === 0) return;
      addAt("cookie-flags", file, text, match.index, {
        title: "Authentication cookie is missing protective flags",
        category: "Authentication",
        severity: "high",
        description: `The nearby authentication-cookie options do not visibly enable: ${missing.join(", ")}.`,
        recommendation: "Set httpOnly: true, secure: true in production, and an intentional sameSite policy; also constrain Path, Domain, and lifetime.",
        evidence: "Authentication-cookie setter detected; arguments redacted.",
        tags: ["cookie", "authentication"],
      });
    });

    const sensitiveLog = /\bconsole\.(?:log|debug|info|warn|trace)\s*\([^\r\n;]*(?:password|passwd|secret|accessToken|access_token|refreshToken|refresh_token|authorization|document\.cookie|sessionToken|jwt)/gi;
    forEachMatch(text, sensitiveLog, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      addAt("sensitive-logging", file, text, match.index, {
        title: "Sensitive value may be written to the console",
        category: "Information Exposure",
        severity: "medium",
        description: "Credentials and cookies in browser or server logs can be recovered by users, extensions, support tooling, and log processors.",
        recommendation: "Remove the log statement or log only a non-sensitive request identifier and a fixed status message.",
        evidence: "Console call references a credential-like value; arguments redacted.",
        tags: ["logging", "privacy", "credential"],
      });
    });

    if (/^(?:next|nuxt|vite|webpack|rollup|astro|svelte|gatsby|vue|angular)[^/]*\.config\./i.test(normalizeName(file))
      || normalizeName(file) === "package.json") {
      const sourceMapPatterns = /\bproductionBrowserSourceMaps\s*:\s*true\b|\b(?:sourceMap|sourcemap)\s*:\s*true\b|\bdevtool\s*:\s*["'`](?:inline-|hidden-)?source-map["'`]|--sourcemap(?:\s|$)/gi;
      forEachMatch(text, sourceMapPatterns, (match) => {
        if (isCommentOnlyMatch(text, match.index)) return;
        addAt("source-maps", file, text, match.index, {
          title: "Production source maps appear to be enabled",
          category: "Information Exposure",
          severity: "medium",
          confidence: "medium",
          description: "Published source maps can expose original source, internal paths, comments, and implementation details to every visitor.",
          recommendation: "Disable public production source maps or upload hidden maps only to an access-controlled error-monitoring service and exclude them from deployment artifacts.",
          tags: ["source-map", "deployment"],
        });
      });
    }

    for (const weakness of cspWeaknesses(text)) {
      addAt("security-headers", file, text, weakness.index, {
        title: `Content Security Policy permits ${weakness.token}`,
        category: "Security Headers",
        severity: weakness.severity,
        confidence: "high",
        description: weakness.description,
        recommendation: weakness.recommendation,
        evidence: `CSP weakness detected: ${weakness.token}`,
        tags: ["csp", "xss", "security-boundary"],
      });
    }

    forEachMatch(text, /<iframe(?=\s|\/?\s*>)[^>]*>/gi, (match) => {
      if (isCommentOnlyMatch(text, match.index)) return;
      const markup = match[0];
      const attributes = openingTagAttributes(markup);
      const sandbox = attributes.get("sandbox");
      const srcdoc = attributes.get("srcdoc");
      const src = attributes.get("src");
      const hasSandbox = Boolean(sandbox);
      const sandboxValue = sandbox?.value ?? "";
      const dynamicSrcdoc = srcdoc?.dynamic === true;
      const thirdPartySource = src?.dynamic === false && /^https:\/\//i.test(src.value);

      if (dynamicSrcdoc && !hasSandbox) {
        addAt("embedded-content", file, text, match.index, {
          title: "Dynamic iframe srcdoc content is not sandboxed",
          category: "Browser Security",
          severity: "high",
          confidence: "medium",
          description: "Dynamic srcdoc markup creates a nested browsing context that can execute active content with the embedding page's origin unless it is tightly sandboxed and the HTML is trusted or sanitized.",
          recommendation: "Avoid dynamic srcdoc for untrusted content. If it is required, sanitize with a maintained allowlist and add the narrowest sandbox permissions without allow-same-origin.",
          tags: ["iframe", "srcdoc", "xss", "sandbox"],
        });
        return;
      }

      if (sandbox && /\ballow-scripts\b/i.test(sandboxValue) && /\ballow-same-origin\b/i.test(sandboxValue)) {
        addAt("embedded-content", file, text, match.index, {
          title: "Iframe sandbox combines allow-scripts and allow-same-origin",
          category: "Browser Security",
          severity: "medium",
          confidence: "medium",
          manual: true,
          description: "Combining script execution with same-origin privileges can undermine the iframe sandbox, especially when the framed content can become same-origin or navigate to same-origin content.",
          recommendation: "Remove allow-same-origin or allow-scripts wherever possible, isolate untrusted content on a separate origin, and grant only the individual capabilities the embed requires.",
          tags: ["iframe", "sandbox", "isolation", "manual-review"],
        });
        return;
      }

      if (thirdPartySource && !hasSandbox) {
        addAt("embedded-content", file, text, match.index, {
          title: "Third-party iframe has no sandbox policy",
          category: "Browser Security",
          severity: "low",
          confidence: "medium",
          manual: true,
          description: "An absolute HTTPS iframe can execute and navigate with all browser capabilities normally granted to embedded third-party content.",
          recommendation: "Confirm the provider's required capabilities, add a least-privilege sandbox and allow policy, and isolate especially sensitive embeds on a separate origin.",
          tags: ["iframe", "third-party", "sandbox", "manual-review"],
        });
      }
    });

    forEachMatch(text, /<script\b[^>]*\bsrc\s*=\s*["']https:\/\/[^"']+["'][^>]*>/gi, (match) => {
      if (isCommentOnlyMatch(text, match.index) || /\bintegrity\s*=\s*["'][^"']+["']/i.test(match[0])) return;
      addAt("third-party-resources", file, text, match.index, {
        title: "Third-party script has no Subresource Integrity hash",
        category: "Supply Chain",
        severity: "medium",
        description: "If the external host or delivery path is compromised, the referenced script can execute with the site's full browser privileges.",
        recommendation: "Self-host the reviewed asset or add a version-pinned URL plus a valid integrity hash and crossorigin=\"anonymous\".",
        tags: ["sri", "third-party", "script"],
      });
    });
  }

  // Contracts can live below a path named "docs" even when the consuming
  // production route lives elsewhere. Require an explicit import at the sink,
  // but build the contract index from every readable non-audit artifact.
  const htmlContracts = sanitizedHtmlContracts(allReadableContents);
  for (const sink of pendingHtmlSinks) {
    if (hasSanitizedHtmlContract(sink, htmlContracts)) continue;
    addAt("dom-xss", sink.file, sink.text, sink.index, {
      title: "HTML reaches a browser DOM sink and needs data-flow review",
      category: "Application Security",
      severity: "high",
      confidence: "medium",
      manual: true,
      description: `${sink.label} interprets strings as markup. This pattern alone does not prove exploitability; user-controlled content can execute script if it reaches the sink without an allowlist sanitizer.`,
      recommendation: "Trace the value to its source. Render untrusted values as text or sanitize rich HTML with a maintained allowlist sanitizer before this sink, then keep a regression test for the sanitizer contract.",
      tags: ["xss", "dom", "manual-review"],
    });
  }

  const isolationContracts = externalLinkIsolationContracts(allReadableContents);
  for (const link of pendingBlankLinks) {
    if (hasDownstreamLinkIsolationContract(link, isolationContracts)) continue;
    addAt("external-navigation", link.file, link.text, link.index, {
      title: "New-tab link does not declare rel=noopener",
      category: "Browser Security",
      severity: "low",
      description: "A page opened in a new tab may retain an opener reference on older or embedded browsers and navigate the original page.",
      recommendation: "Add rel=\"noopener noreferrer\" to the link or open the URL with an explicitly isolated window.",
      tags: ["tabnabbing", "link"],
    });
  }

  const repositoryLockfiles = inputFiles.filter((file) => LOCKFILE_NAMES.has(normalizeName(file)));

  for (const { file, text } of allReadableContents) {
    for (const signal of lockfileSecuritySignals(file, text)) {
      addAt(signal.ruleId, file, text, signal.index, signal);
    }
  }

  const rootLockfiles = repositoryLockfiles.filter((file) => relativeDirectory(file) === "");
  const manifestEntries = allReadableContents
    .filter(({ file }) => normalizeName(file) === "package.json")
    .filter(({ file }) => file.relative.toLowerCase() === "package.json" || isRelevantFile(file, options, workspaceRoots))
    .sort((a, b) => {
      const aRoot = a.file.relative.toLowerCase() === "package.json" ? 0 : 1;
      const bRoot = b.file.relative.toLowerCase() === "package.json" ? 0 : 1;
      return aRoot - bRoot || a.file.relative.localeCompare(b.file.relative);
    });
  const packageEntry = manifestEntries.find(({ file }) => file.relative.toLowerCase() === "package.json") ?? manifestEntries[0] ?? null;
  const rootPackageEntry = manifestEntries.find(({ file }) => file.relative.toLowerCase() === "package.json") ?? null;
  const manifestRecords = [];
  const dependencies = new Set();
  const dependencyGroups = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

  for (const entry of manifestEntries) {
    let manifest;
    try {
      manifest = JSON.parse(entry.text);
      if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new TypeError("top-level value is not an object");
    } catch (error) {
      addFinding("dependency-hygiene", {
        title: "package.json could not be parsed",
        category: "Supply Chain",
        severity: "high",
        description: "Dependency and script security checks cannot reliably inspect an invalid package manifest.",
        recommendation: "Correct the JSON syntax, then rerun Modular so dependency and lifecycle-script checks can complete.",
        evidence: `JSON parse failed: ${error instanceof Error ? error.message : "invalid JSON"}`,
        file: entry.file.relative,
        line: 1,
        suggestedFiles: [entry.file.relative],
        tags: ["dependencies", "configuration"],
      });
      continue;
    }

    const directory = relativeDirectory(entry.file);
    const directLockfiles = repositoryLockfiles.filter((file) => relativeDirectory(file) === directory);
    const effectiveLockfiles = directLockfiles.length > 0
      ? directLockfiles
      : (directory && rootPackageEntry ? rootLockfiles : []);
    const manifestDependencies = new Set(dependencyGroups.flatMap((group) => Object.keys(manifest[group] ?? {})));
    for (const dependency of manifestDependencies) dependencies.add(dependency);
    manifestRecords.push({ entry, manifest, directory, directLockfiles, effectiveLockfiles, dependencies: manifestDependencies });

    for (const group of dependencyGroups) {
      const entries = manifest[group];
      if (!entries || typeof entries !== "object" || Array.isArray(entries)) continue;
      for (const [name, rawVersion] of Object.entries(entries)) {
        if (typeof rawVersion !== "string") continue;
        const version = rawVersion.trim();
        let reason = null;
        let severity = "medium";
        if (version === "*" || /^latest$/i.test(version)) reason = "uses a floating version that can resolve to an unreviewed release";
        else if (/^(?:git\+)?http:\/\//i.test(version)) {
          reason = "is downloaded over an unauthenticated HTTP transport";
          severity = "high";
        } else if (/^(?:git|git\+https|github|gitlab|bitbucket):/i.test(version) && !/#(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(version)) {
          reason = "uses a mutable Git reference instead of an immutable commit";
        }
        if (!reason) continue;
        const expectedLockfile = effectiveLockfiles[0]?.relative ?? relativeJoin(directory, "package-lock.json");
        addFinding("dependency-hygiene", {
          title: "Dependency source is not reproducibly pinned",
          category: "Supply Chain",
          severity,
          description: `${name} in ${group} ${reason}.`,
          recommendation: "Pin the dependency to a reviewed registry version or immutable full commit and regenerate the matching lockfile.",
          evidence: `${group}.${name}: ${sanitizeEvidence(version)}`,
          file: entry.file.relative,
          line: packageLine(entry.text, name),
          suggestedFiles: [entry.file.relative, expectedLockfile],
          tags: ["dependencies", "supply-chain"],
        });
      }
    }

    const scripts = manifest.scripts;
    if (scripts && typeof scripts === "object" && !Array.isArray(scripts)) {
      for (const [name, command] of Object.entries(scripts)) {
        if (typeof command !== "string") continue;
        const remoteShell = /\b(?:curl|wget)\b[^\r\n|;&]*(?:\||&&|;)\s*(?:sh|bash|zsh|cmd|powershell|pwsh)\b/i.test(command)
          || /\b(?:sh|bash|zsh|powershell|pwsh)\b[^\r\n]*(?:https?:\/\/)/i.test(command);
        const disablesSecurity = /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|strict-ssl\s+false|--disable-web-security|--no-check-certificate|\bcurl\b[^\r\n]*\s-k\b/i.test(command);
        if (!remoteShell && !disablesSecurity) continue;
        addFinding("package-scripts", {
          title: remoteShell ? "Package script executes remotely downloaded code" : "Package script disables a security boundary",
          category: "Supply Chain",
          severity: remoteShell && /^(?:preinstall|install|postinstall|prepare)$/i.test(name) ? "critical" : "high",
          description: remoteShell
            ? `The ${name} script downloads and immediately executes code without an auditable, integrity-pinned artifact.`
            : `The ${name} script disables TLS or browser security checks.`,
          recommendation: remoteShell
            ? "Replace the remote shell pipeline with a pinned package or checked-in script, verify a cryptographic checksum, and review it before execution."
            : "Remove the bypass and configure the correct certificate or local test environment instead.",
          evidence: `scripts.${name}: ${sanitizeEvidence(command)}`,
          file: entry.file.relative,
          line: packageLine(entry.text, name),
          suggestedFiles: [entry.file.relative],
          tags: ["package-script", "supply-chain"],
        });
      }
    }

    if (effectiveLockfiles.length === 0 && manifestDependencies.size > 0) {
      const expectedLockfile = relativeJoin(directory, "package-lock.json");
      addFinding("lockfile", {
        title: "Dependency lockfile is missing",
        category: "Supply Chain",
        severity: "medium",
        description: "Without a matching root or workspace lockfile, clean installs may resolve dependency versions that were never reviewed or tested.",
        recommendation: "Generate and commit a lockfile with the package manager used by this workspace, then use deterministic CI installation commands.",
        evidence: `${manifestDependencies.size} declared dependencies; no matching lockfile was found for ${entry.file.relative}.`,
        file: entry.file.relative,
        line: 1,
        suggestedFiles: [entry.file.relative, expectedLockfile],
        tags: ["dependencies", "lockfile"],
      });
    }
    if (directLockfiles.length > 1) {
      addFinding("lockfile", {
        title: "Multiple package-manager lockfiles are present in one workspace",
        category: "Supply Chain",
        severity: "low",
        description: "Different package managers in the same workspace can install different dependency graphs, making review and CI output inconsistent.",
        recommendation: "Choose one package manager for this workspace, remove obsolete sibling lockfiles, declare packageManager, and enforce the same deterministic install in CI.",
        evidence: `Lockfiles: ${directLockfiles.map((file) => file.relative).join(", ")}`,
        file: entry.file.relative,
        line: 1,
        suggestedFiles: [entry.file.relative, ...directLockfiles.map((file) => file.relative)],
        tags: ["dependencies", "lockfile"],
      });
    }
  }

  for (const { file, text } of allReadableContents) {
    forEachMatch(text, /(?:^|\n)\s*(?:(?:\/\/|https?:\/\/)[^:\r\n]+:)?_authToken\s*=\s*([^\s#\r\n]+)/gi, (match) => {
      const value = match[1];
      if (looksLikePlaceholder(value)) return;
      addAt("embedded-secrets", file, text, match.index, {
        title: "Package registry token is stored in configuration",
        category: "Secrets",
        severity: "critical",
        description: "A literal package-registry token in repository configuration can permit package download, publication, or account access.",
        recommendation: "Revoke the token, remove it from history, and reference an environment variable such as ${NPM_TOKEN} from user- or CI-scoped configuration.",
        evidence: "Package registry token: <redacted>",
        tags: ["credential", "registry", "supply-chain"],
      });
    });
  }

  const realEnvironmentFiles = allReadableContents.filter(({ file, text }) => {
    if (!isEnvironmentFile(file)) return false;
    if (publicConfigurationOnly(text)) return false;
    return !/\.env\.(?:example|sample|template|defaults?)(?:\.[^/]*)?$/i.test(file.relative);
  });
  if (realEnvironmentFiles.length > 0) {
    const gitignores = allReadableContents.filter(({ file }) =>
      path.posix.basename(normalizedRelative(file)) === ".gitignore");
    const unignoredEnvironmentFiles = realEnvironmentFiles
      .map((entry) => ({ ...entry, ignore: environmentIgnoreState(entry.file, gitignores) }))
      .filter(({ ignore }) => !ignore.ignored);
    if (unignoredEnvironmentFiles.length > 0) {
      const firstEnvironment = unignoredEnvironmentFiles[0];
      const suggestedIgnore = firstEnvironment.ignore.source?.relative ?? ".gitignore";
      addFinding("environment-hygiene", {
        title: "Environment files are not excluded by .gitignore",
        category: "Secrets",
        severity: "medium",
        confidence: "high",
        description: `${unignoredEnvironmentFiles.length} real environment file${unignoredEnvironmentFiles.length === 1 ? " is" : "s are"} not ignored by the applicable .gitignore rules. This makes accidental credential commits more likely.`,
        recommendation: "Add .env and environment-specific variants to .gitignore, keep only placeholder-only example files, and verify repository history for previously committed values.",
        evidence: firstEnvironment.ignore.source
          ? `${firstEnvironment.file.relative} is not ignored after applying ${firstEnvironment.ignore.source.relative}, including negation rules.`
          : "No applicable .gitignore rule ignores this environment file.",
        file: firstEnvironment.file.relative,
        line: 1,
        suggestedFiles: [suggestedIgnore, ...unignoredEnvironmentFiles.slice(0, 3).map(({ file }) => file.relative)],
        tags: ["environment", "credential", "git"],
      });
    }
  }

  const { dependencyAudit, auditEnabled, auditContexts } = await runDependencyAudit({
    root, options, manifestRecords, dependencies, allReadableContents, inputFiles, addFinding, onProgress,
  });

  if (project?.isWebsite) {
    const securityConfiguration = scannedContents
      .filter(({ file }) => isHeaderConfigFile(file))
      .map(({ text }) => stripCommentsForHeaderDetection(text))
      .join("\n");
    const markupCsp = scannedContents
      .filter(({ file }) => [".html", ".htm", ".astro", ".vue", ".svelte"].includes(file.extension))
      .map(({ text }) => stripCommentsForHeaderDetection(text))
      .join("\n");
    const expectedHeaders = [
      { label: "Content-Security-Policy", regex: /content-security-policy|contentSecurityPolicy/i, allowMarkup: true },
      { label: "X-Content-Type-Options", regex: /x-content-type-options/i },
      { label: "Referrer-Policy", regex: /referrer-policy/i },
      { label: "Permissions-Policy", regex: /permissions-policy/i },
      { label: "frame-ancestors or X-Frame-Options", regex: /frame-ancestors|x-frame-options/i },
    ];
    const missingHeaders = expectedHeaders.filter((header) => !header.regex.test(
      header.allowMarkup ? `${securityConfiguration}\n${markupCsp}` : securityConfiguration,
    ));
    if (missingHeaders.length > 0) {
      const suggestions = frameworkConfigSuggestions(dependencies, inputFiles);
      addFinding("security-headers", {
        title: "Frontend security headers are incomplete",
        category: "Security Headers",
        severity: missingHeaders.some((header) => header.label === "Content-Security-Policy") ? "medium" : "low",
        confidence: "medium",
        manual: true,
        description: `Repository configuration does not visibly define: ${missingHeaders.map((header) => header.label).join(", ")}. Hosting infrastructure may set these separately and should be verified.`,
        recommendation: "Configure the missing headers at the application or hosting edge, start CSP in report-only mode, and verify the deployed response rather than relying only on markup.",
        evidence: "Manual check: no matching header configuration was found in scanned configuration files.",
        file: packageEntry?.file.relative ?? null,
        line: packageEntry ? 1 : null,
        suggestedFiles: suggestions.length > 0 ? suggestions : ["deployment/hosting configuration"],
        tags: ["headers", "csp", "manual-review"],
      });
    }
  }

  const advisoryCheckCompleted = dependencyAudit.status === "completed" || dependencyAudit.status === "partial";
  const completedChecks = advisoryCheckCompleted
    ? SECURITY_CHECKS
    : SECURITY_CHECKS.filter((check) => check.id !== "dependency-advisories");
  const advisoryCoverage = dependencyAudit.status === "completed"
    ? "completed in an isolated package-manager sandbox"
    : dependencyAudit.status === "partial"
      ? "partially completed; inspect the dependency-audit status and workspace results"
      : dependencyAudit.status === "skipped"
        ? "skipped; opt in with --dependency-audit"
        : `${dependencyAudit.status}; no complete advisory result is available`;
  const enabledCheckIds = new Set(completedChecks.map((check) => check.id));
  const hasWorkflowSurface = allReadableContents.some(({ file }) => /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(file.relative));
  const hasLockfileIntegritySurface = allReadableContents.some(({ file }) => (
    ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"].includes(normalizeName(file))
  ));
  const hasTerraformSurface = allReadableContents.some(({ file }) => /\.tf(?:vars)?$/i.test(file.relative));
  const hasContainerSurface = allReadableContents.some(({ file, text }) => {
    const name = normalizeName(file);
    if (/^dockerfile(?:[._-].*)?$/i.test(name) || /^(?:docker-)?compose(?:\.[^.]+)?\.ya?ml$/i.test(name)) return true;
    if (!/\.ya?ml$/i.test(file.relative)) return false;
    return /^\s*(?:apiVersion|kind)\s*:/mi.test(text) && /^\s*(?:containers|initContainers)\s*:/mi.test(text);
  });
  const serverSurfaces = scannedContents.filter(({ file, text }) => isLikelyServerSource(file, text));
  const hasServerSurface = serverSurfaces.length > 0;
  const hasJwtSurface = serverSurfaces.some(({ text }) => /\b(?:jwt|jsonwebtoken|jose|verifyToken|verifyJwt)\b/i.test(text));
  const staticApplicability = new Map([
    ["ci-workflow", hasWorkflowSurface],
    ["container-hardening", hasContainerSurface],
    ["iac-exposure", hasTerraformSurface],
    ["lockfile-integrity", hasLockfileIntegritySurface],
    ["dependency-hygiene", manifestEntries.length > 0],
    ["package-scripts", manifestEntries.length > 0],
    ["lockfile", dependencies.size > 0],
    ["server-ssrf", hasServerSurface],
    ["server-path-traversal", hasServerSurface],
    ["server-command-injection", hasServerSurface],
    ["server-sql-injection", hasServerSurface],
    ["jwt-validation", hasJwtSurface],
  ]);
  const checkLedger = SECURITY_CHECKS.map((check) => {
    const dependencyCheck = check.id === "dependency-advisories";
    const applicable = dependencyCheck
      ? auditContexts.length > 0
      : (staticApplicability.get(check.id) ?? true);
    const executionStatus = dependencyCheck
      ? dependencyAudit.status
      : (applicable ? "completed" : "not-applicable");
    const observedFindings = dependencyCheck
      ? (observedFindingCounts.get("dependency-advisory") ?? 0) + (observedFindingCounts.get("dependency-audit-unavailable") ?? 0)
      : observedFindingCounts.get(check.id) ?? 0;
    return {
      ...check,
      kind: dependencyCheck ? "external-package-manager" : "automated-static",
      status: executionStatus,
      executionStatus,
      applicability: applicable ? "applicable" : "not-applicable",
      enabled: enabledCheckIds.has(check.id) && applicable,
      outcome: applicable
        ? (observedFindings > 0 ? "signals-observed" : "no-static-signal-observed")
        : "not-applicable",
      observedFindings,
      retainedFindings: dependencyCheck
        ? findings.filter((finding) => ["security.dependency-advisory", "security.dependency-audit-unavailable"].includes(finding.id)).length
        : findings.filter((finding) => finding.id === `security.${check.id}`).length,
      suppressedFindings: dependencyCheck
        ? Number(suppressedByRule["dependency-advisory"] ?? 0) + Number(suppressedByRule["dependency-audit-unavailable"] ?? 0)
        : Number(suppressedByRule[check.id] ?? 0),
    };
  });

  return buildScanResult({
    mode: "security",
    title: "Modular Security Check",
    root,
    findings,
    checks: SECURITY_CHECKS.length,
    filesScanned: allReadableContents.length,
    startedAt,
    metadata: {
      scanner: "frontend-security-sast",
      findingIndex: findingIndex.entries,
      scannerVersion: 3,
      checkCount: SECURITY_CHECKS.length,
      // `status` reports execution, while the separate applicability field
      // remains honest when static analysis cannot prove project relevance.
      checks: checkLedger,
      checkLedger,
      checkLedgerSemantics: "completed means the applicable static rule family executed; zero observed signals is not certification or proof of security. Provably absent input surfaces are not-applicable, and the external dependency audit retains its explicit skipped, unavailable, partial, or completed status.",
      standards: {
        mappingLevel: "CWE and OWASP Top 10 category",
        disclaimer: "Mappings describe rule intent; a static finding does not establish standards compliance.",
        rules: Object.fromEntries(SECURITY_CHECKS.map(({ id }) => [id, securityStandards(id)])),
      },
      coverage: {
        "Static application checks": "embedded secrets, public environment variables, DOM XSS sinks, dynamic code, one-file server-side SSRF/path/command/SQL data flows, JWT verification options, insecure transport, browser storage, cookies, messaging origins, user-controlled navigation, iframe isolation, CORS, weak cryptography, sensitive logs, source maps, and third-party scripts",
        "Configuration and supply chain": "package manifests, install scripts, dependency pinning, lockfile transport/integrity signals, registry configuration, environment-file hygiene, GitHub Actions trust boundaries, Docker/container privilege signals, focused Terraform public-exposure settings, framework headers, and CSP",
        "Dependency advisory lookup": advisoryCoverage,
        "Files inspected for credentials": allReadableContents.length,
        "Production files scanned with SAST rules": scannedContents.length,
      },
      filesConsidered: inspectionFiles.length,
      unreadableFiles,
      excludedFiles: inputFiles.length - inspectionFiles.length,
      secretScanFiles: allReadableContents.length,
      productionFilesScanned: scannedContents.length,
      excludedFromNonSecretSast: inputFiles.length - relevantFiles.length,
      skipped: { ...skipped },
      suppressedByRule,
      suppressedSeverityByRule,
      dependencyAudit,
      options: {
        includeTests: options.includeTests === true,
        includeGenerated: options.includeGenerated === true,
        auditDependencies: auditEnabled,
        maxFindingsPerRule,
      },
      limitations: [
        "Static matches identify risky code patterns; bounded source-to-sink analysis follows direct and local-variable flows within one file, not interprocedural or runtime flows. Validate data flow and deployment configuration before remediation.",
        "The default scan reads the collected working tree only; it does not invoke Git or inspect commit history for previously exposed secrets.",
        "Infrastructure-as-code coverage is intentionally focused on high-signal Docker/container and Terraform settings, not a complete cloud-policy or Kubernetes admission evaluation.",
        advisoryCheckCompleted
          ? "Dependency advisory results are a point-in-time package-manager lookup; rerun them after lockfile changes and before release."
          : "Dependency CVE resolution was not completed and is not inferred from a stale embedded vulnerability database; opt in with --dependency-audit when network access is appropriate.",
      ],
      project: {
        confidence: project.confidence,
        framework: project.framework ?? null,
        reasons: project.reasons ?? [],
        signals: project.signals ?? [],
      },
    },
  });
}
