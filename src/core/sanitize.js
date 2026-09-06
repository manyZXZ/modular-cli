const FIELD_SEPARATOR = String.raw`[_.-]?`;

/**
 * Exact credential-field aliases shared by detection and final report
 * redaction. Keep this list deliberately broader than the secret detector:
 * evidence may be committed or shared, so a false-positive redaction is safer
 * than reproducing a credential in a report.
 */
export const SENSITIVE_FIELD_NAME_SOURCE = [
  String.raw`tokens?`,
  String.raw`credentials?`,
  String.raw`secrets?`,
  String.raw`sessions?`,
  String.raw`pass(?:words?|phrases?|codes?)`,
  String.raw`passwd`,
  String.raw`pwd`,
  String.raw`auth(?:entication|orization)?`,
  String.raw`jwt(?:${FIELD_SEPARATOR}tokens?)?`,
  String.raw`sid`,
  String.raw`(?:api|access|refresh|auth|authorization|bearer|id|identity|session|csrf|xsrf|oauth)${FIELD_SEPARATOR}(?:tokens?|keys?|secrets?|credentials?)`,
  String.raw`access${FIELD_SEPARATOR}key(?:${FIELD_SEPARATOR}id)?`,
  String.raw`(?:private|client|consumer|webhook|signing|encryption|service${FIELD_SEPARATOR}account)${FIELD_SEPARATOR}(?:keys?|secrets?|tokens?|credentials?)`,
  String.raw`(?:auth|session)${FIELD_SEPARATOR}cookies?`,
  String.raw`cookies?${FIELD_SEPARATOR}(?:secrets?|keys?|tokens?|passwords?|passphrases?)`,
  String.raw`(?:db|database|redis|smtp)${FIELD_SEPARATOR}(?:passwords?|passphrases?|credentials?)`,
  String.raw`(?:db|database|redis|smtp|user|admin|root|auth)${FIELD_SEPARATOR}pass(?:words?|phrases?|codes?)?`,
  String.raw`(?:db|database)${FIELD_SEPARATOR}(?:url|uri|connection${FIELD_SEPARATOR}string)`,
  String.raw`aws${FIELD_SEPARATOR}(?:access${FIELD_SEPARATOR}key${FIELD_SEPARATOR}id|secret${FIELD_SEPARATOR}access${FIELD_SEPARATOR}key|session${FIELD_SEPARATOR}token)`,
  String.raw`(?:phpsessid|jsessionid|asp${FIELD_SEPARATOR}net${FIELD_SEPARATOR}session${FIELD_SEPARATOR}id)`,
].join("|");

const SENSITIVE_FIELD_PREFIX = new RegExp(`^(?:${SENSITIVE_FIELD_NAME_SOURCE})`, "i");
const QUERY_VALUE = /([?&])([^=&#\s]+)(=)([^&#\s]+)/gi;
const FIELD_REFERENCE = /(["'])([A-Za-z_$][\w$.-]*)\1|([A-Za-z_$][\w$.-]*)/g;
const ASSIGNABLE_VALUE = /"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|`(?:\\.|[^`\\\r\n])*`|\[[^\r\n;]*\]|\{[^\r\n;]*\}|\([^\r\n;]*\)|[^\s,;}>"'`]+/;
const ASSIGNMENT_OPERATOR = String.raw`(?:\?\?=|\|\|=|&&=|=(?!=|>))`;
const TYPED_ASSIGNMENT_TAIL = new RegExp(
  `^(\\s*[!?]?\\s*:\\s*[^;\\r\\n]{1,160}?\\s*${ASSIGNMENT_OPERATOR}\\s*)(${ASSIGNABLE_VALUE.source})`,
);
const DIRECT_ASSIGNMENT_TAIL = new RegExp(
  `^(\\s*(?:\\]\\s*)?(?::|${ASSIGNMENT_OPERATOR})\\s*)(${ASSIGNABLE_VALUE.source})`,
);
const SENSITIVE_SETTER = new RegExp(
  `(\\b(?:[A-Za-z_$][\\w$]*\\s*\\.\\s*)*(?:set|setItem)\\s*\\(\\s*)(["'\`])([^"'\`\\r\\n]+)\\2(\\s*,\\s*)(${ASSIGNABLE_VALUE.source})`,
  "gi",
);
const HTML_TAG = /<[A-Za-z][^>]*>/g;
const HTML_ATTRIBUTE_VALUE = /\b([A-Za-z_:][\w:.-]*)\s*=\s*("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s>]+)/g;

export function isSensitiveCredentialName(value) {
  const field = String(value ?? "");
  const candidates = new Set([field]);
  for (let index = 0; index < field.length; index += 1) {
    if (/[_.-]/.test(field[index]) && index + 1 < field.length) candidates.add(field.slice(index + 1));
    if (index > 0 && /[A-Z]/.test(field[index]) && /[a-z0-9]/.test(field[index - 1])) candidates.add(field.slice(index));
  }
  return [...candidates].some((candidate) => {
    const match = candidate.match(SENSITIVE_FIELD_PREFIX);
    if (!match) return false;
    const suffix = candidate.slice(match[0].length);
    return suffix === "" || /^(?:[_.-][A-Za-z0-9]+|\d+|[A-Z][A-Za-z0-9]*)$/.test(suffix);
  });
}

export function findSensitiveAssignments(value) {
  const input = String(value ?? "");
  const assignments = [];
  FIELD_REFERENCE.lastIndex = 0;
  let fieldMatch;
  while ((fieldMatch = FIELD_REFERENCE.exec(input)) !== null) {
    const field = fieldMatch[2] ?? fieldMatch[3];
    if (!isSensitiveCredentialName(field)) continue;
    const fieldEnd = fieldMatch.index + fieldMatch[0].length;
    const tail = input.slice(fieldEnd);
    const assignment = TYPED_ASSIGNMENT_TAIL.exec(tail) ?? DIRECT_ASSIGNMENT_TAIL.exec(tail);
    if (!assignment) continue;
    const rawValue = assignment[2];
    const valueStart = fieldEnd + assignment[1].length;
    if (/^[|>](?:[+-]?\d?|\d?[+-]?)?$/.test(rawValue)
      && /^(?:\r\n|\n|\r)/.test(tail.slice(assignment[1].length + rawValue.length))) continue;
    if (rawValue.startsWith("(") && /^\s*=>/.test(tail.slice(assignment[0].length))) continue;
    assignments.push({
      field,
      index: fieldMatch.index,
      value: rawValue,
      valueStart,
      valueEnd: valueStart + rawValue.length,
      structured: /^[\[{(]/.test(rawValue),
      quoted: /^["'`]/.test(rawValue),
    });
  }
  return assignments;
}

function redactSensitiveAssignments(value) {
  const input = String(value ?? "");
  const replacements = findSensitiveAssignments(input)
    .filter((assignment) => !assignment.value.startsWith("<redacted"))
    .sort((left, right) => right.valueStart - left.valueStart);
  let output = input;
  let replacedBefore = Number.POSITIVE_INFINITY;
  for (const assignment of replacements) {
    if (assignment.valueEnd > replacedBefore) continue;
    const quote = assignment.quoted ? assignment.value[0] : "";
    const replacement = quote ? `${quote}<redacted>${quote}` : "<redacted>";
    output = `${output.slice(0, assignment.valueStart)}${replacement}${output.slice(assignment.valueEnd)}`;
    replacedBefore = assignment.valueStart;
  }
  return output;
}

function redactLiteral(rawValue) {
  if (rawValue.startsWith("<redacted")) return rawValue;
  const quote = /^["'`]/.test(rawValue) ? rawValue[0] : "";
  return quote ? `${quote}<redacted>${quote}` : "<redacted>";
}

function hasSensitiveFieldContext(value) {
  FIELD_REFERENCE.lastIndex = 0;
  let match;
  while ((match = FIELD_REFERENCE.exec(value)) !== null) {
    if (isSensitiveCredentialName(match[2] ?? match[3])) return true;
  }
  return false;
}

function redactCredentialContextLiterals(value) {
  const input = String(value ?? "");
  if (!hasSensitiveFieldContext(input)) return input;
  return input.replace(/"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|`(?:\\.|[^`\\\r\n])*`/g, (rawValue) => {
    const content = rawValue.slice(1, -1);
    if (content.startsWith("<redacted") || isSensitiveCredentialName(content)) return rawValue;
    return redactLiteral(rawValue);
  });
}

function redactYamlCredentialBlocks(value) {
  const lines = String(value ?? "").match(/[^\r\n]*(?:\r\n|\n|\r|$)/g)?.filter(Boolean) ?? [];
  const output = [];
  for (let index = 0; index < lines.length;) {
    const rawLine = lines[index];
    const content = rawLine.replace(/(?:\r\n|\n|\r)$/, "");
    const header = /^(\s*)(["']?)([A-Za-z_$][\w$.-]*)\2\s*:\s*[|>](?:[+-]?\d?|\d?[+-]?)?\s*(?:#.*)?$/.exec(content);
    if (!header || !isSensitiveCredentialName(header[3])) {
      output.push(rawLine);
      index += 1;
      continue;
    }
    const baseIndent = header[1].length;
    let end = index + 1;
    while (end < lines.length) {
      const body = lines[end].replace(/(?:\r\n|\n|\r)$/, "");
      if (body.trim() === "") {
        end += 1;
        continue;
      }
      const indentation = /^\s*/.exec(body)?.[0].length ?? 0;
      if (indentation <= baseIndent) break;
      end += 1;
    }
    if (end === index + 1) {
      output.push(rawLine);
      index += 1;
      continue;
    }
    const lastEnding = lines[end - 1].match(/(?:\r\n|\n|\r)$/)?.[0] ?? "";
    output.push(rawLine, `${header[1]}  <redacted>${lastEnding}`);
    index = end;
  }
  return output.join("");
}

function htmlAttribute(tag, requestedName) {
  HTML_ATTRIBUTE_VALUE.lastIndex = 0;
  let match;
  while ((match = HTML_ATTRIBUTE_VALUE.exec(tag)) !== null) {
    if (match[1].toLowerCase() !== requestedName) continue;
    return match[2].replace(/^(["'])(.*)\1$/, "$2");
  }
  return null;
}

function redactContextualValues(value) {
  return String(value ?? "")
    .replace(SENSITIVE_SETTER, (match, prefix, quote, field, separator, rawValue) => (
      isSensitiveCredentialName(field)
        ? `${prefix}${quote}${field}${quote}${separator}${redactLiteral(rawValue)}`
        : match
    ))
    .replace(HTML_TAG, (tag) => {
      const type = htmlAttribute(tag, "type");
      const name = htmlAttribute(tag, "name");
      const credentialContext = type?.toLowerCase() === "password"
        || (name !== null && isSensitiveCredentialName(name));
      if (!credentialContext) return tag;
      HTML_ATTRIBUTE_VALUE.lastIndex = 0;
      return tag.replace(HTML_ATTRIBUTE_VALUE, (attribute, attributeName, rawValue) => (
        /^(?:value|content)$/i.test(attributeName)
          ? attribute.replace(rawValue, redactLiteral(rawValue))
          : attribute
      ));
    });
}

/**
 * Remove credential-shaped material before scanner evidence reaches a result or
 * report. Reports are often committed or shared even when source stays local.
 */
export function redactSensitiveText(value, options = {}) {
  let redactedPatterns = redactYamlCredentialBlocks(value)
    .replace(/-----BEGIN [^-\r\n]+ PRIVATE KEY-----/gi, "<redacted private key>")
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted AWS key>")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g, "<redacted GitHub token>")
    .replace(/\bglpat-[A-Za-z0-9_-]{12,255}\b/g, "<redacted GitLab token>")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{8,255}\b/g, "<redacted Slack token>")
    .replace(/\bsk_live_[A-Za-z0-9]{10,255}\b/g, "<redacted Stripe key>")
    .replace(/\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,255}\b/g, "<redacted API key>")
    .replace(/\bnpm_[A-Za-z0-9]{16,255}\b/g, "<redacted npm token>")
    .replace(/\bAIza[0-9A-Za-z_-]{20,}\b/g, "<redacted Google API key>")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "<redacted JWT>")
    .replace(/(\b(?:authorization|proxy-authorization)\b\s*[:=]\s*["'`]?(?:bearer|basic)\s+)[^\s"'`,;}]+/gi, "$1<redacted>")
    .replace(/((?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/)[^\s/@:]+(?::[^\s/@]*)?@/gi, "$1<redacted>@")
    .replace(/(\bcurl\b[^\r\n;]{0,300}?(?:-u|--user)(?:=|\s+))("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s;|]+)/gi, "$1<redacted>")
    .replace(
      /(\s--?(?:password|passwd|passphrase|token|api[-_]?key|auth[-_]?token|access[-_]?token|refresh[-_]?token|client[-_]?secret)(?:=|\s+))("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s;|]+)/gi,
      (match, prefix, rawValue) => (rawValue.startsWith("<redacted") ? match : `${prefix}${redactLiteral(rawValue)}`),
    )
    .replace(QUERY_VALUE, (match, separator, field, equals, rawValue) => (
      isSensitiveCredentialName(field) ? `${separator}${field}${equals}<redacted>` : match
    ));
  if (options.redactHighEntropy !== false) {
    redactedPatterns = redactedPatterns.replace(/\b[A-Za-z0-9_+/=-]{32,}\b/g, "<redacted high-entropy value>");
  }
  return redactCredentialContextLiterals(redactContextualValues(redactSensitiveAssignments(redactedPatterns)));
}

export function sanitizeEvidence(value, maximum = 220) {
  const compact = redactSensitiveText(value).replace(/\s+/g, " ").trim();
  return compact.length > maximum ? `${compact.slice(0, maximum - 1)}…` : compact;
}
