import { isHtmlDocument, regexEscape } from "./text.js";

export function markupTagTokens(text, expectedName = null) {
  const found = [];
  const expected = expectedName?.toLowerCase() ?? null;
  let cursor = 0;

  while (cursor < text.length) {
    const index = text.indexOf("<", cursor);
    if (index < 0) break;
    let nameStart = index + 1;
    let closing = false;
    if (text[nameStart] === "/") {
      closing = true;
      nameStart += 1;
    }
    const nameMatch = /^[a-z][\w:-]*/i.exec(text.slice(nameStart));
    if (!nameMatch) {
      cursor = index + 1;
      continue;
    }
    const name = nameMatch[0];
    const nameEnd = nameStart + name.length;
    // A real HTML/JSX tag name must end before whitespace, `/`, or `>`.
    // Regex source such as `/<html[\\s>]/` otherwise looks like an opening
    // document tag and can trigger document-only accessibility findings.
    if (nameEnd < text.length && !/[\s/>]/.test(text[nameEnd])) {
      cursor = nameEnd;
      continue;
    }
    if (expected && name.toLowerCase() !== expected) {
      cursor = nameEnd;
      continue;
    }

    let quote = null;
    let braceDepth = 0;
    let end = nameStart + name.length;
    for (; end < text.length; end += 1) {
      const character = text[end];
      if (quote) {
        if (character === "\\") {
          end += 1;
          continue;
        }
        if (character === quote) quote = null;
        continue;
      }
      if (character === '"' || character === "'" || character === "`") {
        quote = character;
        continue;
      }
      if (character === "{") {
        braceDepth += 1;
        continue;
      }
      if (character === "}" && braceDepth > 0) {
        braceDepth -= 1;
        continue;
      }
      if (character === ">" && braceDepth === 0) break;
    }
    if (end >= text.length) break;

    const raw = text.slice(index, end + 1);
    found.push({
      raw,
      index,
      end: end + 1,
      name,
      closing,
      selfClosing: !closing && /\/\s*>$/.test(raw),
    });
    cursor = end + 1;
  }
  return found;
}

export function tags(text, tagName) {
  return markupTagTokens(text, tagName)
    .filter(({ closing }) => !closing)
    .map(({ raw, index }) => ({ raw, index }));
}

export function pairedTags(text, tagName) {
  const found = [];
  const stack = [];
  for (const token of markupTagTokens(text, tagName)) {
    if (!token.closing) {
      if (!token.selfClosing) stack.push(token);
      continue;
    }
    const opening = stack.pop();
    if (!opening) continue;
    const attributes = opening.raw
      .slice(1 + opening.name.length)
      .replace(/>$/, "");
    found.push({
      raw: text.slice(opening.index, token.end),
      attributes,
      content: text.slice(opening.end, token.index),
      index: opening.index,
    });
  }
  return found.sort((left, right) => left.index - right.index);
}

export function hasAttribute(tag, attribute) {
  return new RegExp(`(?:^|\\s)${attribute}(?:\\s*=|\\s|/?>)`, "i").test(tag);
}

export function attributeValue(tag, attribute) {
  const escaped = attribute.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`(?:^|\\s)${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|{([^}]*)}|([^\\s>]+))`, "i").exec(tag);
  return match ? (match[1] ?? match[2] ?? match[3] ?? match[4] ?? "") : null;
}

// Return only values that source inspection can prove are static. Dynamic JSX
// expressions must not be validated as literal URLs or metadata values.
export function staticAttributeValue(tag, attribute) {
  const escaped = attribute.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(
    `(?:^|\\s)${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|\\{\\s*(["'\\x60])([\\s\\S]*?)\\3\\s*\\}|([^\\s>]+))`,
    "i",
  ).exec(tag);
  if (!match) return null;
  const value = match[1] ?? match[2] ?? match[4] ?? match[5] ?? "";
  // Template interpolation means the final value is runtime-dependent.
  return /\$\{/.test(value) ? null : value.trim();
}

export function decodeXmlText(value) {
  return String(value ?? "")
    .replace(/^<!\[CDATA\[([\s\S]*)\]\]>$/, "$1")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .trim();
}

export function absoluteWebUrlIssue(value, { requireHttps = false } = {}) {
  const normalized = decodeXmlText(value);
  if (!normalized) return "the URL is empty";
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    return "the URL is not absolute";
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return `the ${parsed.protocol} scheme is not crawlable`;
  if (parsed.username || parsed.password) return "the URL exposes embedded credentials";
  if (parsed.hash) return "the URL contains a fragment";
  if (requireHttps && parsed.protocol !== "https:" && !isLoopbackUrl(parsed)) return "the production URL does not use HTTPS";
  return null;
}

export function isLoopbackUrl(url) {
  const hostname = String(url?.hostname ?? "").replace(/^\[|\]$/g, "").toLowerCase();
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

export function hasMeaningfulAttribute(tag, attribute) {
  const value = attributeValue(tag, attribute);
  if (value === null) return false;
  const normalized = value.replace(/\s+/g, "").toLowerCase();
  return normalized.length > 0
    && !/^(?:["'`]{2}|null|undefined|false|&nbsp;|&#160;)$/.test(normalized);
}

export function hasEnabledBooleanAttribute(tag, attribute) {
  const escaped = attribute.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (!hasAttribute(tag, attribute)) return false;
  // JSX false/null/undefined remove a boolean attribute at render time. In HTML,
  // any other present value (including the string "false") still enables it.
  return !new RegExp(`(?:^|\\s)${escaped}\\s*=\\s*\\{\\s*(?:false|null|undefined)\\s*\\}`, "i").test(tag);
}

export function hasLiteralTrueAttribute(tag, attribute) {
  const value = attributeValue(tag, attribute);
  return value !== null && value.replace(/["'`{}\s]/g, "").toLowerCase() === "true";
}

export function normalizedAttributeToken(tag, attribute, fallback = "") {
  const value = attributeValue(tag, attribute);
  return (value ?? fallback).replace(/["'`{}\s]/g, "").toLowerCase();
}

export function hasJsxAttributeSpread(tag) {
  return /\{\s*\.\.\.[^}]+\}/.test(tag);
}

export function isNativeElementTag(file, tag, name) {
  const actualName = /^<([a-z][\w:-]*)\b/i.exec(tag)?.[1] ?? "";
  // HTML tag names are case-insensitive. Component-oriented source languages
  // use an initial capital for user components, so `<Input>` and `<Select>`
  // must not be treated as native controls by a source-only audit.
  return isHtmlDocument(file)
    ? actualName.toLowerCase() === name
    : actualName === name;
}

export function isStaticallyHiddenControl(tag) {
  if (hasEnabledBooleanAttribute(tag, "hidden") || hasLiteralTrueAttribute(tag, "aria-hidden")) return true;
  const classValue = attributeValue(tag, "className") ?? attributeValue(tag, "class") ?? "";
  if (/(?:^|\s)hidden(?:\s|$)/.test(classValue)) return true;
  const styleValue = attributeValue(tag, "style") ?? "";
  return /(?:^|[;,{]\s*)(?:display\s*:\s*none|visibility\s*:\s*hidden)\b/i.test(styleValue);
}

export function isInsideLabeledFormField(text, index) {
  const stack = [];
  for (const token of markupTagTokens(text, "FormField")) {
    if (!token.closing) {
      if (!token.selfClosing) stack.push(token);
      continue;
    }
    const opening = stack.pop();
    if (!opening || index < opening.end || index >= token.index) continue;
    const labeled = hasMeaningfulAttribute(opening.raw, "label")
      || hasMeaningfulAttribute(opening.raw, "aria-label") || hasMeaningfulAttribute(opening.raw, "aria-labelledby");
    if (!labeled) return false;
    const content = text.slice(opening.end, token.index);
    const children = markupTagTokens(content);
    const first = children[0];
    const blank = (value) => value.replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, "").trim() === "";
    if (!first || opening.end + first.index !== index || !blank(content.slice(0, first.index))) return false;
    const end = first.selfClosing ? first.end : children.find((child) => child.closing && child.name === first.name)?.end;
    // A component that clones one direct child cannot name nested controls,
    // fragments or multiple sibling controls through its outer group label.
    return end !== undefined && blank(content.slice(end));
  }
  return false;
}

function utilityClassTokens(tag) {
  const value = attributeValue(tag, "className") ?? attributeValue(tag, "class") ?? "";
  return value
    .replace(/["'`(),]/g, " ")
    .split(/\s+/)
    .filter(Boolean);
}

export function hasImageSizeContract(tag) {
  if ((hasMeaningfulAttribute(tag, "width") && hasMeaningfulAttribute(tag, "height"))
    || hasEnabledBooleanAttribute(tag, "fill")) return true;

  const style = attributeValue(tag, "style") ?? "";
  const hasInlineWidth = /(?:^|[;,{]\s*)width\s*:/i.test(style);
  const hasInlineHeight = /(?:^|[;,{]\s*)height\s*:/i.test(style);
  if ((hasInlineWidth && hasInlineHeight) || /\baspect(?:-?ratio|Ratio)\s*:/i.test(style)) return true;

  const tokens = utilityClassTokens(tag);
  const hasUtility = (name, excluded = []) => tokens.some((token) => {
    const utility = token.split(":").at(-1) ?? "";
    if (!utility.startsWith(`${name}-`)) return false;
    const value = utility.slice(name.length + 1).replace(/^!-?/, "");
    return value.length > 0 && !excluded.includes(value);
  });
  const hasAspectRatio = hasUtility("aspect", ["auto"])
    || tokens.some((token) => /\[aspect-ratio:[^\]]+\]/.test(token));
  const hasTwoAxisSize = hasUtility("size", ["auto"]);
  const hasWidth = hasUtility("w", ["auto", "fit", "max", "min"]);
  const hasHeight = hasUtility("h", ["auto", "fit", "max", "min"]);
  return hasAspectRatio || hasTwoAxisSize || (hasWidth && hasHeight);
}

function staticClassTokens(tag) {
  const value = attributeValue(tag, "className") ?? attributeValue(tag, "class");
  if (!value || /[{}$]/.test(value)) return [];
  return value.replace(/["'`]/g, " ").split(/\s+/).filter(Boolean);
}

function markupAncestorsAt(text, index) {
  const stack = [];
  for (const token of markupTagTokens(text.slice(0, index))) {
    if (!token.closing) {
      if (!token.selfClosing) stack.push(token);
      continue;
    }
    const name = token.name.toLowerCase();
    const openingIndex = stack.findLastIndex((candidate) => candidate.name.toLowerCase() === name);
    if (openingIndex >= 0) stack.splice(openingIndex);
  }
  return stack;
}

function cssAxisValue(declarations, property) {
  const match = new RegExp(`(?:^|;)\\s*${property}\\s*:\\s*([^;!}]+)`, "i").exec(declarations);
  return match?.[1]?.trim() ?? null;
}

function hasCssAxes(declarations, { fixed = false } = {}) {
  const width = cssAxisValue(declarations, "width");
  const height = cssAxisValue(declarations, "height");
  if (!width || !height
    || /^(?:auto|initial|inherit|unset)$/i.test(width)
    || /^(?:auto|initial|inherit|unset)$/i.test(height)) return false;
  if (!fixed) return true;
  return !/%$/.test(width) && !/%$/.test(height)
    && !/^(?:var|calc|min|max|clamp)\(/i.test(width)
    && !/^(?:var|calc|min|max|clamp)\(/i.test(height);
}

function localStyleRules(text) {
  return pairedTags(text, "style").flatMap((style) =>
    [...style.content.matchAll(/([^{}]+)\{([^{}]*)\}/g)].flatMap((match) =>
      match[1].split(",").map((selector) => ({ selector: selector.trim(), declarations: match[2] }))));
}

// Inline transcript/email templates often reserve an avatar's space through
// a fixed ancestor and a descendant image rule. Recognize only that provable,
// local two-rule contract; do not let an unrelated global `img` rule suppress
// a missing-dimensions finding.
export function hasLocalCssImageSizeContract(text, image) {
  const ancestorClasses = markupAncestorsAt(text, image.index)
    .flatMap(({ raw }) => staticClassTokens(raw));
  if (ancestorClasses.length === 0) return false;
  const rules = localStyleRules(text);

  return ancestorClasses.some((className) => {
    const escaped = regexEscape(className);
    const fixedAncestor = rules.some(({ selector, declarations }) =>
      new RegExp(`^\\.${escaped}(?:[:\\[].*)?$`).test(selector)
        && hasCssAxes(declarations, { fixed: true }));
    if (!fixedAncestor) return false;
    return rules.some(({ selector, declarations }) =>
      new RegExp(`(?:^|\\s)\\.${escaped}(?:[:\\[].*)?\\s+img(?:[:\\[].*)?$`, "i").test(selector)
        && hasCssAxes(declarations));
  });
}

export function imageDimensionCertainty(tag) {
  const dynamicSizing = hasJsxAttributeSpread(tag)
    || /\b(?:className|class|style)\s*=\s*\{\s*[a-z_$][\w$.[\]]*\s*\}/i.test(tag);
  if (dynamicSizing) return { confidence: "low", manual: true };
  if (hasAttribute(tag, "className") || hasAttribute(tag, "class") || hasAttribute(tag, "style")) {
    return { confidence: "medium", manual: true };
  }
  return { confidence: "high", manual: false };
}

export function openingTags(text) {
  return markupTagTokens(text)
    .filter(({ closing }) => !closing)
    .map(({ raw, index }) => ({ raw, index }));
}

export function isFocusableMarkup(tag) {
  const name = /^<([a-z][\w:-]*)\b/i.exec(tag)?.[1]?.toLowerCase();
  if (!name || hasEnabledBooleanAttribute(tag, "disabled") || hasEnabledBooleanAttribute(tag, "hidden")) return false;

  const tabIndex = attributeValue(tag, "tabindex");
  if (tabIndex !== null && /^\+?\d+$/.test(tabIndex.replace(/[{}\s]/g, ""))) return true;
  const contentEditable = attributeValue(tag, "contenteditable");
  if (hasAttribute(tag, "contenteditable")
    && (contentEditable === null || !/^(?:false|inherit)$/i.test(contentEditable.replace(/[{}\s]/g, "")))) return true;
  if (name === "a" || name === "area") return hasMeaningfulAttribute(tag, "href");
  if (["button", "select", "textarea", "iframe", "summary"].includes(name)) return true;
  if (name === "input") return (attributeValue(tag, "type") ?? "text").replace(/[{}\s]/g, "").toLowerCase() !== "hidden";
  if (name === "audio" || name === "video") return hasEnabledBooleanAttribute(tag, "controls");
  return false;
}

export function autocompletePurpose(tag) {
  const type = (attributeValue(tag, "type") ?? "text").replace(/[{}\s]/g, "").toLowerCase();
  const identities = [attributeValue(tag, "name"), attributeValue(tag, "id")]
    .filter(Boolean)
    .map((value) => value
      .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      .replace(/[^a-z0-9]+/gi, " ")
      .trim()
      .toLowerCase());
  const identity = identities.join(" ");

  if (type === "password") return {
    tokens: new Set(["current-password", "new-password"]),
    suggestion: "`current-password` or `new-password`, according to the field's purpose",
  };
  if (type === "email" || /(?:^|\s)e\s*mail(?:$|\s)/.test(identity)) return {
    contact: true,
    tokens: new Set(["email"]),
    suggestion: "`email`",
  };
  if (type === "tel" || /(?:^|\s)(?:tel|telephone|phone)(?:$|\s)/.test(identity)) return {
    contact: true,
    tokens: new Set(["tel", "tel-country-code", "tel-national", "tel-area-code", "tel-local", "tel-local-prefix", "tel-local-suffix", "tel-extension"]),
    suggestion: "`tel`",
  };
  if (/(?:^|\s)(?:user\s*name|login)(?:$|\s)/.test(identity)) return { tokens: new Set(["username"]), suggestion: "`username`" };
  if (/(?:^|\s)(?:first|given)\s*name(?:$|\s)/.test(identity)) return { tokens: new Set(["given-name"]), suggestion: "`given-name`" };
  if (/(?:^|\s)(?:last|family|sur)\s*name(?:$|\s)/.test(identity)) return { tokens: new Set(["family-name"]), suggestion: "`family-name`" };
  // A bare `name` is a personal-data purpose only when the whole id/name
  // identifies that field. Compound domain controls such as authorNameId,
  // thread-name-template, and templateName describe authored content rather
  // than the current user's full name.
  if (identities.some((value) => /^(?:full\s*name|name)$/.test(value))) {
    return { tokens: new Set(["name"]), suggestion: "`name`" };
  }
  if (/(?:^|\s)(?:zip|postal)(?:\s*code)?(?:$|\s)/.test(identity)) return { tokens: new Set(["postal-code"]), suggestion: "`postal-code`" };
  if (/(?:^|\s)(?:street\s*address|address\s*(?:line)?\s*1)(?:$|\s)/.test(identity)) {
    return { tokens: new Set(["street-address", "address-line1"]), suggestion: "`street-address` or `address-line1`" };
  }
  if (/(?:^|\s)(?:company|organization)(?:$|\s)/.test(identity)) return { tokens: new Set(["organization"]), suggestion: "`organization`" };
  return null;
}

export function hasValidAutocompletePurpose(tag, purpose) {
  const escaped = "autocomplete";
  const expression = new RegExp(`(?:^|\\s)${escaped}\\s*=\\s*\\{([^}]*)\\}`, "i").exec(tag);
  if (expression && !/^\s*["'`][\s\S]*["'`]\s*$/.test(expression[1])) return true;

  let value = attributeValue(tag, "autocomplete");
  if (value === null) return false;
  value = value.trim().replace(/^(["'`])([\s\S]*)\1$/, "$2").toLowerCase();
  const tokens = value.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return false;

  let index = 0;
  if (/^section-[a-z0-9_-]+$/.test(tokens[index] ?? "")) index += 1;
  if (["shipping", "billing"].includes(tokens[index])) index += 1;
  if (purpose.contact && ["home", "work", "mobile", "fax", "pager"].includes(tokens[index])) index += 1;
  if (!purpose.tokens.has(tokens[index])) return false;
  index += 1;
  if (tokens[index] === "webauthn") index += 1;
  return index === tokens.length;
}

export function isExplicitPriorityImage(tag, { framework = false } = {}) {
  const fetchPriority = attributeValue(tag, "fetchpriority")?.replace(/[{}\s]/g, "").toLowerCase();
  const dataLcp = attributeValue(tag, "data-lcp")?.replace(/[{}\s]/g, "").toLowerCase();
  return fetchPriority === "high"
    || (framework && hasEnabledBooleanAttribute(tag, "priority"))
    || (hasAttribute(tag, "data-lcp") && (dataLcp === null || dataLcp === "" || dataLcp === "true"));
}

export function hasUsableLanguage(tag) {
  const value = attributeValue(tag, "lang");
  if (value === null) return false;
  let normalized = value.trim();
  const jsxExpression = /(?:^|\s)lang\s*=\s*\{/i.test(tag);
  if (jsxExpression) {
    const literal = /(?:^|\s)lang\s*=\s*\{\s*(?:"((?:\\[\s\S]|[^"\\])*)"|'((?:\\[\s\S]|[^'\\])*)'|`((?:\\[\s\S]|[^`\\])*)`)\s*\}/i.exec(tag);
    if (!literal) {
      // Runtime expressions have no statically known language value. Null,
      // booleans and numeric literals are known invalid attribute values.
      return normalized.length > 0 && !/^(?:null|undefined|false|true|[-+]?\d+(?:\.\d+)?)$/i.test(normalized);
    }
    if (literal[3] !== undefined && /\$\{/.test(literal[3])) return true;
    normalized = (literal[1] ?? literal[2] ?? literal[3]).replace(
      /\\(?:u\{([\da-f]{1,6})\}|u([\da-f]{4})|x([\da-f]{2})|(\r?\n)|([\s\S]))/gi,
      (_match, codePoint, unicode, hexadecimal, continuation, escaped) => {
        if (continuation) return "";
        if (codePoint || unicode || hexadecimal) {
          const value = Number.parseInt(codePoint ?? unicode ?? hexadecimal, 16);
          return value <= 0x10FFFF ? String.fromCodePoint(value) : "\uFFFD";
        }
        return ({ n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", 0: "\0" })[escaped] ?? escaped;
      },
    ).trim();
  }
  if (!normalized || /^(?:["'`]{2}|null|undefined|false)$/i.test(normalized.replace(/\s+/g, ""))) return false;
  if (!jsxExpression && /[{}%$]/.test(normalized)) return true;
  return /^[a-z]{2,8}(?:-[a-z0-9]{1,8})*$/i.test(normalized);
}

export function visibleText(value) {
  return value
    .replace(/<svg\b[\s\S]*?<\/svg\s*>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:nbsp|#160);/gi, " ")
    .replace(/\{\s*(?:null|undefined|false|true)\s*\}/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function contentHasAccessibleText(content) {
  if (visibleText(content)) return true;
  const imageTags = [
    ...tags(content, "img"),
    ...[...content.matchAll(/<Image\b[^>]*>/g)].map((match) => ({ raw: match[0] })),
  ];
  if (imageTags.some(({ raw }) => hasMeaningfulAttribute(raw, "alt"))) return true;
  const svg = tags(content, "svg");
  return svg.some(({ raw }) => hasMeaningfulAttribute(raw, "aria-label") || hasMeaningfulAttribute(raw, "title"))
    || /<title\b[^>]*>\s*[^<\s][^<]*<\/title\s*>/i.test(content);
}

export function hasAccessibleName(tag, content = "") {
  return hasMeaningfulAttribute(tag, "aria-label")
    || hasMeaningfulAttribute(tag, "aria-labelledby")
    || hasMeaningfulAttribute(tag, "title")
    || contentHasAccessibleText(content);
}

export function isInsideMeaningfulLabel(text, index) {
  const before = text.slice(0, index).toLowerCase();
  const openingIndex = before.lastIndexOf("<label");
  if (openingIndex <= before.lastIndexOf("</label>")) return false;
  const openingEnd = text.indexOf(">", openingIndex);
  const closingIndex = text.toLowerCase().indexOf("</label>", index);
  if (openingEnd < 0 || closingIndex < 0) return false;
  const labelContent = text.slice(openingEnd + 1, closingIndex)
    .replace(/<(?:input|select|textarea)\b[^>]*>/gi, " ");
  return contentHasAccessibleText(labelContent);
}
