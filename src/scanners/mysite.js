import path from "node:path";

import {
  isMarkupFile,
  isSourceFile,
  isStyleFile,
  isTestFile,
  isWebAssetFile,
  readTextFile,
  verifyFileMetadata,
} from "../core/files.js";
import { buildScanResult, createFinding } from "../core/model.js";
import { createFindingIndex } from "../core/policy.js";
import { htmlDocumentSurface } from "../core/syntax.js";
import { detectWebProject } from "../core/project.js";
import { sanitizeEvidence } from "../core/sanitize.js";
import {
  CHECK_IDS,
  RULE_FAMILY_BY_FINDING,
  checkDescriptors,
} from "./mysite/catalog.js";
import {
  blankComment,
  compact,
  isHtmlDocument,
  isMarkdownDocument,
  lineAt,
  matchAt,
  regexEscape,
} from "./mysite/text.js";
import {
  absoluteWebUrlIssue,
  attributeValue,
  autocompletePurpose,
  contentHasAccessibleText,
  decodeXmlText,
  hasAccessibleName,
  hasAttribute,
  hasEnabledBooleanAttribute,
  hasImageSizeContract,
  hasJsxAttributeSpread,
  hasLiteralTrueAttribute,
  hasLocalCssImageSizeContract,
  hasMeaningfulAttribute,
  hasUsableLanguage,
  hasValidAutocompletePurpose,
  imageDimensionCertainty,
  isExplicitPriorityImage,
  isFocusableMarkup,
  isInsideLabeledFormField,
  isInsideMeaningfulLabel,
  isLoopbackUrl,
  isNativeElementTag,
  isStaticallyHiddenControl,
  markupTagTokens,
  normalizedAttributeToken,
  openingTags,
  pairedTags,
  staticAttributeValue,
  tags,
  visibleText,
} from "./mysite/markup.js";
import {
  analyzeMarkdown,
  auditMarkdown,
  markdownField,
  markdownScalar,
  meaningfulMarkdownScalar,
} from "./mysite/markdown.js";
import { auditHtmlDocument } from "./mysite/document.js";
import { auditStyles } from "./mysite/styles.js";
import {
  ASSET_BUDGET_BYTES,
  MEDIA_ASSET_EXTENSIONS,
  RASTER_IMAGE_EXTENSIONS,
  auditAsset,
} from "./mysite/assets.js";

const SEVERITY_RANK = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });
const CONFIDENCE_RANK = Object.freeze({ high: 0, medium: 1, low: 2 });

const UI_LIBRARIES = new Set([
  "@chakra-ui/react",
  "@mui/material",
  "@radix-ui/react-primitive",
  "@shopify/polaris",
  "@wordpress/components",
  "antd",
  "bootstrap",
  "daisyui",
  "flowbite",
  "react-bootstrap",
  "semantic-ui-react",
  "tailwindcss",
]);

const WEB_APP_LIBRARIES = new Set([
  "@angular/core",
  "@remix-run/react",
  "@sveltejs/kit",
  "astro",
  "gatsby",
  "next",
  "nuxt",
  "react",
  "react-dom",
  "solid-js",
  "svelte",
  "vue",
]);

const ANALYTICS_PATTERN = /\b(analytics|gtag|google tag manager|googletagmanager|segment\.|mixpanel|amplitude|matomo|plausible|posthog|clarity\(|hotjar|dataLayer)\b/i;
const CONSENT_PATTERN = /\b(consent|cookie preferences?|cookie settings|privacy preferences?|cmp|onetrust|cookiebot)\b/i;
const PRIVACY_PATTERN = /\b(privacy|gizlilik|kvkk|gdpr|ccpa|terms|koşullar|legal)\b/i;
const RESPONSIVE_UTILITY_PATTERN = /\b(?:sm|md|lg|xl|2xl):[a-z0-9_!/[.\]-]+/i;
const JAVASCRIPT_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".ts", ".tsx"]);
function maskJavaScriptComments(text) {
  const output = text.split("");
  let quote = null;

  const isEscaped = (index) => {
    let backslashes = 0;
    for (let cursor = index - 1; cursor >= 0 && text[cursor] === "\\"; cursor -= 1) backslashes += 1;
    return backslashes % 2 === 1;
  };

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (character === "\\") {
        index += 1;
        continue;
      }
      if (character === quote) quote = null;
      else if ((character === "\n" || character === "\r") && quote !== "`") quote = null;
      continue;
    }

    if (character === "'" || character === '"' || character === "`") {
      quote = character;
      continue;
    }
    if (character !== "/" || isEscaped(index)) continue;

    if (text[index + 1] === "/") {
      for (let cursor = index; cursor < text.length && text[cursor] !== "\n" && text[cursor] !== "\r"; cursor += 1) {
        output[cursor] = " ";
        index = cursor;
      }
      continue;
    }
    if (text[index + 1] === "*") {
      let cursor = index;
      while (cursor < text.length) {
        if (text[cursor] !== "\n" && text[cursor] !== "\r") output[cursor] = " ";
        if (text[cursor] === "*" && text[cursor + 1] === "/") {
          if (text[cursor + 1] !== "\n" && text[cursor + 1] !== "\r") output[cursor + 1] = " ";
          cursor += 1;
          break;
        }
        cursor += 1;
      }
      index = cursor;
    }
  }

  return output.join("");
}

function maskIgnoredComments(file, text) {
  let masked = text;
  if (isHtmlDocument(file) || isMarkdownDocument(file) || isMarkupFile(file) || isSourceFile(file)) {
    masked = masked
      .replace(/<!--[\s\S]*?-->/g, blankComment)
      .replace(/\{\/\*[\s\S]*?\*\/\}/g, blankComment);
  }
  if (JAVASCRIPT_EXTENSIONS.has(file.extension)) {
    masked = maskJavaScriptComments(masked);
  }
  if (isStyleFile(file)) masked = masked.replace(/\/\*[\s\S]*?\*\//g, blankComment);
  return masked;
}

function isConcreteHtmlDocument(file, text, deploymentRoots = new Set([""])) {
  if (!isHtmlDocument(file)) return false;
  if (/<!doctype\s+html\b|<html\b|<head\b|<body\b/i.test(text)) return true;

  return deploymentRelativePaths(file, deploymentRoots).some((relative) => {
    const segments = relative.split("/");
    if (segments.some((segment) => /^(?:components?|fragments?|includes?|partials?)$/.test(segment))) return false;
    if (segments.length === 1) return true;
    if (/^(?:public|static)\//.test(relative)) return true;
    if (/(?:^|\/)(?:pages?|routes?)\//.test(relative)) return true;
    return /(?:^|\/)(?:index|404|410|500|offline)\.html?$/.test(relative);
  });
}

function isMarkdownContentPage(file, deploymentRoots = new Set([""])) {
  if (!isMarkdownDocument(file)) return false;
  return deploymentRelativePaths(file, deploymentRoots).some((relative) =>
    /^(?:src\/)?(?:content|app|pages|routes)\//.test(relative));
}

function isPageLike(file, text = "", deploymentRoots = new Set([""])) {
  const relative = file.relative.toLowerCase();
  if (isHtmlDocument(file)) return isConcreteHtmlDocument(file, text, deploymentRoots);
  if (isMarkdownContentPage(file, deploymentRoots)) return true;
  return /(^|\/)(pages?|routes?)\/.*\.(jsx?|tsx?|vue|svelte|astro)$/.test(relative)
    || /(^|\/)app\/(?:.*\/)?(page|layout)\.(jsx?|tsx?)$/.test(relative)
    || /(^|\/)(app|page|index|home|landing)\.(jsx?|tsx?|vue|svelte|astro)$/.test(relative);
}

function isApplicationMountShell(file, text) {
  if (!isHtmlDocument(file)) return false;
  const hasMountRoot = /<(?:div|main)\b[^>]*\bid\s*=\s*["'](?:root|app|__next|__nuxt|svelte|application)["'][^>]*>/i.test(text);
  const hasApplicationScript = /<script\b[^>]*(?:type\s*=\s*["']module["']|src\s*=)[^>]*>/i.test(text);
  const hasStaticStructure = /<(?:article|form|h[1-6]|nav|section)\b/i.test(text);
  return hasMountRoot && hasApplicationScript && !hasStaticStructure;
}

function importBindings(clause) {
  const normalized = String(clause).replace(/^\s*type\s+/, "").trim();
  const bindings = [];
  const defaultBinding = /^([A-Z][\w$]*)\b/.exec(normalized)?.[1];
  if (defaultBinding) bindings.push({ name: defaultBinding, namespace: false });
  const namespace = /\*\s+as\s+([A-Z][\w$]*)\b/.exec(normalized)?.[1];
  if (namespace) bindings.push({ name: namespace, namespace: true });
  const named = /\{([\s\S]*?)\}/.exec(normalized)?.[1] ?? "";
  for (const entry of named.split(",")) {
    const candidate = entry.trim().replace(/^type\s+/, "");
    if (!candidate) continue;
    const binding = /\bas\s+([A-Z][\w$]*)\s*$/.exec(candidate)?.[1]
      ?? /^([A-Z][\w$]*)\b/.exec(candidate)?.[1];
    if (binding) bindings.push({ name: binding, namespace: false });
  }
  return bindings;
}

function sourceAliasRoot(file) {
  const segments = normalizedPath(file).split("/");
  const sourceIndex = segments.lastIndexOf("src");
  return sourceIndex >= 0 ? segments.slice(0, sourceIndex + 1).join("/") : "src";
}

function resolveLocalModule(importerFile, specifier, modulePaths) {
  const importer = normalizedPath(importerFile);
  let base;
  if (/^[~@]\//.test(specifier)) {
    base = path.posix.join(sourceAliasRoot(importerFile), specifier.slice(2));
  } else if (specifier.startsWith(".")) {
    base = path.posix.normalize(path.posix.join(path.posix.dirname(importer), specifier));
  } else {
    return null;
  }
  base = base.toLowerCase();
  const extension = path.posix.extname(base);
  const extensionless = extension && JAVASCRIPT_EXTENSIONS.has(extension)
    ? base.slice(0, -extension.length)
    : base;
  const candidates = [base, extensionless];
  for (const candidateExtension of JAVASCRIPT_EXTENSIONS) {
    candidates.push(`${extensionless}${candidateExtension}`);
    candidates.push(`${extensionless}/index${candidateExtension}`);
  }
  return candidates.find((candidate) => modulePaths.has(candidate)) ?? null;
}

function renderedLocalDependencies(context, modulePaths) {
  const dependencies = new Set();
  const imports = context.text.matchAll(/\bimport\s+(?!\s*type\b)([^;"']{1,500}?)\s+from\s+["']([^"'\r\n]+)["']/g);
  for (const match of imports) {
    const target = resolveLocalModule(context.file, match[2], modulePaths);
    if (!target) continue;
    const rendered = importBindings(match[1]).some(({ name, namespace }) => {
      const suffix = namespace ? "\\." : "(?=\\s|/?>)";
      return new RegExp(`<${regexEscape(name)}${suffix}`).test(context.text);
    });
    if (rendered) dependencies.add(target);
  }
  return dependencies;
}

// Resolve only explicit, local JSX composition contracts. A module qualifies
// when it contains an h1 itself or renders a local imported component whose
// module has already qualified. This covers shared PageHeader -> wrapper ->
// route chains without assuming that third-party components emit an h1 or
// attempting to execute application code.
function primaryHeadingContracts(contexts) {
  const modulePaths = new Set(contexts.map(({ file }) => normalizedPath(file)));
  const dependencies = new Map(contexts.map((context) => [
    normalizedPath(context.file),
    renderedLocalDependencies(context, modulePaths),
  ]));
  const contracts = new Set(contexts
    .filter(({ text }) => /<h1\b[^>]*>/i.test(text))
    .map(({ file }) => normalizedPath(file)));
  let changed = true;
  while (changed) {
    changed = false;
    for (const [modulePath, importedModules] of dependencies) {
      if (contracts.has(modulePath) || ![...importedModules].some((candidate) => contracts.has(candidate))) continue;
      contracts.add(modulePath);
      changed = true;
    }
  }
  return contracts;
}

function delegatesPrimaryHeading(file, text) {
  const relative = normalizedPath(file);
  if (/<Outlet\b/.test(text)) return true;
  if (/<Routes\b/.test(text) && /<Route\b/.test(text)) return true;
  if (/(?:^|\/)layout\.(?:jsx?|tsx?)$/.test(relative) && /\{\s*children\s*\}/.test(text)) return true;
  if (!/<Navigate\b/.test(text)) return false;
  return !/<(?:article|aside|button|form|h[1-6]|img|input|main|p|section|select|textarea|video)\b/i.test(text);
}

function literalRoutePath(tag) {
  const value = attributeValue(tag, "path")?.trim();
  if (!value) return null;
  const quoted = /^(?:"([\s\S]*)"|'([\s\S]*)'|`([\s\S]*)`)$/.exec(value);
  return (quoted ? (quoted[1] ?? quoted[2] ?? quoted[3] ?? "") : value).trim();
}

function isExplicitFallbackRoutePath(value) {
  return new Set(["*", "/*", "**", "/**", "404", "/404"]).has(value)
    || /^\/:\w*(?:pathmatch|catchall)\w*\(\.\*\)\*$/i.test(value);
}

function routeComponentName(tag) {
  for (const attribute of ["element", "Component", "component"]) {
    const value = attributeValue(tag, attribute)?.trim();
    if (!value) continue;
    const jsx = /^<\s*([A-Z][\w$]*(?:\.[A-Z][\w$]*)*)\b/.exec(value)?.[1];
    if (jsx) return jsx;
    const reference = /^([A-Z][\w$]*(?:\.[A-Z][\w$]*)*)$/.exec(value)?.[1];
    if (reference) return reference;
  }
  return null;
}

function localImportTargets(context, modulePaths) {
  const targets = new Map();
  const imports = context.text.matchAll(/\bimport\s+(?!\s*type\b)([^;"']{1,500}?)\s+from\s+["']([^"'\r\n]+)["']/g);
  for (const match of imports) {
    const target = resolveLocalModule(context.file, match[2], modulePaths);
    if (!target) continue;
    for (const binding of importBindings(match[1])) targets.set(binding.name, target);
  }
  return targets;
}

function isNotFoundComponentName(name) {
  const terminal = String(name).split(".").at(-1)?.replace(/[^a-z0-9]/gi, "").toLowerCase() ?? "";
  return /^(?:notfound|notfoundpage|pagenotfound|notfoundcomponent|pagenotfoundcomponent)$/.test(terminal);
}

function isNotFoundModulePath(modulePath) {
  const stem = path.posix.basename(modulePath, path.posix.extname(modulePath))
    .replace(/[^a-z0-9]/gi, "")
    .toLowerCase();
  return /^(?:404|notfound|notfoundpage|pagenotfound)$/.test(stem);
}

function hasLocalComponentDeclaration(text, name) {
  if (!/^[A-Z][\w$]*$/.test(name)) return false;
  return new RegExp(`\\b(?:class|function|const|let|var)\\s+${regexEscape(name)}\\b`).test(text);
}

// Treat a router fallback as implemented only when the route path is a static
// catch-all/404 literal and its element resolves to project source (or a local
// declaration). A similarly named but unused component, a package import, a
// computed path, or a catch-all redirect does not prove a not-found experience.
function hasExplicitLocalNotFoundRoute(contexts) {
  const modulePaths = new Set(contexts.map(({ file }) => normalizedPath(file)));
  for (const context of contexts) {
    const usesKnownJsxRouter = /\bfrom\s+["'](?:react-router(?:-dom)?|@tanstack\/react-router)["']/.test(context.text);
    if (!usesKnownJsxRouter) continue;
    const localTargets = localImportTargets(context, modulePaths);
    for (const route of tags(context.text, "Route")) {
      const routePath = literalRoutePath(route.raw);
      if (!routePath || !isExplicitFallbackRoutePath(routePath)) continue;
      const componentName = routeComponentName(route.raw);
      if (!componentName) continue;
      const rootBinding = componentName.split(".")[0];
      const target = localTargets.get(rootBinding);
      const localDeclaration = hasLocalComponentDeclaration(context.text, componentName);
      if (!target && !localDeclaration) continue;
      if (isNotFoundComponentName(componentName) || (target && isNotFoundModulePath(target))) return true;
    }
  }
  return false;
}

function containsMarkup(file, text) {
  if (isMarkupFile(file)) return true;
  return new Set([".js", ".mjs", ".cjs", ".mts", ".cts", ".ts"]).has(file.extension)
    && /<(?:a|article|aside|body|button|dialog|div|footer|form|h[1-6]|head|header|html|iframe|img|input|label|main|nav|section|select|textarea|video)(?=\s|\/?>)[^>]*>/i.test(text);
}

const AUDITABLE_SITE_EXTENSIONS = new Set([
  ".astro", ".cjs", ".css", ".htm", ".html", ".js", ".jsx", ".less",
  ".md", ".mdx", ".mjs", ".mts", ".cts", ".sass", ".scss", ".svelte", ".ts", ".tsx",
  ".vue",
]);

const NON_PRODUCTION_SEGMENTS = new Set([
  ".storybook",
  ".lhci",
  ".lighthouseci",
  "__fixtures__",
  "__generated__",
  "__mocks__",
  "__snapshots__",
  "__tests__",
  "coverage",
  "cypress",
  "e2e",
  "fixture",
  "fixtures",
  "generated",
  "lighthouse-report",
  "lighthouse-reports",
  "mocks",
  "playwright-report",
  "snapshot",
  "snapshots",
  "spec",
  "specs",
  "storybook",
  "storybook-static",
  "test",
  "test-results",
  "tests",
  "testing",
]);

const AUXILIARY_CONTENT_SEGMENTS = new Set([
  "demo",
  "demos",
  "docs",
  "documentation",
  "example",
  "examples",
  "stories",
]);

function normalizedPath(file) {
  return String(file.relative ?? "").replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();
}

function deploymentRelativePaths(file, deploymentRoots = new Set([""])) {
  const relative = normalizedPath(file);
  const candidates = [relative];
  for (const root of deploymentRoots) {
    if (!root) continue;
    const prefix = `${root.replace(/\/$/, "")}/`;
    if (relative.startsWith(prefix)) candidates.push(relative.slice(prefix.length));
  }
  return [...new Set(candidates)];
}

function likelyDeliveredAsset(asset, contexts, deploymentRoots = new Set([""])) {
  const candidates = deploymentRelativePaths(asset, deploymentRoots);
  const conventional = candidates.some((relative) =>
    /^(?:public|static|assets?|images?|img|fonts?|media|icons?)(?:\/|$)/.test(relative)
      || /^(?:favicon|apple-touch-icon|mask-icon)(?:[-.])/i.test(relative));
  if (conventional) return true;

  const basename = path.posix.basename(normalizedPath(asset));
  if (!basename) return false;
  return contexts.some(({ file, text }) => (containsMarkup(file, text) || isStyleFile(file))
    && text.toLowerCase().includes(basename));
}

function isDeployableStaticMetadata(file, kind, deploymentRoots = new Set([""])) {
  const target = kind === "robots" ? "robots.txt" : "sitemap.xml";
  return deploymentRelativePaths(file, deploymentRoots).some((relative) =>
    relative === target || relative === `public/${target}` || relative === `static/${target}`);
}

function isFrameworkMetadataRoute(file, kind, deploymentRoots = new Set([""])) {
  const name = kind === "robots" ? "robots" : "sitemap";
  const sourceExtension = "(?:js|jsx|mjs|cjs|ts|tsx)";
  return deploymentRelativePaths(file, deploymentRoots).some((relative) =>
    new RegExp(`^(?:src/)?app/(?:.*/)?${name}\\.${sourceExtension}$`).test(relative)
      || new RegExp(`^(?:src/)?pages/(?:.*/)?${name}(?:\\.txt|\\.xml)?\\.${sourceExtension}$`).test(relative)
      || new RegExp(`^app/routes/(?:.*/)?${name}(?:\\[\\.\\](?:txt|xml)|\\.(?:txt|xml))?\\.${sourceExtension}$`).test(relative)
      || new RegExp(`^(?:src/)?routes/(?:.*/)?${name}\\.(?:txt|xml)/\\+server\\.${sourceExtension}$`).test(relative)
      || new RegExp(`^server/routes/(?:.*/)?${name}\\.(?:txt|xml)\\.${sourceExtension}$`).test(relative));
}

function isProductionRouteOrContent(relative) {
  return /(?:^|\/)(?:src\/)?(?:app|pages|routes)(?:\/|$)/.test(relative)
    || /(?:^|\/)(?:src\/)?content(?:\/|$)/.test(relative)
    || /(?:^|\/)(?:public|static)(?:\/|$)/.test(relative);
}

function excludedFromProductionScope(file, options) {
  if (options.includeNonProduction === true) return false;
  const relative = normalizedPath(file);
  const firstSegment = relative.split("/", 1)[0];
  // A complete app nested below an explicitly auxiliary top-level tree is not
  // production evidence for the repository itself.
  if (NON_PRODUCTION_SEGMENTS.has(firstSegment) || AUXILIARY_CONTENT_SEGMENTS.has(firstSegment)) return true;
  // Test/spec/story filenames remain non-production even when they live under
  // a real route tree. Check the filename before preserving route segments so
  // `src/routes/account.test.tsx` is excluded while `app/test/page.tsx` remains
  // a deployable route.
  if (/\.(?:fixture|stories?|story|test|spec|snap)(?:\.[^.]+)+$/.test(relative)) return true;
  // Route segment names are user-facing URL structure, even when they happen
  // to be named test, generated, docs, demo, or examples inside a workspace.
  if (/(?:^|\/)(?:src\/)?(?:app|pages|routes)\//.test(relative)) return false;
  if (isTestFile(file)) return true;
  if (/(?:^|\/)(?:playwright|cypress|vitest|jest|karma|wdio)\.config\.(?:js|jsx|mjs|cjs|ts|tsx)$/.test(relative)) return true;
  if (/(?:^|\/)(?:fixtures?|mocks?|snapshots?|test[-_]utils?|spec[-_]utils?)\.(?:js|jsx|mjs|cjs|ts|tsx)$/.test(relative)) return true;
  if (/\.(?:generated|gen|min)\.(?:css|js|jsx|mjs|cjs|ts|tsx)$/.test(relative)) return true;

  const segments = relative.split("/");
  if (segments.some((segment) => NON_PRODUCTION_SEGMENTS.has(segment))) return true;
  if (segments.some((segment) => AUXILIARY_CONTENT_SEGMENTS.has(segment))) {
    return !isProductionRouteOrContent(relative);
  }
  return false;
}

function isAuditableSiteFile(file, deploymentRoots = new Set([""])) {
  const relative = normalizedPath(file);
  const name = path.posix.basename(relative);
  if (name === "package.json" || name === ".browserslistrc") return true;
  if (/^browserslist(?:\.config)?\./.test(name)) return true;
  if (isDeployableStaticMetadata(file, "robots", deploymentRoots) || isDeployableStaticMetadata(file, "sitemap", deploymentRoots)) return true;
  if (isFrameworkMetadataRoute(file, "robots", deploymentRoots) || isFrameworkMetadataRoute(file, "sitemap", deploymentRoots)) return true;
  if (name.endsWith(".webmanifest")) return true;
  if (AUDITABLE_SITE_EXTENSIONS.has(file.extension)) {
    if (file.extension === ".md" || file.extension === ".mdx") {
      return isMarkdownContentPage(file, deploymentRoots);
    }
    return true;
  }
  if (file.extension === ".json") {
    return deploymentRelativePaths(file, deploymentRoots).some((candidate) =>
      /^(?:public|static|src\/content|content)\//.test(candidate));
  }
  return false;
}

function hasGeneratedHeader(text) {
  return text.slice(0, 2_000).split(/\r?\n/).slice(0, 15).some((line) => {
    if (!/^\s*(?:\/\/+|\/\*+|\*+|<!--)/.test(line)) return false;
    if (/(?:@generated\b|auto(?:matically)?[- ]generated\b|(?:code|file) (?:is )?generated\b|generated (?:file|code)\b)/i.test(line)) return true;
    const comment = line
      .replace(/^\s*(?:\/\/+|\/\*+|\*+|<!--)\s*/, "")
      .replace(/\s*(?:\*\/|-->)\s*$/, "")
      .trim();
    return /^(?:(?:this|the) (?:file|code) (?:is )?)?do not edit[.!]*$/i.test(comment);
  });
}

function parseRobotsGroups(text) {
  const groups = [];
  let current = null;
  const lines = text.split(/\r?\n/);

  function finishGroup() {
    if (current?.agents.length) groups.push(current);
    current = null;
  }

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index];
    const content = raw.replace(/\s+#.*$/, "").trim();
    if (!content) continue;
    const separator = content.indexOf(":");
    if (separator < 0) continue;
    const key = content.slice(0, separator).trim().toLowerCase();
    const value = content.slice(separator + 1).trim();

    if (key === "user-agent") {
      if (current?.directives.length) finishGroup();
      current ??= { agents: [], directives: [] };
      current.agents.push(value.toLowerCase());
      continue;
    }
    if (!current?.agents.length) continue;
    current.directives.push({ key, value, raw: content, line: index + 1 });
  }
  finishGroup();
  return groups;
}

function wildcardRobotsBlock(text) {
  const wildcardDirectives = parseRobotsGroups(text)
    .filter((group) => group.agents.includes("*"))
    .flatMap((group) => group.directives);
  const rootBlock = wildcardDirectives.find(({ key, value }) => key === "disallow" && value === "/");
  if (!rootBlock) return null;
  const allowsEverything = wildcardDirectives.some(({ key, value }) => key === "allow" && (value === "/" || value === "/*"));
  return allowsEverything ? null : rootBlock;
}

function javascriptDelimitedEnd(text, start) {
  const closing = text[start] === "{" ? "}" : text[start] === "(" ? ")" : null;
  if (!closing) return -1;
  let depth = 0;
  let quote = null;
  for (let index = start; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (character === "\\") {
        index += 1;
        continue;
      }
      if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"' || character === "`") {
      quote = character;
      continue;
    }
    if (character === text[start]) depth += 1;
    else if (character === closing) {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  return -1;
}

function sanitizeHtmlImportName(text) {
  return /\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+["']sanitize-html["']/.exec(text)?.[1]
    ?? /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']sanitize-html["']\s*\)/.exec(text)?.[1]
    ?? null;
}

function storageRootBindings(text) {
  const bindings = new Map();
  const declarations = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*path\s*\.\s*(?:join|resolve)\s*\(\s*process\s*\.\s*cwd\s*\(\s*\)\s*,\s*["']([^"']{2,100})["']/gi;
  for (const declaration of text.matchAll(declarations)) {
    bindings.set(declaration[1], declaration[2].replace(/\\/g, "/").replace(/^\/+|\/+$/g, "").toLowerCase());
  }
  return bindings;
}

function pathStorageKeys(text, pathName, beforeIndex = text.length) {
  const keys = new Set();
  const bindings = storageRootBindings(text);
  const assignments = new RegExp(
    `\\b(?:const|let|var)\\s+${regexEscape(pathName)}(?:\\s*:[^=;\\r\\n]+)?\\s*=\\s*path\\s*\\.\\s*(?:join|resolve)\\s*\\(([^;\\r\\n]{1,1000})`,
    "gi",
  );
  for (const assignment of text.matchAll(assignments)) {
    if (assignment.index > beforeIndex) continue;
    const direct = /\bprocess\s*\.\s*cwd\s*\(\s*\)\s*,\s*["']([^"']{2,100})["']/i.exec(assignment[1])?.[1];
    if (direct) keys.add(direct.replace(/\\/g, "/").replace(/^\/+|\/+$/g, "").toLowerCase());
    for (const identifier of assignment[1].matchAll(/\b([A-Za-z_$][\w$]*)\b/g)) {
      const key = bindings.get(identifier[1]);
      if (key) keys.add(key);
    }
  }
  return keys;
}

function objectPropertyObject(text, property) {
  const declaration = new RegExp(`(?:["']${regexEscape(property)}["']|\\b${regexEscape(property)}\\b)\\s*:\\s*\\{`, "i").exec(text);
  if (!declaration) return null;
  const opening = declaration.index + declaration[0].lastIndexOf("{");
  const end = javascriptDelimitedEnd(text, opening);
  return end < 0 ? null : text.slice(opening, end);
}

function sanitizedResultExpression(expression, resultName) {
  const source = expression.trim();
  if (source === resultName) return true;
  const conditional = /^([\s\S]*?)\?([\s\S]+):([\s\S]+)$/.exec(source);
  if (!conditional) return false;
  const safeBranch = (branch) => {
    const value = branch.trim();
    if (value === resultName) return true;
    if (!value.startsWith("`") || !value.endsWith("`")) return false;
    const substitutions = [...value.matchAll(/\$\{([^}]*)\}/g)];
    return substitutions.length > 0
      && substitutions.every((match) => match[1].trim() === resultName)
      && value.replace(/\$\{[^}]*\}/g, "").indexOf("${") < 0;
  };
  return safeBranch(conditional[2]) && safeBranch(conditional[3]);
}

function sanitizerResultIsReturned(body, sanitizerImport, optionSource) {
  const callSource = `${regexEscape(sanitizerImport)}\\s*\\([^,]+,\\s*(?:${optionSource})\\s*\\)`;
  const exactCall = new RegExp(`^\\s*(?:await\\s+)?${callSource}\\s*$`, "is");
  const sanitizedVariables = new Set();
  const assignments = new RegExp(
    `\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)(?:\\s*:[^=;\\r\\n]+)?\\s*=\\s*(?:await\\s+)?${callSource}`,
    "gis",
  );
  for (const assignment of body.matchAll(assignments)) {
    sanitizedVariables.add(assignment[1]);
  }
  const returns = [...body.matchAll(/\breturn\b([\s\S]*?)(?:;|$)/g)].map((match) => match[1]);
  return returns.length > 0 && returns.every((expression) =>
    exactCall.test(expression)
      || [...sanitizedVariables].some((name) => sanitizedResultExpression(expression, name)));
}

function linkIsolationOptionNames(text, sanitizerImport) {
  const names = new Set();
  const declarations = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*\{/g;
  for (const declaration of text.matchAll(declarations)) {
    const opening = declaration.index + declaration[0].lastIndexOf("{");
    const end = javascriptDelimitedEnd(text, opening);
    if (end < 0) continue;
    const value = text.slice(opening, end);
    const transformTags = objectPropertyObject(value, "transformTags");
    const allowedAttributes = objectPropertyObject(value, "allowedAttributes");
    if (!transformTags || !allowedAttributes
      || !/(?:["']a["']|\ba\b)\s*:\s*\[[^\]]*["']rel["']/is.test(allowedAttributes)) continue;
    const transforms = new RegExp(
      `(?:["']a["']|\\ba\\b)\\s*:\\s*${regexEscape(sanitizerImport)}\\s*\\.\\s*simpleTransform\\s*\\(\\s*["']a["']\\s*,\\s*\\{([^}]{0,1000})\\}`,
      "gis",
    );
    const safeTransform = [...transformTags.matchAll(transforms)].some((match) =>
      /\btarget\s*:\s*["']_blank["']/i.test(match[1])
        && /\brel\s*:\s*["'][^"']*\b(?:noopener|noreferrer)\b[^"']*["']/i.test(match[1]));
    if (safeTransform) names.add(declaration[1]);
  }
  return names;
}

function verifiedLinkIsolationSanitizers(text) {
  const sanitizerImport = sanitizeHtmlImportName(text);
  if (!sanitizerImport) return new Set();
  const optionNames = linkIsolationOptionNames(text, sanitizerImport);
  if (optionNames.size === 0) return new Set();
  const optionSource = [...optionNames].map(regexEscape).join("|");
  const names = new Set();

  const functions = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)(?:\s*:\s*[^{\r\n]+)?\s*\{/g;
  for (const declaration of text.matchAll(functions)) {
    const opening = declaration.index + declaration[0].lastIndexOf("{");
    const end = javascriptDelimitedEnd(text, opening);
    if (end < 0) continue;
    if (sanitizerResultIsReturned(text.slice(opening + 1, end - 1), sanitizerImport, optionSource)) {
      names.add(declaration[1]);
    }
  }

  const arrows = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)(?:\s*:\s*[^=\r\n]+)?\s*=>\s*/g;
  for (const declaration of text.matchAll(arrows)) {
    const valueStart = declaration.index + declaration[0].length;
    const valueEnd = text[valueStart] === "{"
      ? javascriptDelimitedEnd(text, valueStart)
      : (() => {
          const terminator = text.slice(valueStart).search(/[;\r\n]/);
          return terminator < 0 ? text.length : valueStart + terminator;
        })();
    if (valueEnd <= valueStart) continue;
    const body = text.slice(valueStart, valueEnd);
    const expressionCall = new RegExp(
      `^\\s*(?:await\\s+)?${regexEscape(sanitizerImport)}\\s*\\([^,]+,\\s*(?:${optionSource})\\s*\\)\\s*$`,
      "is",
    );
    if ((text[valueStart] === "{" && sanitizerResultIsReturned(body, sanitizerImport, optionSource))
      || (text[valueStart] !== "{" && expressionCall.test(body))) {
      names.add(declaration[1]);
    }
  }
  return names;
}

function routeHandlerFlow(text, routeEnd) {
  const tail = text.slice(routeEnd, Math.min(text.length, routeEnd + 2000));
  const callback = /,\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{/.exec(tail);
  if (!callback) return null;
  const opening = routeEnd + callback.index + callback[0].lastIndexOf("{");
  const end = javascriptDelimitedEnd(text, opening);
  return end < 0 ? null : { start: opening + 1, text: text.slice(opening + 1, end - 1) };
}

function externalLinkIsolationContracts(contexts) {
  const contracts = [];
  for (const { file, text } of contexts) {
    const sanitizerNames = verifiedLinkIsolationSanitizers(text);
    if (sanitizerNames.size === 0) continue;
    const routes = /\.\s*(?:get|route)\s*\(\s*["']([^"']+)["']/g;
    for (const route of text.matchAll(routes)) {
      const parameter = /\/:([A-Za-z_$][\w$]*)$/.exec(route[1])?.[1];
      if (!parameter) continue;
      const routePrefix = route[1].slice(0, -(parameter.length + 2));
      if (!routePrefix || routePrefix === "/") continue;
      const handler = routeHandlerFlow(text, route.index + route[0].length);
      if (!handler) continue;
      const flow = handler.text;
      const reads = /\b(?:let|const|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*(?:await\s+)?(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:readFile|readFileSync)\s*\(\s*([A-Za-z_$][\w$]*)/g;
      for (const read of flow.matchAll(reads)) {
        const contentName = read[1];
        const pathName = read[2];
        const preceding = flow.slice(0, read.index);
        const pathProvenance = new RegExp(
          `\\b(?:const|let|var)\\s+${regexEscape(pathName)}(?:\\s*:[^=;\\r\\n]+)?\\s*=\\s*path\\s*\\.\\s*(?:join|resolve)\\s*\\([^;\\r\\n]{0,500}\\b${regexEscape(parameter)}\\b`,
          "i",
        ).test(preceding);
        if (!pathProvenance) continue;
        const storageKeys = pathStorageKeys(text, pathName, handler.start + read.index);
        if (storageKeys.size === 0) continue;

        const afterRead = flow.slice(read.index + read[0].length);
        const sanitizerName = [...sanitizerNames].find((name) =>
          new RegExp(
            `\\b${regexEscape(contentName)}\\s*=\\s*(?:await\\s+)?${regexEscape(name)}\\s*\\(\\s*${regexEscape(contentName)}\\s*\\)`,
            "i",
          ).test(afterRead));
        if (!sanitizerName) continue;
        const sanitizeCall = new RegExp(
          `\\b${regexEscape(contentName)}\\s*=\\s*(?:await\\s+)?${regexEscape(sanitizerName)}\\s*\\(\\s*${regexEscape(contentName)}\\s*\\)`,
          "i",
        ).exec(afterRead);
        const afterSanitize = afterRead.slice((sanitizeCall?.index ?? 0) + (sanitizeCall?.[0].length ?? 0));
        if (!new RegExp(`\\.\\s*send\\s*\\(\\s*${regexEscape(contentName)}\\s*\\)`, "i").test(afterSanitize)) continue;
        contracts.push({ consumer: normalizedPath(file), routePrefix, storageKeys });
        break;
      }
    }
  }
  return contracts;
}

function contentAssignmentContainsAnchor(text, contentName, anchorIndex, writeIndex) {
  const assignments = new RegExp(
    `(?:\\b(?:let|const|var)\\s+${regexEscape(contentName)}(?:\\s*:[^=;\\r\\n]+)?\\s*=|\\b${regexEscape(contentName)}\\s*\\+=)\\s*`,
    "gi",
  );
  for (const assignment of text.matchAll(assignments)) {
    if (assignment.index >= anchorIndex || assignment.index >= writeIndex) continue;
    const valueStart = assignment.index + assignment[0].length;
    const statementEnd = text.indexOf(";", valueStart);
    if (statementEnd < anchorIndex || statementEnd > writeIndex) continue;
    if (text.slice(valueStart, anchorIndex).includes("`")) return true;
  }
  return false;
}

function nextProducerBoundary(text, anchorIndex) {
  const tail = text.slice(anchorIndex + 1);
  const boundary = /(?:\b(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(|(?:^|[\r\n])\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*(?:\s*:[^=;\r\n]+)?\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)/gm.exec(tail);
  return boundary ? anchorIndex + 1 + boundary.index : text.length;
}

function hasDownstreamLinkIsolationContract(context, contracts, anchorIndex) {
  if (contracts.length === 0) return false;
  const text = context.text;
  const producerEnd = nextProducerBoundary(text, anchorIndex);
  const writes = /\b(?:await\s+)?(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\b/g;
  for (const write of text.matchAll(writes)) {
    const pathName = write[1];
    const contentName = write[2];
    if (write.index <= anchorIndex || write.index >= producerEnd
      || !contentAssignmentContainsAnchor(text, contentName, anchorIndex, write.index)) continue;
    const producerStorageKeys = pathStorageKeys(text, pathName, write.index);
    if (producerStorageKeys.size === 0) continue;
    const fileNames = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\r\n]+)?\s*=\s*(\x60[^\x60]{1,1000}\.html\x60)/gi;
    for (const fileName of text.matchAll(fileNames)) {
      if (fileName.index <= anchorIndex || fileName.index > write.index) continue;
      const fileNameVariable = fileName[1];
      const pathAssignment = new RegExp(
        `\\b(?:const|let|var)\\s+${regexEscape(pathName)}(?:\\s*:[^=;\\r\\n]+)?\\s*=\\s*path\\s*\\.\\s*(?:join|resolve)\\s*\\([^;\\r\\n]{0,500}\\b${regexEscape(fileNameVariable)}\\b`,
        "i",
      ).exec(text.slice(fileName.index, write.index));
      if (!pathAssignment) continue;

      for (const contract of contracts) {
        if (![...contract.storageKeys].some((key) => producerStorageKeys.has(key))) continue;
        const topic = path.posix.basename(contract.routePrefix).replace(/s$/i, "").toLowerCase();
        if (topic.length < 5 || !new RegExp(`^\\x60${regexEscape(topic)}-\\$\\{`, "i").test(fileName[2])) continue;
        const routeSource = regexEscape(contract.routePrefix.replace(/\/$/, ""));
        const url = new RegExp(
          `\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)(?:\\s*:[^=;\\r\\n]+)?\\s*=\\s*\\x60[^\\x60]{0,1000}${routeSource}\\/\\$\\{\\s*${regexEscape(fileNameVariable)}\\s*\\}[^\\x60]*\\x60`,
          "i",
        ).exec(text.slice(write.index, producerEnd));
        if (!url) continue;
        const afterUrl = text.slice(write.index + url.index + url[0].length, producerEnd);
        if (new RegExp(`\\breturn\\s*\\{[^}]{0,500}\\b${regexEscape(url[1])}\\b`, "i").test(afterUrl)) return true;
      }
    }
  }
  return false;
}

function dependencyNames(manifest) {
  const groups = [
    manifest?.dependencies,
    manifest?.devDependencies,
    manifest?.peerDependencies,
    manifest?.optionalDependencies,
  ];
  return new Set(groups.flatMap((group) => Object.keys(group ?? {})));
}

function recommendedEntryFiles(contexts, deploymentRoots = new Set([""])) {
  const preferred = contexts.filter(({ file, text }) =>
    isPageLike(file, text, deploymentRoots)
      && (isHtmlDocument(file) || isMarkdownDocument(file) || containsMarkup(file, text)));
  const candidates = preferred.length > 0 ? preferred : contexts.filter(({ file, text }) => containsMarkup(file, text));
  return candidates.slice(0, 4).map(({ file }) => file.relative);
}

function frameworkMetadataSignals(text) {
  const starts = [...text.matchAll(/\b(?:useSeoMeta|useHead|definePageMeta)\s*\(|\bexport\s+(?:const|function)\s+(?:meta|head|Head)\b|<(?:Helmet|svelte:head)\b/g)]
    .map((match) => match.index ?? 0);
  if (starts.length === 0) return null;
  const snippets = starts.map((index) => text.slice(index, index + 3_000)).join("\n");
  const descriptor = (name) => new RegExp(`\\bname\\s*:\\s*["']${name}["'][\\s\\S]{0,300}\\bcontent\\s*:`, "i").test(snippets);
  return {
    title: /<title\b|\btitle\s*:/i.test(snippets) || descriptor("title"),
    description: /\bdescription\s*:/i.test(snippets) || descriptor("description"),
    canonical: /\bcanonical\s*:|\brel\s*:\s*["']canonical["']/i.test(snippets),
    socialMetadata: /\b(?:openGraph|twitter|ogTitle|ogDescription|ogImage)\s*:|\b(?:property|name)\s*:\s*["'](?:og:|twitter:)/i.test(snippets),
    structuredData: /application\/ld\+json|schema\.org|\bjsonLd\s*:|\bstructuredData\s*:/i.test(snippets),
  };
}

function frameworkSuggestions(framework, contexts = []) {
  let expected;
  switch (String(framework ?? "").toLowerCase()) {
    case "next.js": expected = ["app/layout.tsx", "app/page.tsx"]; break;
    case "nuxt": expected = ["nuxt.config.ts", "app.vue"]; break;
    case "astro": expected = ["src/layouts/Layout.astro", "src/pages/index.astro"]; break;
    case "gatsby": expected = ["gatsby-config.js", "src/pages/index.jsx"]; break;
    case "remix": expected = ["app/root.tsx", "app/routes/_index.tsx"]; break;
    case "sveltekit": expected = ["src/routes/+layout.svelte", "src/routes/+page.svelte"]; break;
    case "angular": expected = ["src/index.html", "src/app/app.component.html"]; break;
    case "vue": expected = ["index.html", "src/App.vue"]; break;
    case "svelte": expected = ["index.html", "src/App.svelte"]; break;
    case "react": expected = ["index.html", "src/App.tsx"]; break;
    case "vite": expected = ["index.html", "src/main.js"]; break;
    default: return [];
  }

  const actualPaths = new Map(contexts.map(({ file }) => [normalizedPath(file), file.relative]));
  const roots = new Set([""]);
  for (const actual of actualPaths.keys()) {
    for (const candidate of expected) {
      const normalizedCandidate = candidate.toLowerCase();
      if (actual === normalizedCandidate) roots.add("");
      else if (actual.endsWith(`/${normalizedCandidate}`)) {
        roots.add(actual.slice(0, -(normalizedCandidate.length + 1)));
      }
    }
  }
  const rankedRoots = [...roots]
    .map((root) => ({
      root,
      matches: expected.map((candidate) => {
        const key = root ? `${root}/${candidate.toLowerCase()}` : candidate.toLowerCase();
        return actualPaths.get(key) ?? null;
      }).filter(Boolean),
    }))
    .filter(({ matches }) => matches.length > 0)
    .sort((left, right) => right.matches.length - left.matches.length
      || left.root.split("/").length - right.root.split("/").length
      || left.root.localeCompare(right.root));
  return rankedRoots[0]?.matches ?? [];
}

function createCollector(options = {}) {
  const findings = [];
  const findingIndex = createFindingIndex("mysite");
  const counts = new Map();
  const suppressedByRule = {};
  const suppressedSeverityByRule = {};
  const requestedLimit = Number(options.maxFindingsPerRule ?? 50);
  const defaultLimit = Number.isFinite(requestedLimit) ? Math.max(1, Math.floor(requestedLimit)) : 50;
  const comparePriority = (left, right) => {
    const severity = (SEVERITY_RANK[left.severity] ?? 99) - (SEVERITY_RANK[right.severity] ?? 99);
    if (severity !== 0) return severity;
    const confidence = (CONFIDENCE_RANK[left.confidence] ?? 99) - (CONFIDENCE_RANK[right.confidence] ?? 99);
    if (confidence !== 0) return confidence;
    if (left.manual !== right.manual) return left.manual ? 1 : -1;
    const file = String(left.file ?? "").localeCompare(String(right.file ?? ""));
    if (file !== 0) return file;
    return Number(left.line ?? 0) - Number(right.line ?? 0);
  };

  function add(input, limit = defaultLimit) {
    const recommendation = input.recommendation ?? input.action ?? "Review and correct this issue.";
    const candidate = createFinding({
      ...input,
      ruleFamily: input.ruleFamily ?? RULE_FAMILY_BY_FINDING[input.id] ?? input.id,
      action: input.action ?? recommendation,
      confidence: input.confidence ?? (input.manual ? "medium" : "high"),
      evidence: sanitizeEvidence(input.evidence),
      recommendation,
      suggestedFiles: [...new Set((input.suggestedFiles ?? []).filter(Boolean))].slice(0, 6),
      tags: [...new Set(input.tags ?? [])],
    });
    findingIndex.record(candidate);
    const current = counts.get(input.id) ?? 0;
    if (current >= limit) {
      suppressedByRule[input.id] = (suppressedByRule[input.id] ?? 0) + 1;
      const retainedIndices = findings.flatMap((finding, index) => finding.id === candidate.id ? [index] : []);
      const lowestPriorityIndex = retainedIndices.reduce((selected, index) => (
        selected === null || comparePriority(findings[index], findings[selected]) > 0
          ? index
          : selected
      ), null);
      const replaceRetained = lowestPriorityIndex !== null
        && comparePriority(candidate, findings[lowestPriorityIndex]) < 0;
      const suppressedSeverity = replaceRetained ? findings[lowestPriorityIndex].severity : candidate.severity;
      suppressedSeverityByRule[input.id] ??= {};
      suppressedSeverityByRule[input.id][suppressedSeverity] = (suppressedSeverityByRule[input.id][suppressedSeverity] ?? 0) + 1;
      if (replaceRetained) findings[lowestPriorityIndex] = candidate;
      return;
    }
    counts.set(input.id, current + 1);
    findings.push(candidate);
  }

  return { add, findings, findingIndex: findingIndex.entries, maxFindingsPerRule: defaultLimit, suppressedByRule, suppressedSeverityByRule };
}

function projectFinding(add, entryFiles, input) {
  const file = input.file ?? entryFiles[0] ?? null;
  add({
    ...input,
    file,
    line: input.line ?? (file ? 1 : null),
    suggestedFiles: input.suggestedFiles ?? entryFiles,
  }, input.limit ?? 1);
}

function auditMarkup(
  context,
  add,
  deploymentRoots = new Set([""]),
  headingContracts = new Set(),
  linkIsolationContracts = [],
) {
  const { file, text } = context;

  if (!isHtmlDocument(file)) {
    const htmlTag = tags(text, "html")[0];
    if (htmlTag && !hasUsableLanguage(htmlTag.raw)) {
      add({
        id: "a11y-document-language",
        title: "Document language is missing or invalid",
        category: "Accessibility",
        severity: "medium",
        description: "Assistive technologies need the page language to choose pronunciation and reading rules.",
        evidence: htmlTag.raw,
        file: file.relative,
        line: lineAt(text, htmlTag.index),
        recommendation: "Add a valid `lang` attribute to the root `<html>` element and update it when the page language changes.",
        suggestedFiles: [file.relative],
        tags: ["screen-reader", "semantic-html", "i18n"],
      });
    }
  }

  for (const script of pairedTags(text, "script")) {
    if (!isNativeElementTag(file, script.raw, "script")) continue;
    const opening = `<script${script.attributes}>`;
    const type = staticAttributeValue(opening, "type")?.toLowerCase();
    if (type !== "application/ld+json") continue;
    const payload = script.content.trim();
    // JSX and template expressions are runtime data, not invalid literal JSON.
    if (!payload || /^\{\s*(?:JSON\.stringify\b|[A-Za-z_$][\w$.[\]]*\s*\})/i.test(payload)) continue;
    try {
      JSON.parse(payload);
    } catch {
      add({
        id: "seo-invalid-structured-data",
        title: "JSON-LD block is not valid JSON",
        category: "SEO & structured data",
        severity: "medium",
        description: "Malformed JSON-LD cannot be parsed reliably by search or answer engines, even when the script type is present.",
        evidence: compact(payload, 180),
        file: file.relative,
        line: lineAt(text, script.index),
        recommendation: "Serialize this block as strict JSON, validate it after rendering, and ensure every declared entity matches visible page content.",
        suggestedFiles: [file.relative],
        tags: ["seo", "geo", "aeo", "aio", "json-ld", "schema.org"],
        references: ["https://developers.google.com/search/docs/appearance/structured-data/intro-structured-data"],
      });
    }
  }

  for (const image of tags(text, "img")) {
    if (!isNativeElementTag(file, image.raw, "img")) continue;
    if (!hasAttribute(image.raw, "alt")) {
      add({
        id: "a11y-image-alt",
        title: "Image is missing alternative text",
        category: "Accessibility",
        severity: "high",
        description: "An image without `alt` is not reliably understandable to screen-reader users.",
        evidence: image.raw,
        file: file.relative,
        line: lineAt(text, image.index),
        recommendation: "Add concise, meaningful `alt` text, or `alt=\"\"` when the image is purely decorative.",
        suggestedFiles: [file.relative],
        tags: ["screen-reader", "images", "wcag"],
      });
    }

    const hasDimensions = hasImageSizeContract(image.raw)
      || hasLocalCssImageSizeContract(text, image);
    if (!hasDimensions) {
      const certainty = imageDimensionCertainty(image.raw);
      add({
        id: "performance-image-dimensions",
        title: "Image has no detectable size contract",
        category: "Performance",
        severity: "low",
        ...certainty,
        description: "Static markup does not show intrinsic dimensions, an inline aspect ratio, or a recognizable two-axis sizing utility. External CSS or spread props may still reserve space and require rendered verification.",
        evidence: image.raw,
        file: file.relative,
        line: lineAt(text, image.index),
        recommendation: "Declare `width` and `height`, an aspect ratio, or a framework image `fill` layout with a sized container.",
        suggestedFiles: [file.relative],
        tags: ["core-web-vitals", "cls", "responsive-images"],
      });
    }

    const loading = attributeValue(image.raw, "loading")?.replace(/[{}\s]/g, "").toLowerCase();
    if (loading === "lazy" && isExplicitPriorityImage(image.raw)) {
      add({
        id: "performance-priority-image-lazy",
        title: "Priority image is also configured for lazy loading",
        category: "Performance",
        severity: "medium",
        description: "Deferring an explicitly high-priority image can delay a likely Largest Contentful Paint resource.",
        evidence: image.raw,
        file: file.relative,
        line: lineAt(text, image.index),
        recommendation: "Remove lazy loading from the above-the-fold priority image, keep its dimensions, and verify `fetchpriority=\"high\"` is reserved for the actual LCP candidate.",
        suggestedFiles: [file.relative],
        tags: ["core-web-vitals", "lcp", "image-delivery"],
      });
    }
  }

  for (const match of text.matchAll(/<Image\b[^>]*>/g)) {
    const image = { raw: match[0], index: match.index ?? 0 };
    if (!hasAttribute(image.raw, "alt")) {
      add({
        id: "a11y-image-alt",
        title: "Framework image is missing alternative text",
        category: "Accessibility",
        severity: "high",
        description: "An image component without `alt` is not reliably understandable to screen-reader users.",
        evidence: image.raw,
        file: file.relative,
        line: lineAt(text, image.index),
        recommendation: "Pass concise, meaningful `alt` text, or an empty string when the image is purely decorative.",
        suggestedFiles: [file.relative],
        tags: ["screen-reader", "images", "wcag"],
      });
    }
    const hasDimensions = hasImageSizeContract(image.raw)
      || hasLocalCssImageSizeContract(text, image);
    if (!hasDimensions) {
      const certainty = imageDimensionCertainty(image.raw);
      add({
        id: "performance-image-dimensions",
        title: "Framework image has no detectable size contract",
        category: "Performance",
        severity: "low",
        ...certainty,
        description: "Static component props do not show intrinsic dimensions, a fill layout, an inline aspect ratio, or a recognizable two-axis sizing utility. Imported-image metadata, external CSS, or spread props may still reserve space and require rendered verification.",
        evidence: image.raw,
        file: file.relative,
        line: lineAt(text, image.index),
        recommendation: "Pass intrinsic `width`/`height`, or use `fill` inside a predictably sized responsive container.",
        suggestedFiles: [file.relative],
        tags: ["core-web-vitals", "cls", "responsive-images"],
      });
    }
    const loading = attributeValue(image.raw, "loading")?.replace(/[{}\s]/g, "").toLowerCase();
    if (loading === "lazy" && isExplicitPriorityImage(image.raw, { framework: true })) {
      add({
        id: "performance-priority-image-lazy",
        title: "Priority framework image is also configured for lazy loading",
        category: "Performance",
        severity: "medium",
        description: "A framework priority hint and lazy loading express conflicting fetch strategies for a likely LCP resource.",
        evidence: image.raw,
        file: file.relative,
        line: lineAt(text, image.index),
        recommendation: "Remove `loading=\"lazy\"` from this priority image and confirm it is the route's actual above-the-fold LCP candidate.",
        suggestedFiles: [file.relative],
        tags: ["core-web-vitals", "lcp", "image-delivery"],
      });
    }
  }

  for (const iframe of tags(text, "iframe")) {
    if (!isNativeElementTag(file, iframe.raw, "iframe")) continue;
    if (!hasMeaningfulAttribute(iframe.raw, "title")) {
      add({
        id: "a11y-iframe-title",
        title: "Embedded frame has no accessible title",
        category: "Accessibility",
        severity: "medium",
        description: "Screen-reader users need a title to understand an embedded frame before entering it.",
        evidence: iframe.raw,
        file: file.relative,
        line: lineAt(text, iframe.index),
        recommendation: "Add a short, unique `title` describing the frame's content or purpose.",
        suggestedFiles: [file.relative],
        tags: ["screen-reader", "embedded-content"],
      });
    }
  }

  for (const media of [...tags(text, "audio"), ...tags(text, "video")]) {
    const mediaName = /^<([a-z][\w:-]*)\b/i.exec(media.raw)?.[1]?.toLowerCase();
    if (!mediaName || !isNativeElementTag(file, media.raw, mediaName)) continue;
    if (!hasEnabledBooleanAttribute(media.raw, "autoplay") || hasEnabledBooleanAttribute(media.raw, "muted")) continue;
    add({
      id: "a11y-audible-autoplay",
      title: "Audible media is configured to autoplay",
      category: "Accessibility",
      severity: "medium",
      description: "Unexpected sound interferes with screen readers, concentration, and a user's control over the page.",
      evidence: media.raw,
      file: file.relative,
      line: lineAt(text, media.index),
      recommendation: "Remove autoplay and let the user start playback. If a decorative silent video must autoplay, keep it muted, inline, pausable, and compatible with reduced-motion preferences.",
      suggestedFiles: [file.relative],
      tags: ["media", "user-control", "wcag", "reduced-motion"],
    });
  }

  for (const button of pairedTags(text, "button")) {
    if (!isNativeElementTag(file, button.raw, "button")) continue;
    const opening = `<button${button.attributes}>`;
    if (!hasAccessibleName(opening, button.content)) {
      add({
        id: "a11y-control-name",
        title: "Button has no accessible name",
        category: "Accessibility",
        severity: "high",
        description: "Icon-only or empty buttons are ambiguous to screen-reader and voice-control users.",
        evidence: button.raw,
        file: file.relative,
        line: lineAt(text, button.index),
        recommendation: "Add visible text or a specific `aria-label`/`aria-labelledby` value.",
        suggestedFiles: [file.relative],
        tags: ["screen-reader", "interaction", "affordance"],
      });
    }
  }

  for (const control of tags(text, "input")) {
    if (!isNativeElementTag(file, control.raw, "input")) continue;
    const type = normalizedAttributeToken(control.raw, "type", "text");
    if (type !== "image" || hasMeaningfulAttribute(control.raw, "alt") || hasAccessibleName(control.raw)) continue;
    add({
      id: "a11y-image-input-alt",
      title: "Image submit control has no accessible name",
      category: "Accessibility",
      severity: "high",
      description: "An input image without alternative text does not expose the control's action to screen-reader users.",
      evidence: control.raw,
      file: file.relative,
      line: lineAt(text, control.index),
      recommendation: "Add concise `alt` text describing the submit action, or replace the image input with a named button.",
      suggestedFiles: [file.relative],
      tags: ["wcag", "forms", "screen-reader", "controls"],
      standards: [{
        id: "WCAG-1.1.1",
        title: "WCAG 2.2 — Non-text Content",
        url: "https://www.w3.org/WAI/WCAG22/Understanding/non-text-content.html",
      }],
    });
  }

  for (const dialog of openingTags(text)) {
    const name = /^<([a-z][\w:-]*)\b/i.exec(dialog.raw)?.[1] ?? "";
    const role = staticAttributeValue(dialog.raw, "role")?.toLowerCase();
    const nativeDialog = isHtmlDocument(file) ? name.toLowerCase() === "dialog" : name === "dialog";
    if (!nativeDialog && !["dialog", "alertdialog"].includes(role)) continue;
    if (hasAccessibleName(dialog.raw)) continue;
    add({
      id: "a11y-dialog-name",
      title: "Dialog has no programmatic accessible name",
      category: "Accessibility",
      severity: "high",
      description: "A dialog must announce a concise purpose when focus enters it; visible descendant text does not name the dialog automatically.",
      evidence: dialog.raw,
      file: file.relative,
      line: lineAt(text, dialog.index),
      recommendation: "Reference the visible dialog heading with `aria-labelledby`, or add a concise `aria-label` when no visible heading is appropriate.",
      suggestedFiles: [file.relative],
      tags: ["wcag", "dialog", "screen-reader", "focus-management"],
      standards: [{
        id: "WCAG-4.1.2",
        title: "WCAG 2.2 — Name, Role, Value",
        url: "https://www.w3.org/WAI/WCAG22/Understanding/name-role-value.html",
      }],
    });
  }

  const interactiveContainers = [
    ...pairedTags(text, "button")
      .filter((item) => isNativeElementTag(file, item.raw, "button"))
      .map((item) => ({ ...item, ancestor: "button" })),
    ...pairedTags(text, "a")
      .filter((item) => isNativeElementTag(file, item.raw, "a")
        && hasMeaningfulAttribute(`<a${item.attributes}>`, "href"))
      .map((item) => ({ ...item, ancestor: "link" })),
  ];
  for (const container of interactiveContainers) {
    const nested = openingTags(container.content).find(({ raw }) => isFocusableMarkup(raw));
    if (!nested) continue;
    const contentOffset = container.raw.indexOf(container.content);
    add({
      id: "a11y-interactive-nesting",
      title: `Interactive control is nested inside a ${container.ancestor}`,
      category: "Accessibility & interaction",
      severity: "high",
      description: "Nested interactive controls create conflicting click, focus, keyboard, and accessibility-tree behavior.",
      evidence: compact(`${container.raw.slice(0, container.raw.indexOf(">") + 1)} … ${nested.raw}`),
      file: file.relative,
      line: lineAt(text, container.index + Math.max(0, contentOffset) + nested.index),
      recommendation: "Use one interactive element for the action, or place independent controls beside each other instead of nesting them.",
      suggestedFiles: [file.relative],
      tags: ["keyboard", "screen-reader", "semantic-html", "interaction"],
    });
  }

  for (const fieldset of pairedTags(text, "fieldset")) {
    if (!isNativeElementTag(file, fieldset.raw, "fieldset")) continue;
    const groupedControls = openingTags(fieldset.content).filter(({ raw }) => {
      const name = /^<([a-z][\w:-]*)\b/i.exec(raw)?.[1]?.toLowerCase();
      if (!["input", "select", "textarea"].includes(name)) return false;
      if (!isNativeElementTag(file, raw, name)) return false;
      return name !== "input" || normalizedAttributeToken(raw, "type", "text") !== "hidden";
    });
    if (groupedControls.length < 2) continue;
    const legend = pairedTags(fieldset.content, "legend").find((item) => contentHasAccessibleText(item.content));
    if (legend) continue;
    add({
      id: "a11y-fieldset-legend",
      title: "Grouped form controls have no usable legend",
      category: "Accessibility",
      severity: "medium",
      description: "A fieldset needs a legend so assistive technology announces the shared question or purpose with its controls.",
      evidence: compact(fieldset.raw, 180),
      file: file.relative,
      line: lineAt(text, fieldset.index),
      recommendation: "Add a concise visible `<legend>` as the first fieldset child; keep each individual control labelled as well.",
      suggestedFiles: [file.relative],
      tags: ["wcag", "forms", "screen-reader", "semantic-html"],
      standards: [{
        id: "WCAG-1.3.1",
        title: "WCAG 2.2 — Info and Relationships",
        url: "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships.html",
      }],
    });
  }

  for (const table of pairedTags(text, "table")) {
    if (!isNativeElementTag(file, table.raw, "table")) continue;
    if (!/<th\b/i.test(table.content)) continue;
    const caption = pairedTags(table.content, "caption").find((item) => contentHasAccessibleText(item.content));
    const opening = `<table${table.attributes}>`;
    if (caption || hasMeaningfulAttribute(opening, "aria-label") || hasMeaningfulAttribute(opening, "aria-labelledby")) continue;
    add({
      id: "a11y-table-name",
      title: "Data table has no detectable accessible name",
      category: "Accessibility & content structure",
      severity: "low",
      confidence: "medium",
      manual: true,
      description: "A concise table name helps users understand the relationship represented by rows and columns before navigating the cells.",
      evidence: compact(table.raw, 180),
      file: file.relative,
      line: lineAt(text, table.index),
      recommendation: "Add a descriptive `<caption>`, preferably visible, or reference an existing visible heading with `aria-labelledby`.",
      suggestedFiles: [file.relative],
      tags: ["tables", "screen-reader", "semantic-html", "scannability"],
    });
  }

  for (const anchor of pairedTags(text, "a")) {
    if (!isNativeElementTag(file, anchor.raw, "a")) continue;
    const opening = `<a${anchor.attributes}>`;
    const label = visibleText(anchor.content);
    if (!hasAccessibleName(opening, anchor.content)) {
      add({
        id: "a11y-link-name",
        title: "Link has no accessible name",
        category: "Accessibility",
        severity: "high",
        description: "An unnamed link cannot communicate its destination or purpose.",
        evidence: anchor.raw,
        file: file.relative,
        line: lineAt(text, anchor.index),
        recommendation: "Add meaningful link text or an accessible label that describes the destination.",
        suggestedFiles: [file.relative],
        tags: ["navigation", "screen-reader", "seo"],
      });
    } else if (/^(click here|here|read more|learn more|buraya tıkla|tıkla|devamı)$/i.test(label)) {
      add({
        id: "ux-ambiguous-link-text",
        title: "Link text is ambiguous out of context",
        category: "Usability",
        severity: "low",
        description: "Generic link labels are difficult to scan and unhelpful in a screen reader's links list.",
        evidence: compact(anchor.raw),
        file: file.relative,
        line: lineAt(text, anchor.index),
        recommendation: "Replace generic text with a concise description of the destination or action.",
        suggestedFiles: [file.relative],
        tags: ["scannability", "navigation", "screen-reader"],
      });
    }

    if (!hasMeaningfulAttribute(opening, "href") && /\b(?:onClick|onclick)\s*=/.test(opening)) {
      add({
        id: "a11y-clickable-noncontrol",
        title: "Anchor without a destination is used as a control",
        category: "Accessibility & interaction",
        severity: "high",
        description: "An anchor without `href` is not a keyboard-operable link and exposes the wrong interaction semantics.",
        evidence: compact(opening),
        file: file.relative,
        line: lineAt(text, anchor.index),
        recommendation: "Use a native `<button type=\"button\">` for an action, or provide a real `href` when this navigates to a destination.",
        suggestedFiles: [file.relative],
        tags: ["keyboard", "semantic-html", "affordance", "navigation"],
      });
    }

    if (/\btarget\s*=\s*["']_blank["']/i.test(opening)
      && !/\brel\s*=\s*["'][^"']*\b(?:noopener|noreferrer)\b/i.test(opening)
      && !hasDownstreamLinkIsolationContract(context, linkIsolationContracts, anchor.index)) {
      add({
        id: "security-external-link-opener",
        title: "New-tab link does not isolate its opener",
        category: "Security & privacy",
        severity: "medium",
        description: "A new tab can retain access to the opener in browser configurations that do not add isolation automatically.",
        evidence: anchor.raw,
        file: file.relative,
        line: lineAt(text, anchor.index),
        recommendation: "Add `rel=\"noopener noreferrer\"` to links that use `target=\"_blank\"`.",
        suggestedFiles: [file.relative],
        tags: ["security", "external-links", "trust"],
      });
    }
  }

  for (const svg of pairedTags(text, "svg")) {
    if (!isNativeElementTag(file, svg.raw, "svg")) continue;
    const opening = `<svg${svg.attributes}>`;
    if (staticAttributeValue(opening, "role")?.toLowerCase() !== "img") continue;
    if (hasAccessibleName(opening, svg.content)) continue;
    add({
      id: "a11y-svg-image-name",
      title: "SVG exposed as an image has no accessible name",
      category: "Accessibility",
      severity: "high",
      description: "An SVG with image semantics must expose the graphic's purpose to people who cannot see it.",
      evidence: compact(svg.raw, 180),
      file: file.relative,
      line: lineAt(text, svg.index),
      recommendation: "Add a concise `<title>` referenced by `aria-labelledby`, or an `aria-label`; remove `role=\"img\"` and hide it only when decorative.",
      suggestedFiles: [file.relative],
      tags: ["wcag", "svg", "images", "screen-reader"],
      standards: [{
        id: "WCAG-1.1.1",
        title: "WCAG 2.2 — Non-text Content",
        url: "https://www.w3.org/WAI/WCAG22/Understanding/non-text-content.html",
      }],
    });
  }

  const labels = new Set();
  for (const label of pairedTags(text, "label")) {
    const opening = `<label${label.attributes}>`;
    const target = attributeValue(opening, "for") ?? attributeValue(opening, "htmlFor");
    if (target && contentHasAccessibleText(label.content)) labels.add(target.replace(/["'`]/g, "").trim());
  }
  const nativeControls = [...tags(text, "input"), ...tags(text, "select"), ...tags(text, "textarea")]
    .filter(({ raw }) => {
      const name = /^<([a-z][\w:-]*)\b/i.exec(raw)?.[1]?.toLowerCase();
      return name && isNativeElementTag(file, raw, name);
    });
  for (const input of nativeControls) {
    const type = normalizedAttributeToken(input.raw, "type", "text");
    if (["hidden", "submit", "reset", "button", "image"].includes(type)) continue;
    // A source-only audit cannot prove that a JSX prop spread omits id/ARIA
    // relationships. Statically hidden controls are not exposed in the
    // accessibility tree and are commonly activated by a named button.
    if (hasJsxAttributeSpread(input.raw) || isStaticallyHiddenControl(input.raw)) continue;
    const id = attributeValue(input.raw, "id");
    const named = hasMeaningfulAttribute(input.raw, "aria-label")
      || hasMeaningfulAttribute(input.raw, "aria-labelledby")
      || (id && labels.has(id.replace(/["'`]/g, "").trim()))
      || isInsideMeaningfulLabel(text, input.index)
      || isInsideLabeledFormField(text, input.index);
    if (!named) {
      add({
        id: "a11y-form-label",
        title: "Form control has no programmatic label",
        category: "Forms & validation",
        severity: "high",
        description: "Placeholders and visual proximity do not provide a persistent accessible name.",
        evidence: input.raw,
        file: file.relative,
        line: lineAt(text, input.index),
        recommendation: "Associate a visible `<label>` using `for`/`id`, or provide an accurate accessible label when a visible label is unsuitable.",
        suggestedFiles: [file.relative],
        tags: ["forms", "screen-reader", "usability"],
      });
    }

    if (/^<input\b/i.test(input.raw)) {
      const purpose = autocompletePurpose(input.raw);
      if (purpose && !hasValidAutocompletePurpose(input.raw, purpose)) {
        add({
          id: "forms-missing-autocomplete",
          title: "Personal-data field has no autocomplete purpose",
          category: "Forms & validation",
          severity: "low",
          description: "A programmatic input purpose reduces typing effort and helps people with cognitive, motor, and memory-related disabilities complete forms.",
          evidence: input.raw,
          file: file.relative,
          line: lineAt(text, input.index),
          recommendation: `Add an appropriate autocomplete token, such as ${purpose.suggestion}; do not infer or prefill sensitive values without user intent.`,
          suggestedFiles: [file.relative],
          tags: ["forms", "autocomplete", "usability", "wcag"],
        });
      }
    }
  }

  const formTags = pairedTags(text, "form").filter((form) => isNativeElementTag(file, form.raw, "form"));
  for (const form of formTags) {
    const contentOffset = form.index + form.raw.indexOf(">") + 1;
    for (const button of pairedTags(form.content, "button")) {
      if (!isNativeElementTag(file, button.raw, "button")) continue;
      if (hasMeaningfulAttribute(`<button${button.attributes}>`, "type")) continue;
      add({
        id: "forms-implicit-button-type",
        title: "Button inside a form relies on the implicit submit type",
        category: "Forms & validation",
        severity: "low",
        description: "A button without an explicit type submits its containing form by default, which can trigger accidental submissions after UI refactors.",
        evidence: compact(button.raw),
        file: file.relative,
        line: lineAt(text, contentOffset + button.index),
        recommendation: "Set `type=\"submit\"` for the intended primary submit action and `type=\"button\"` for every non-submit action.",
        suggestedFiles: [file.relative],
        tags: ["forms", "error-prevention", "interaction", "usability"],
      });
    }

    const userInputs = tags(form.content, "input").filter(({ raw }) => {
      if (!isNativeElementTag(file, raw, "input") || hasJsxAttributeSpread(raw) || isStaticallyHiddenControl(raw)) return false;
      const type = normalizedAttributeToken(raw, "type", "text");
      return !["hidden", "submit", "reset", "button", "image"].includes(type);
    });
    if (userInputs.length === 0) continue;
    const validationSignal = /\b(?:required|minlength|maxlength|min|max|pattern)\b|\b(?:validate|validation|validator|schema|zod|yup|valibot|joi|safeParse)\b/i.test(form.raw);
    if (!validationSignal) {
      add({
        id: "forms-no-validation-signal",
        title: "Form has no detectable input-validation contract",
        category: "Forms & validation",
        severity: "low",
        confidence: "medium",
        manual: true,
        description: "Input constraints and matching server validation prevent confusing submissions and unsafe assumptions.",
        evidence: compact(form.raw),
        file: file.relative,
        line: lineAt(text, form.index),
        recommendation: "Define field constraints, validate again on the server, preserve entered values, and show specific recovery guidance beside the affected fields.",
        suggestedFiles: [file.relative],
        tags: ["input-validation", "error-handling", "usability"],
      });
    }
    const requiredInputs = userInputs.some(({ raw }) => hasAttribute(raw, "required") || hasAttribute(raw, "aria-required"));
    const errorFeedback = /\b(?:aria-describedby|aria-errormessage|aria-invalid|role\s*=\s*["']alert|aria-live|field.?error|error.?message)\b/i.test(form.raw);
    if (requiredInputs && !errorFeedback) {
      add({
        id: "forms-no-error-feedback-signal",
        title: "Required form fields have no detectable accessible error feedback",
        category: "Forms & validation",
        severity: "medium",
        confidence: "medium",
        manual: true,
        description: "Validation failures should identify the affected field, explain the correction, and be announced without discarding input.",
        evidence: compact(form.raw),
        file: file.relative,
        line: lineAt(text, form.index),
        recommendation: "Connect inline errors with `aria-describedby`/`aria-errormessage`, set invalid state, summarize on submit when useful, and focus the first invalid control.",
        suggestedFiles: [file.relative],
        tags: ["input-validation", "error-states", "screen-reader", "feedback"],
      });
    }
  }

  const positiveTabIndex = matchAt(text, /\btabIndex\s*=\s*(?:["']?[1-9]\d*["']?|\{\s*[1-9]\d*\s*\})|\btabindex\s*=\s*["']?[1-9]\d*/i);
  if (positiveTabIndex) {
    add({
      id: "a11y-positive-tabindex",
      title: "Positive tabindex overrides the natural keyboard order",
      category: "Accessibility",
      severity: "medium",
      description: "A manually numbered focus order easily diverges from the visual and reading order.",
      evidence: positiveTabIndex.match[0],
      file: file.relative,
      line: lineAt(text, positiveTabIndex.index),
      recommendation: "Use semantic source order and `tabindex=\"0\"` only when a custom control must join the normal tab sequence.",
      suggestedFiles: [file.relative],
      tags: ["keyboard", "focus", "user-flow"],
    });
  }

  const clickOnly = matchAt(text, /<(?:div|span|li|p)\b(?=[^>]*\b(?:onClick|onclick)\s*=)(?![^>]*\brole\s*=)(?![^>]*\btabIndex\s*=)[^>]*>/i);
  if (clickOnly) {
    add({
      id: "a11y-clickable-noncontrol",
      title: "Pointer-only element is used as a control",
      category: "Interaction design",
      severity: "high",
      description: "A clickable non-interactive element is not keyboard-operable or announced as a control by default.",
      evidence: clickOnly.match[0],
      file: file.relative,
      line: lineAt(text, clickOnly.index),
      recommendation: "Use a native `<button>` or `<a>`; if unavoidable, implement correct role, focus, Enter/Space behavior, and state semantics.",
      suggestedFiles: [file.relative],
      tags: ["keyboard", "affordance", "semantic-html"],
    });
  }

  for (const hidden of openingTags(text).filter(({ raw }) => hasLiteralTrueAttribute(raw, "aria-hidden"))) {
    if (!isFocusableMarkup(hidden.raw)) continue;
    add({
      id: "a11y-focusable-aria-hidden",
      title: "Focusable element is hidden from assistive technology",
      category: "Accessibility",
      severity: "high",
      description: "Keyboard focus can land on an element that screen-reader users cannot identify because `aria-hidden=\"true\"` removes it from the accessibility tree.",
      evidence: hidden.raw,
      file: file.relative,
      line: lineAt(text, hidden.index),
      recommendation: "Remove `aria-hidden` from interactive content, or remove/disable every focus path while the region is hidden; prefer the `inert` attribute for inactive UI subtrees.",
      suggestedFiles: [file.relative],
      tags: ["screen-reader", "keyboard", "focus", "aria"],
    });
  }

  const markupTokens = markupTagTokens(text);
  for (let tokenIndex = 0; tokenIndex < markupTokens.length; tokenIndex += 1) {
    const opening = markupTokens[tokenIndex];
    if (opening.closing || opening.selfClosing || !hasLiteralTrueAttribute(opening.raw, "aria-hidden")) continue;
    if (isFocusableMarkup(opening.raw)) continue;

    let depth = 1;
    let closing = null;
    for (let cursor = tokenIndex + 1; cursor < markupTokens.length; cursor += 1) {
      const candidate = markupTokens[cursor];
      if (candidate.name.toLowerCase() !== opening.name.toLowerCase()) continue;
      if (candidate.closing) depth -= 1;
      else if (!candidate.selfClosing) depth += 1;
      if (depth === 0) {
        closing = candidate;
        break;
      }
    }
    if (!closing) continue;
    const content = text.slice(opening.end, closing.index);
    const focusable = openingTags(content).find(({ raw: candidate }) => isFocusableMarkup(candidate));
    if (!focusable) continue;
    const absoluteIndex = opening.end + focusable.index;
    add({
      id: "a11y-focusable-aria-hidden",
      title: "ARIA-hidden region contains focusable content",
      category: "Accessibility",
      severity: "high",
      description: "A hidden accessibility subtree must not contain controls that remain reachable in the keyboard focus order.",
      evidence: compact(`${opening.raw} … ${focusable.raw}`),
      file: file.relative,
      line: lineAt(text, absoluteIndex),
      recommendation: "When the region is hidden, disable or remove its controls from focus as well. Prefer `inert` for inactive drawers, dialogs, and menus, then restore focus deliberately when reopened.",
      suggestedFiles: [file.relative],
      tags: ["screen-reader", "keyboard", "focus", "aria"],
    });
  }

  const duplicateIds = new Map();
  for (const tag of text.matchAll(/<[a-z][^>]*\bid\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
    const id = tag[1];
    if (duplicateIds.has(id)) {
      add({
        id: "a11y-duplicate-id",
        title: "Duplicate HTML id can break labels and ARIA references",
        category: "Accessibility",
        severity: "medium",
        description: "IDs must be unique within a rendered document for fragment links and accessibility relationships to resolve reliably.",
        evidence: tag[0],
        file: file.relative,
        line: lineAt(text, tag.index ?? 0),
        recommendation: `Give \`${id}\` a unique value, especially when this markup is rendered from a repeated component.`,
        suggestedFiles: [file.relative],
        tags: ["screen-reader", "forms", "semantic-html"],
      });
      break;
    }
    duplicateIds.set(id, tag.index ?? 0);
  }

  for (const video of pairedTags(text, "video")) {
    if (!isNativeElementTag(file, video.raw, "video")) continue;
    if (!/<track\b[^>]*kind\s*=\s*["']captions["']/i.test(video.content)) {
      add({
        id: "a11y-video-captions",
        title: "Video has no discoverable captions track",
        category: "Accessibility",
        severity: "medium",
        confidence: "medium",
        description: "Spoken information in video needs synchronized captions for deaf and hard-of-hearing users.",
        evidence: compact(video.raw),
        file: file.relative,
        line: lineAt(text, video.index),
        recommendation: "Provide accurate captions and reference them with `<track kind=\"captions\">`; verify any custom player exposes them.",
        suggestedFiles: [file.relative],
        tags: ["media", "captions", "wcag"],
      });
    }
  }

  if (isPageLike(file, text, deploymentRoots) && !isApplicationMountShell(file, text)) {
    const headings = [...text.matchAll(/<h([1-6])\b[^>]*>/gi)].map((match) => ({ level: Number(match[1]), index: match.index ?? 0, raw: match[0] }));
    const h1s = headings.filter(({ level }) => level === 1);
    const composedHeading = headingContracts.has(normalizedPath(file));
    if (h1s.length === 0 && !composedHeading && !delegatesPrimaryHeading(file, text)) {
      add({
        id: "content-missing-h1",
        title: "Page has no identifiable level-one heading",
        category: "Content hierarchy",
        severity: "medium",
        confidence: "medium",
        description: "A clear primary heading helps users, assistive technology, search engines, and answer engines understand the page topic.",
        evidence: "No `<h1>` was found in this page-like source file.",
        file: file.relative,
        line: 1,
        recommendation: "Add one descriptive visible `<h1>`, or verify the route's composed layout supplies one at runtime.",
        suggestedFiles: [file.relative],
        tags: ["seo", "aeo", "screen-reader", "visual-hierarchy"],
      });
    }
    if (isHtmlDocument(file) && h1s.length > 1) {
      add({
        id: "content-multiple-h1",
        title: "Static document has multiple level-one headings",
        category: "Content hierarchy",
        severity: "low",
        confidence: "medium",
        manual: true,
        description: "Multiple `<h1>` elements can be valid, but each page still needs one unambiguous primary topic and a coherent outline.",
        evidence: `${h1s.length} <h1> elements were found; review starts at ${compact(h1s[1].raw)}.`,
        file: file.relative,
        line: lineAt(text, h1s[1].index),
        recommendation: "Confirm the outline in the rendered page. Prefer one descriptive primary `<h1>` unless multiple top-level sections are intentional and clearly structured.",
        suggestedFiles: [file.relative],
        tags: ["seo", "aeo", "screen-reader", "visual-hierarchy"],
      });
    }

    for (let level = 1; level <= 6; level += 1) {
      for (const heading of pairedTags(text, `h${level}`)) {
        const componentContent = /<[A-Z][\w.$:-]*(?:\s|\/?>)/.test(heading.content);
        if (hasAccessibleName(`<h${level}${heading.attributes}>`, heading.content) || componentContent) continue;
        add({
          id: "content-empty-heading",
          title: "Heading has no readable content",
          category: "Content hierarchy",
          severity: "medium",
          description: "An empty heading creates a meaningless outline stop for screen-reader users and provides no scannable visual hierarchy.",
          evidence: compact(heading.raw),
          file: file.relative,
          line: lineAt(text, heading.index),
          recommendation: "Remove the heading if it is decorative, or give it concise visible text that describes the section that follows.",
          suggestedFiles: [file.relative],
          tags: ["screen-reader", "semantic-html", "readability", "content-hierarchy"],
        });
      }
    }
    const jump = headings.find((heading, index) => index > 0 && heading.level > headings[index - 1].level + 1);
    if (jump) {
      add({
        id: "content-heading-jump",
        title: "Heading hierarchy skips a level",
        category: "Content hierarchy",
        severity: "low",
        description: "Skipped levels can make the page outline harder to scan and navigate with assistive technology.",
        evidence: jump.raw,
        file: file.relative,
        line: lineAt(text, jump.index),
        recommendation: "Organize headings as a meaningful nested outline; do not choose heading levels only for their visual size.",
        suggestedFiles: [file.relative],
        tags: ["readability", "scannability", "screen-reader"],
      });
    }
  }

  const insecureUrl = matchAt(text, /(?:href|src|action)\s*=\s*["']http:\/\/(?!localhost\b|127\.0\.0\.1\b)[^"']+/i);
  if (insecureUrl) {
    add({
      id: "security-insecure-resource",
      title: "Production resource uses an insecure HTTP URL",
      category: "Security & privacy",
      severity: "high",
      description: "HTTP resources can be intercepted and may be blocked as mixed content on an HTTPS page.",
      evidence: insecureUrl.match[0],
      file: file.relative,
      line: lineAt(text, insecureUrl.index),
      recommendation: "Use HTTPS for the destination, or serve the resource from a trusted same-origin path.",
      suggestedFiles: [file.relative],
      tags: ["mixed-content", "privacy", "trust"],
    });
  }

  const passwordGetForm = matchAt(text, /<form\b(?![^>]*\bmethod\s*=\s*["']post["'])[^>]*>(?:(?!<\/form\s*>)[\s\S]){0,5000}<input\b[^>]*\btype\s*=\s*["']password["']/i);
  if (passwordGetForm) {
    add({
      id: "privacy-password-get-form",
      title: "Password form may submit sensitive data with GET",
      category: "Security & privacy",
      severity: "high",
      description: "GET form values can appear in URLs, browser history, logs, analytics, and referrer headers.",
      evidence: compact(passwordGetForm.match[0]),
      file: file.relative,
      line: lineAt(text, passwordGetForm.index),
      recommendation: "Submit credential forms with POST over HTTPS and keep secrets out of query strings.",
      suggestedFiles: [file.relative],
      tags: ["forms", "credentials", "privacy"],
    });
  }
}

function auditSource(context, add, project = {}) {
  const { file, text } = context;
  if (file.size > 350_000 && (isSourceFile(file) || isStyleFile(file))) {
    add({
      id: "performance-large-source-file",
      title: "Large source asset deserves a payload review",
      category: "Performance",
      severity: "medium",
      confidence: "medium",
      description: "A very large source or stylesheet can indicate generated data, a monolithic bundle, or missed code splitting.",
      evidence: `${file.relative} is ${Math.round(file.size / 1024)} KiB.`,
      file: file.relative,
      line: 1,
      recommendation: "Inspect the production bundle, remove unused code/data, and split route-level or interaction-only features when practical.",
      suggestedFiles: [file.relative],
      tags: ["page-speed", "code-splitting", "performance-budget"],
    });
  }

  const browserGlobal = matchAt(text, /\b(?:window|document|navigator|localStorage|sessionStorage)\b/);
  const relative = normalizedPath(file);
  const viteClientApiModule = /(?:^|\/)src\/api(?:\/|$)/.test(relative)
    && (project.signals ?? []).includes("tooling:vite")
    && !["next.js", "nuxt", "sveltekit", "remix", "astro"].includes(String(project.framework ?? "").toLowerCase());
  const serverNamedPath = /(^|\/)(?:server|api|ssr|middleware)(?:\/|\.)/i.test(relative);
  if (browserGlobal && serverNamedPath && !viteClientApiModule
    && !/typeof\s+(?:window|document)\s*!==?\s*["']undefined["']/i.test(text)) {
    add({
      id: "compat-browser-global-on-server",
      title: "Browser-only global may execute during server rendering",
      category: "Cross-platform compatibility",
      severity: "medium",
      confidence: "medium",
      description: "Unprotected browser globals can fail during SSR, prerendering, tests, or edge/server execution.",
      evidence: browserGlobal.match[0],
      file: file.relative,
      line: lineAt(text, browserGlobal.index),
      recommendation: "Move the access into a client lifecycle or guard it with a runtime capability check.",
      suggestedFiles: [file.relative],
      tags: ["ssr", "cross-platform", "error-handling"],
    });
  }

  const destructiveStorage = matchAt(text, /\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'](?:token|accessToken|refreshToken|password|secret|jwt)/i);
  if (destructiveStorage) {
    add({
      id: "privacy-sensitive-browser-storage",
      title: "Sensitive credential appears to be stored in Web Storage",
      category: "Security & privacy",
      severity: "high",
      confidence: "medium",
      description: "Web Storage is readable by any script executing in the origin and increases the impact of cross-site scripting.",
      evidence: destructiveStorage.match[0],
      file: file.relative,
      line: lineAt(text, destructiveStorage.index),
      recommendation: "Prefer secure, HttpOnly, SameSite cookies for session credentials and minimize browser-side secret lifetime.",
      suggestedFiles: [file.relative],
      tags: ["authentication", "privacy", "xss"],
    });
  }

  const frameworkNoIndex = matchAt(text, /\brobots\s*:\s*\{[\s\S]{0,300}?\b(?:index\s*:\s*false|noindex\s*:\s*true)/i);
  if (frameworkNoIndex) {
    add({
      id: "seo-page-noindex",
      title: "Framework metadata appears to exclude a route from search indexes",
      category: "SEO",
      severity: "medium",
      confidence: "medium",
      description: "A noindex policy removes the route from conventional search and can reduce answer-engine discoverability.",
      evidence: frameworkNoIndex.match[0],
      file: file.relative,
      line: lineAt(text, frameworkNoIndex.index),
      recommendation: "Confirm this route should be private or temporary; otherwise enable indexing in production metadata.",
      suggestedFiles: [file.relative],
      tags: ["seo", "geo", "aeo", "indexability"],
    });
  }

  const headerNoIndex = matchAt(text, /["'`]x-robots-tag["'`]\s*[:=,]\s*["'`][^"'`\r\n]*\bnoindex\b/i);
  if (headerNoIndex) {
    add({
      id: "seo-page-noindex",
      title: "Response-header configuration appears to exclude content from indexing",
      category: "SEO",
      severity: "medium",
      confidence: "medium",
      manual: true,
      description: "An X-Robots-Tag noindex policy can remove every response in its configured scope from conventional search and answer-engine discovery.",
      evidence: headerNoIndex.match[0],
      file: file.relative,
      line: lineAt(text, headerNoIndex.index),
      recommendation: "Confirm the header is scoped only to intentionally private, duplicate, or non-public responses; remove it from indexable production routes.",
      suggestedFiles: [file.relative],
      tags: ["seo", "headers", "noindex", "indexability"],
    });
  }

  const hugeComponent = containsMarkup(file, text) && text.split(/\r?\n/).length > 800;
  if (hugeComponent) {
    add({
      id: "design-large-component",
      title: "Large UI file may hide reusable components and states",
      category: "Design system",
      severity: "low",
      confidence: "medium",
      description: "Very large page components are harder to keep consistent across loading, error, empty, and responsive states.",
      evidence: `${file.relative} contains ${text.split(/\r?\n/).length} lines.`,
      file: file.relative,
      line: 1,
      recommendation: "Review repeated interface regions and extract cohesive components backed by shared tokens and explicit state variants.",
      suggestedFiles: [file.relative],
      tags: ["component-reusability", "consistency", "states"],
    });
  }
}

function addManualReviews(add, entryFiles, signals, options) {
  if (options.includeManualReviews === false) return;
  const common = {
    severity: "info",
    manual: true,
    confidence: "medium",
    file: entryFiles[0] ?? null,
    line: entryFiles.length > 0 ? 1 : null,
    suggestedFiles: entryFiles,
  };

  add({
    ...common,
    id: "manual-visual-ux-review",
    title: "Manual review: visual hierarchy, consistency, and interaction quality",
    category: "UI & UX",
    description: "Static source cannot determine whether the rendered interface feels coherent or directs attention effectively.",
    evidence: "Requires rendered desktop/mobile review and representative user tasks.",
    recommendation: "Review typography, color and contrast, whitespace, alignment, grid, balance, CTA prominence, affordances, feedback, microinteractions, readability, and scannability in real rendered states.",
    tags: ["visual-hierarchy", "consistency", "cta", "usability"],
  }, 1);

  add({
    ...common,
    id: "manual-user-flow-review",
    title: "Manual review: navigation, information architecture, and product flows",
    category: "User experience",
    description: "Code structure alone does not prove that people can understand and complete their intended journeys.",
    evidence: "Requires task-based usability review with production-like content.",
    recommendation: "Walk critical flows end to end, including navigation, onboarding, progressive disclosure, search, filtering/sorting, personalization, forms, input validation, recovery, and user-feedback paths where applicable.",
    tags: ["user-flow", "information-architecture", "onboarding", "search"],
  }, 1);

  add({
    ...common,
    id: "manual-responsive-a11y-review",
    title: "Manual review: responsive, keyboard, screen-reader, and touch behavior",
    category: "Accessibility & responsive design",
    description: "Source heuristics cannot verify focus order, announcements, reflow, target spacing, gestures, or assistive-technology behavior.",
    evidence: "Requires browser and device testing at zoomed, narrow, touch, keyboard-only, and screen-reader configurations.",
    recommendation: "Test supported breakpoints and orientation changes, 200–400% zoom, touch targets, keyboard navigation, focus management, landmark/headings output, names/roles/states, and common screen readers.",
    tags: ["wcag", "keyboard", "screen-reader", "touch-targets", "breakpoints"],
  }, 1);

  add({
    ...common,
    id: "manual-cwv-browser-review",
    title: "Manual review: field performance and browser/platform compatibility",
    category: "Performance & compatibility",
    description: "Core Web Vitals and compatibility depend on production bundles, networks, devices, browsers, runtime data, and third parties.",
    evidence: "Requires a production build plus lab and real-user measurements.",
    recommendation: "Measure LCP, INP, and CLS on key routes; set page-speed budgets; then test the declared browser/device matrix, reduced motion, high contrast, slow networks, and failure/loading/empty states.",
    tags: ["core-web-vitals", "page-speed", "cross-browser", "cross-platform"],
  }, 1);

  add({
    ...common,
    id: "manual-discoverability-review",
    title: "Manual review: SEO, GEO, AEO, and AIO content quality",
    category: "Discoverability",
    description: "Markup signals help discovery, but automated checks cannot judge expertise, answer quality, factual support, or whether structured data matches visible content.",
    evidence: [
      signals.structuredData
        ? "Structured-data syntax was detected; its eligibility and factual match still require validation."
        : "No structured-data syntax was detected.",
      signals.markdownContent
        ? `Markdown content was inspected; ${signals.answerStructure ? "question/answer heading structure was detected" : "no explicit question/answer heading structure was detected"}.`
        : null,
      signals.markdownContent
        ? (signals.authorOrSources ? "Author/source signals were detected." : "No explicit author/source signal was detected in Markdown content.")
        : null,
      "Content quality requires human review.",
    ].filter(Boolean).join(" "),
    recommendation: "Validate crawlable canonical pages, entity clarity, answer-first headings, concise direct answers, author/source credibility, internal links, fresh factual evidence, and schema that exactly matches visible content.",
    tags: ["seo", "geo", "aeo", "aio", "structured-data"],
  }, 1);

  add({
    ...common,
    id: "manual-conversion-measurement-review",
    title: "Manual review: conversion, analytics, experimentation, privacy, and trust",
    category: "Conversion & trust",
    description: "The correct CTA, analytics events, A/B-test guardrails, and consent model depend on business intent and jurisdiction.",
    evidence: signals.analytics
      ? "Analytics or telemetry code was detected; event quality and lawful consent still require review."
      : "No recognizable analytics provider was detected; measurement may be absent, server-side, or intentionally omitted.",
    recommendation: "Define primary conversions and event semantics, validate analytics, document A/B hypotheses and guardrails, minimize collected data, honor consent/withdrawal, and verify visible privacy, contact, ownership, and security assurances.",
    tags: ["conversion", "analytics", "a-b-testing", "privacy", "credibility"],
  }, 1);
}

export async function runSiteScan({ root = process.cwd(), files = [], skipped = {}, onProgress, options = {} } = {}) {
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

  // Nested public/static assets must be admitted for production workspaces, but
  // fixture/example package trees remain excluded by the production-scope gate.
  const candidateDeploymentRoots = new Set([""]);
  for (const file of inputFiles) {
    if (excludedFromProductionScope(file, options)) continue;
    const relative = normalizedPath(file);
    if (path.posix.basename(relative) !== "package.json") continue;
    const directory = path.posix.dirname(relative);
    candidateDeploymentRoots.add(directory === "." ? "" : directory);
  }

  const contexts = [];
  const assetSnapshots = [];
  let unreadable = 0;
  let productionCandidates = 0;
  let excludedNonProduction = 0;
  let excludedNonSite = 0;
  let excludedGenerated = 0;
  for (let index = 0; index < inputFiles.length; index += 1) {
    const file = inputFiles[index];
    const outsideProductionScope = excludedFromProductionScope(file, options);
    const assetMetadata = isWebAssetFile(file);
    const auditable = assetMetadata || isAuditableSiteFile(file, candidateDeploymentRoots);
    if (typeof onProgress === "function") {
      await Promise.resolve(onProgress({
        phase: "Website audit",
        current: index + 1,
        total: inputFiles.length,
        file: file.relative,
        check: outsideProductionScope || !auditable
          ? "excluded from production scope"
          : (assetMetadata ? "asset metadata validation" : "static analysis"),
      }));
    }
    if (outsideProductionScope) {
      excludedNonProduction += 1;
      continue;
    }
    if (!auditable) {
      excludedNonSite += 1;
      continue;
    }
    productionCandidates += 1;
    if (assetMetadata) {
      const snapshot = await verifyFileMetadata(file, { root });
      if (!snapshot) unreadable += 1;
      else assetSnapshots.push(snapshot);
      continue;
    }
    const text = await readTextFile(file, { root });
    if (text === null) {
      unreadable += 1;
      continue;
    }
    if (options.includeGenerated !== true
      && path.posix.basename(normalizedPath(file)) !== "package.json"
      && hasGeneratedHeader(text)) {
      excludedGenerated += 1;
      continue;
    }
    contexts.push({ file, text: maskIgnoredComments(file, text) });
  }

  const { add, findings, findingIndex, maxFindingsPerRule, suppressedByRule, suppressedSeverityByRule } = createCollector(options);
  const deliveredAssets = assetSnapshots.filter((asset) =>
    likelyDeliveredAsset(asset, contexts, candidateDeploymentRoots));
  for (const asset of deliveredAssets) auditAsset(asset, add);
  const entryFiles = [...new Set([
    ...frameworkSuggestions(project.framework, contexts),
    ...recommendedEntryFiles(contexts, candidateDeploymentRoots),
  ])].slice(0, 6);
  const htmlContexts = contexts.filter(({ file, text }) => isConcreteHtmlDocument(file, text, candidateDeploymentRoots));
  const htmlFragmentContexts = contexts.filter(({ file, text }) => isHtmlDocument(file)
    && !isConcreteHtmlDocument(file, text, candidateDeploymentRoots));
  const markdownContexts = contexts.filter(({ file }) => isMarkdownContentPage(file, candidateDeploymentRoots));
  const markdownAnalyses = new Map(markdownContexts.map((context) => [context, analyzeMarkdown(context.text)]));
  const pageContexts = contexts.filter(({ file, text }) => isPageLike(file, text, candidateDeploymentRoots)
    && !isApplicationMountShell(file, text));
  const interfacePageContexts = pageContexts.filter(({ file }) => !isMarkdownDocument(file));
  const hasPageSurface = htmlContexts.length > 0 || pageContexts.length > 0;
  const markupContexts = contexts.filter(({ file, text }) => containsMarkup(file, text));
  const styleContexts = contexts.filter(({ file }) => isStyleFile(file));
  const headingContracts = primaryHeadingContracts(contexts);
  const linkIsolationContracts = externalLinkIsolationContracts(contexts);

  const manifestRecords = [];
  const manifestContexts = contexts.filter(({ file }) => path.posix.basename(normalizedPath(file)) === "package.json");
  for (const manifestContext of manifestContexts) {
    try {
      const manifest = JSON.parse(manifestContext.text);
      if (manifest && typeof manifest === "object" && !Array.isArray(manifest)) {
        manifestRecords.push({ manifest, relative: normalizedPath(manifestContext.file) });
      }
    } catch {
      add({
        id: "project-invalid-package-json",
        title: "package.json cannot be parsed",
        category: "Reliability",
        severity: "high",
        description: "Invalid project metadata can break builds, dependency auditing, and reproducible deployment.",
        evidence: "JSON parsing failed.",
        file: manifestContext.file.relative,
        line: 1,
        recommendation: "Correct the JSON syntax and run the package manager's validation/install command.",
        suggestedFiles: [manifestContext.file.relative],
        tags: ["build", "error-handling"],
      }, 1);
    }
  }
  const dependencies = new Set(manifestRecords.flatMap(({ manifest: packageManifest }) =>
    [...dependencyNames(packageManifest)]));
  const productionPaths = inputFiles
    .filter((file) => !excludedFromProductionScope(file, options))
    .map((file) => normalizedPath(file));
  const deploymentRoots = new Set([""]);
  const manifestLooksLikeWebApp = ({ manifest: packageManifest, relative }) => {
    const packageDependencies = dependencyNames(packageManifest);
    const hasWebDependency = [...packageDependencies].some((name) => WEB_APP_LIBRARIES.has(name) || name === "vite");
    const scriptText = Object.values(packageManifest.scripts ?? {}).filter((value) => typeof value === "string").join("\n");
    const hasWebScript = /\b(?:astro|gatsby|next|nuxt|remix|vite|webpack|parcel|ng\s+(?:serve|build))\b/i.test(scriptText);
    const directory = path.posix.dirname(relative) === "." ? "" : path.posix.dirname(relative);
    const prefix = directory ? `${directory}/` : "";
    const hasNearbyEntry = productionPaths.some((candidate) => {
      if (!candidate.startsWith(prefix)) return false;
      const local = candidate.slice(prefix.length);
      return /^(?:index\.html|(?:src\/)?(?:app|pages|routes)\/|(?:next|nuxt|astro|svelte|vite)\.config\.)/i.test(local);
    });
    return hasWebDependency || hasWebScript || hasNearbyEntry;
  };
  for (const record of manifestRecords) {
    if (!manifestLooksLikeWebApp(record)) continue;
    const directory = path.posix.dirname(record.relative);
    deploymentRoots.add(directory === "." ? "" : directory);
  }

  const signals = {
    analytics: false,
    canonical: false,
    consent: false,
    cssVariables: false,
    description: false,
    errorState: false,
    experimentation: false,
    focusStyles: false,
    legal: false,
    loadingState: false,
    main: false,
    mediaQueries: false,
    motion: false,
    nav: false,
    reducedMotion: false,
    responsiveUtilities: false,
    socialMetadata: false,
    structuredData: false,
    title: false,
    tokensOrTheme: false,
    emptyState: false,
    markdownContent: false,
    answerStructure: false,
    authorOrSources: false,
  };

  const literalTitles = [];
  const literalDescriptions = [];
  for (const context of contexts) {
    const { file, text } = context;
    signals.analytics ||= ANALYTICS_PATTERN.test(text);
    signals.consent ||= CONSENT_PATTERN.test(text);
    signals.legal ||= PRIVACY_PATTERN.test(text);
    signals.experimentation ||= /\b(feature.?flag|experiment|variant|split.?test|a\/b test|optimizely|launchdarkly|growthbook)\b/i.test(text);
    signals.loadingState ||= /(?:^|[/_.-])(loading|skeleton|spinner|pending)(?:[/_.-]|$)|\b(?:isLoading|isPending|aria-busy|Suspense\b|fallback\s*=)/i.test(`${file.relative} ${text}`);
    signals.errorState ||= /(?:^|[/_.-])(error|error-boundary|fallback)(?:[/_.-]|$)|\b(?:ErrorBoundary|onError|role\s*=\s*["']alert|aria-live)\b/i.test(`${file.relative} ${text}`);
    signals.emptyState ||= /\b(empty state|no results|nothing (?:here|found)|sonuç bulunamadı|kayıt bulunamadı)\b|(?:^|[/_.-])empty(?:[/_.-]|$)/i.test(`${file.relative} ${text}`);
    signals.tokensOrTheme ||= /(?:^|\/)(?:tokens?|theme|design-system|ui)(?:[./_-]|\/)|\bcreateTheme\b/i.test(file.relative);

    if (isMarkdownContentPage(file, candidateDeploymentRoots)) {
      const analysis = markdownAnalyses.get(context);
      const markdownTitle = markdownField(analysis, ["title", "seo.title"]);
      const markdownDescription = markdownField(analysis, ["description", "seo.description", "meta.description"]);
      const markdownCanonical = markdownField(analysis, ["canonical", "canonicalurl", "canonical_url", "seo.canonical", "seo.canonicalurl"]);
      const markdownSocial = markdownField(analysis, ["opengraph", "seo.opengraph", "twitter", "seo.twitter", "image", "seo.image"]);
      const markdownStructured = markdownField(analysis, ["schema", "seo.schema", "jsonld", "json-ld", "structureddata", "structured_data"]);
      const markdownAuthor = markdownField(analysis, ["author", "authors", "byline", "source", "sources", "references"]);
      const primaryHeading = analysis.headings.find((heading) => heading.level === 1 && heading.content);

      signals.markdownContent = true;
      signals.title ||= meaningfulMarkdownScalar(markdownTitle);
      signals.description ||= meaningfulMarkdownScalar(markdownDescription);
      signals.canonical ||= meaningfulMarkdownScalar(markdownCanonical);
      signals.socialMetadata ||= meaningfulMarkdownScalar(markdownSocial);
      signals.structuredData ||= meaningfulMarkdownScalar(markdownStructured) || /schema\.org|application\/ld\+json/i.test(analysis.body);
      signals.answerStructure ||= analysis.headings.some(({ content, level }) => level >= 2
        && /(?:\?|^(?:how|what|why|when|where|who|nasıl|nedir|neden|ne zaman|nerede|kim)\b)/i.test(content));
      signals.authorOrSources ||= meaningfulMarkdownScalar(markdownAuthor)
        || /(?:^|\n)#{1,6}\s+(?:sources?|references?|kaynak(?:lar)?)(?:\s|$)/i.test(analysis.body);

      const literalTitle = meaningfulMarkdownScalar(markdownTitle)
        ? markdownScalar(markdownTitle)
        : primaryHeading?.content;
      if (literalTitle) {
        literalTitles.push({
          value: compact(literalTitle, 100).toLowerCase(),
          file,
          index: 0,
          raw: markdownTitle?.raw ?? primaryHeading.raw,
        });
      }
      if (meaningfulMarkdownScalar(markdownDescription)) {
        literalDescriptions.push({
          value: compact(markdownScalar(markdownDescription), 240).toLowerCase(),
          file,
          index: 0,
          raw: markdownDescription.raw,
        });
      }
    }

    if (isSourceFile(file)) {
      signals.title ||= /\b(?:metadata|seo|head)\s*[:=][\s\S]{0,500}\btitle\s*:/i.test(text)
        || /export\s+(?:const|function)\s+(?:metadata|generateMetadata)\b[\s\S]{0,500}\btitle\b/i.test(text);
      signals.description ||= /\b(?:metadata|seo|head)\s*[:=][\s\S]{0,500}\bdescription\s*:/i.test(text);
      signals.canonical ||= /\b(?:alternates|canonical)\s*:/i.test(text);
      signals.socialMetadata ||= /\bopenGraph\s*:|\btwitter\s*:/i.test(text);
      signals.structuredData ||= /application\/ld\+json|schema\.org|\bjsonLd\b|\bstructuredData\b/i.test(text);
      const frameworkMetadata = frameworkMetadataSignals(text);
      if (frameworkMetadata) {
        signals.title ||= frameworkMetadata.title;
        signals.description ||= frameworkMetadata.description;
        signals.canonical ||= frameworkMetadata.canonical;
        signals.socialMetadata ||= frameworkMetadata.socialMetadata;
        signals.structuredData ||= frameworkMetadata.structuredData;
      }
    } else if (file.extension === ".json") {
      signals.structuredData ||= /"@context"\s*:\s*"https?:\/\/schema\.org"|"@type"\s*:/i.test(text);
    }

    if (containsMarkup(file, text)) {
      const documentSurface = htmlDocumentSurface(text);
      signals.title ||= /<title\b[^>]*>|\b(?:metadata|head)\s*[:=][\s\S]{0,400}\btitle\s*:/i.test(documentSurface)
        || /export\s+(?:const|function)\s+(?:metadata|generateMetadata)\b/i.test(text);
      signals.description ||= /<meta\b(?=[^>]*\bname\s*=\s*["']description["'])[^>]*>/i.test(text)
        || /\bdescription\s*:\s*["'`]/i.test(text);
      signals.canonical ||= /<link\b(?=[^>]*\brel\s*=\s*["']canonical["'])[^>]*>/i.test(text)
        || /\b(?:alternates|canonical)\s*:/i.test(text);
      signals.socialMetadata ||= /(?:property|name)\s*=\s*["'](?:og:|twitter:)/i.test(text)
        || /\bopenGraph\s*:|\btwitter\s*:/i.test(text);
      signals.structuredData ||= /application\/ld\+json|schema\.org|\bjsonLd\b|\bstructuredData\b/i.test(text);
      signals.main ||= /<main\b|\brole\s*=\s*["']main["']/i.test(text);
      signals.nav ||= /<nav\b|\brole\s*=\s*["']navigation["']/i.test(text);
      signals.responsiveUtilities ||= RESPONSIVE_UTILITY_PATTERN.test(text);
      for (const title of documentSurface.matchAll(/<title\b[^>]*>\s*([^<{][^<]*)<\/title\s*>/gi)) {
        literalTitles.push({ value: compact(title[1], 100).toLowerCase(), file, index: title.index ?? 0, raw: title[0] });
      }
      if (isConcreteHtmlDocument(file, text, candidateDeploymentRoots)) {
        const description = tags(text, "meta").find(({ raw }) =>
          (staticAttributeValue(raw, "name") ?? "").toLowerCase() === "description");
        const value = description ? staticAttributeValue(description.raw, "content") : null;
        if (value) {
          literalDescriptions.push({
            value: compact(value, 240).toLowerCase(),
            file,
            index: description.index,
            raw: description.raw,
          });
        }
      }
    }

    if (isStyleFile(file)) {
      signals.cssVariables ||= /--[a-z0-9_-]+\s*:/i.test(text);
      signals.mediaQueries ||= /@(?:media|container)\b/i.test(text);
      signals.motion ||= /@keyframes\b|\banimation(?:-name)?\s*:|\btransition(?:-property)?\s*:/i.test(text);
      signals.reducedMotion ||= /prefers-reduced-motion/i.test(text);
      signals.focusStyles ||= /:focus-visible|:focus\b/i.test(text);
    }
  }

  for (const context of contexts) {
    if (isConcreteHtmlDocument(context.file, context.text, candidateDeploymentRoots)) auditHtmlDocument(context, add);
    if (isMarkdownContentPage(context.file, candidateDeploymentRoots)) auditMarkdown(context, markdownAnalyses.get(context), add);
    if (containsMarkup(context.file, context.text)) {
      auditMarkup(context, add, candidateDeploymentRoots, headingContracts, linkIsolationContracts);
    }
    if (isStyleFile(context.file)) {
      const relative = normalizedPath(context.file);
      const nearestManifest = manifestRecords
        .filter((record) => { const dir = path.posix.dirname(record.relative); return dir === "." || relative.startsWith(`${dir}/`); })
        .sort((a, b) => b.relative.length - a.relative.length)[0];
      const manifest = nearestManifest?.manifest;
      const dependencies = { ...manifest?.dependencies, ...manifest?.devDependencies };
      const sourceStyle = !/(?:^|\/)(?:public|static)\//.test(relative);
      const bundled = sourceStyle && ["vite", "next", "nuxt", "astro", "@sveltejs/kit", "@angular/build", "@angular-devkit/build-angular", "react-scripts"].some((name) => dependencies[name]);
      auditStyles(context, add, bundled);
    }
    if (isSourceFile(context.file) || isStyleFile(context.file)) auditSource(context, add, project);
  }

  const readablePaths = new Set(contexts.map(({ file }) => normalizedPath(file)));
  const robotsInventory = inputFiles.filter((file) => !excludedFromProductionScope(file, options)
    && isDeployableStaticMetadata(file, "robots", deploymentRoots));
  const robotsContexts = contexts.filter(({ file }) => isDeployableStaticMetadata(file, "robots", deploymentRoots));
  const robotsRoutes = inputFiles.filter((file) => !excludedFromProductionScope(file, options)
    && isFrameworkMetadataRoute(file, "robots", deploymentRoots));
  const sitemapInventory = inputFiles.filter((file) => !excludedFromProductionScope(file, options)
    && isDeployableStaticMetadata(file, "sitemap", deploymentRoots));
  const sitemapContexts = contexts.filter(({ file }) => isDeployableStaticMetadata(file, "sitemap", deploymentRoots));
  const sitemapRoutes = inputFiles.filter((file) => !excludedFromProductionScope(file, options)
    && isFrameworkMetadataRoute(file, "sitemap", deploymentRoots));
  const unvalidatedRobots = robotsInventory.filter((file) => !readablePaths.has(normalizedPath(file)));
  const unvalidatedSitemaps = sitemapInventory.filter((file) => !readablePaths.has(normalizedPath(file)));

  for (const file of unvalidatedRobots) {
    add({
      id: "crawl-robots-unvalidated",
      title: "robots.txt is present but its contents were not inspected",
      category: "SEO & crawlability",
      severity: "medium",
      manual: true,
      description: "Presence prevents a false missing-file result, but unreadable crawler rules could still block production indexing.",
      evidence: file.skippedReason === "large"
        ? `${file.relative} is ${Math.ceil(file.size / 1024)} KiB and exceeds the ${Math.ceil((file.maxFileBytes ?? 0) / 1024)} KiB read limit.`
        : `${file.relative} could not be read during this scan.`,
      file: file.relative,
      line: 1,
      recommendation: "Inspect the deployed robots.txt directly, validate its user-agent groups, and rerun Modular with a sufficient file-size limit if repository validation is needed.",
      suggestedFiles: [file.relative],
      tags: ["robots", "coverage", "manual-review"],
    });
  }

  for (const file of unvalidatedSitemaps) {
    add({
      id: "crawl-sitemap-unvalidated",
      title: "XML sitemap is present but its contents were not inspected",
      category: "SEO & crawlability",
      severity: "low",
      manual: true,
      description: "The sitemap exists, but this scan could not verify its XML root, URL format, or production canonical host.",
      evidence: file.skippedReason === "large"
        ? `${file.relative} is ${Math.ceil(file.size / 1024)} KiB and exceeds the ${Math.ceil((file.maxFileBytes ?? 0) / 1024)} KiB read limit.`
        : `${file.relative} could not be read during this scan.`,
      file: file.relative,
      line: 1,
      recommendation: "Validate the sitemap with a streaming/XML-aware tool or split it into a sitemap index, then verify the deployed URL and rerun with a sufficient file-size limit when appropriate.",
      suggestedFiles: [file.relative],
      tags: ["sitemap", "coverage", "manual-review"],
    });
  }

  if (hasPageSurface && robotsInventory.length === 0 && robotsRoutes.length === 0) {
    projectFinding(add, entryFiles, {
      id: "crawl-missing-robots",
      title: "No robots policy was found",
      category: "SEO & crawlability",
      severity: "low",
      description: "A robots policy makes crawler permissions and sitemap discovery explicit.",
      evidence: "No static robots.txt or framework robots route was detected.",
      recommendation: "Add a production robots policy, allow intended public routes, and reference the canonical sitemap URL.",
      suggestedFiles: ["public/robots.txt", "app/robots.ts", ...entryFiles],
      tags: ["robots", "seo", "geo", "aeo"],
    });
  }

  for (const context of robotsContexts) {
    const { file, text } = context;
    if (!/^\s*user-agent\s*:/mi.test(text)) {
      add({
        id: "crawl-invalid-robots",
        title: "robots.txt has no User-agent group",
        category: "SEO & crawlability",
        severity: "medium",
        description: "Crawler directives must belong to a User-agent group to be interpreted consistently.",
        evidence: compact(text.slice(0, 220)),
        file: file.relative,
        line: 1,
        recommendation: "Add a valid `User-agent:` group and test the production file with a robots parser.",
        suggestedFiles: [file.relative],
        tags: ["robots", "seo"],
      }, 1);
    }
    const unsupportedNoindex = matchAt(text, /^\s*noindex\s*:\s*\S.*$/im);
    if (unsupportedNoindex) {
      add({
        id: "crawl-unsupported-noindex",
        title: "robots.txt uses an unsupported Noindex directive",
        category: "SEO & crawlability",
        severity: "medium",
        description: "Major search crawlers do not treat `Noindex:` in robots.txt as a reliable indexing control, and a crawl block can prevent them from seeing page-level noindex metadata.",
        evidence: compact(unsupportedNoindex.match[0], 180),
        file: file.relative,
        line: lineAt(text, unsupportedNoindex.index),
        recommendation: "Remove this directive and return a page-level robots noindex header/meta tag while allowing the crawler to fetch the URL, or require authentication for private content.",
        suggestedFiles: [file.relative],
        tags: ["robots", "noindex", "seo", "indexability"],
        references: ["https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag"],
      }, 1);
    }
    const blockAll = wildcardRobotsBlock(text);
    if (blockAll) {
      add({
        id: "crawl-sitewide-disallow",
        title: "Wildcard crawler policy blocks the site root",
        category: "SEO & crawlability",
        severity: "high",
        description: "A wildcard `Disallow: /` prevents compliant crawlers from accessing the site except for any narrower paths explicitly allowed.",
        evidence: blockAll.raw,
        file: file.relative,
        line: blockAll.line,
        recommendation: "Keep this only for intentionally private/non-production deployments; remove the root block or replace it with narrow private-path rules in production.",
        suggestedFiles: [file.relative],
        tags: ["robots", "indexability", "geo", "aeo"],
      }, 1);
    }
    if (!/^\s*sitemap\s*:/mi.test(text) && (sitemapContexts.length > 0 || sitemapRoutes.length > 0)) {
      add({
        id: "crawl-robots-missing-sitemap",
        title: "robots.txt does not advertise the sitemap",
        category: "SEO & crawlability",
        severity: "low",
        description: "A Sitemap directive helps crawlers discover the canonical sitemap location.",
        evidence: "No `Sitemap:` directive was found.",
        file: file.relative,
        line: 1,
        recommendation: "Add an absolute HTTPS `Sitemap:` URL that matches the production canonical host.",
        suggestedFiles: [file.relative],
        tags: ["robots", "sitemap", "seo"],
      }, 1);
    }
    for (const directive of text.matchAll(/^\s*sitemap\s*:\s*([^#\r\n]*?)(?:\s+#.*)?$/gim)) {
      const value = directive[1].trim();
      const issue = absoluteWebUrlIssue(value);
      if (!issue) continue;
      add({
        id: "crawl-invalid-sitemap-directive",
        title: "robots.txt contains an invalid Sitemap directive",
        category: "SEO & crawlability",
        severity: "medium",
        description: "A Sitemap directive must contain an absolute HTTP(S) URL so crawlers can discover it independently of the robots file location.",
        evidence: `${compact(directive[0], 180)} — ${issue}.`,
        file: file.relative,
        line: lineAt(text, directive.index ?? 0),
        recommendation: "Replace the directive with the sitemap's absolute production HTTPS URL and verify that it returns a successful XML response.",
        suggestedFiles: [file.relative],
        tags: ["robots", "sitemap", "seo", "crawlability"],
        references: ["https://www.sitemaps.org/protocol.html"],
      });
    }
  }

  if (hasPageSurface && sitemapInventory.length === 0 && sitemapRoutes.length === 0) {
    projectFinding(add, entryFiles, {
      id: "crawl-missing-sitemap",
      title: "No XML sitemap implementation was found",
      category: "SEO & crawlability",
      severity: "low",
      description: "A sitemap helps search and answer engines discover canonical, updated public URLs.",
      evidence: "No sitemap.xml or framework sitemap route was detected.",
      recommendation: "Generate an XML sitemap from public canonical routes, include accurate last-modified values, and expose it through robots.txt.",
      suggestedFiles: ["public/sitemap.xml", "app/sitemap.ts", ...entryFiles],
      tags: ["sitemap", "seo", "geo", "aeo"],
    });
  }

  for (const context of sitemapContexts) {
    const xml = context.text.replace(/<!--[\s\S]*?-->/g, blankComment);
    const root = /<(?:[A-Za-z_][\w.-]*:)?(urlset|sitemapindex)\b([^>]*)>/i.exec(xml);
    if (!root) {
      add({
        id: "crawl-invalid-sitemap",
        title: "Sitemap does not contain an XML sitemap root",
        category: "SEO & crawlability",
        severity: "medium",
        description: "Crawlers expect either a `urlset` or `sitemapindex` root element.",
        evidence: compact(context.text.slice(0, 220)),
        file: context.file.relative,
        line: 1,
        recommendation: "Emit valid UTF-8 XML using the sitemap protocol namespace and absolute canonical URLs.",
        suggestedFiles: [context.file.relative],
        tags: ["sitemap", "seo"],
      }, 1);
      continue;
    }

    if (!/\bxmlns(?::[A-Za-z_][\w.-]*)?\s*=\s*["']http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9["']/i.test(root[0])) {
      add({
        id: "crawl-sitemap-namespace",
        title: "Sitemap root is missing the standard namespace",
        category: "SEO & crawlability",
        severity: "low",
        description: "The sitemap protocol namespace makes the document's vocabulary explicit to XML consumers and validators.",
        evidence: compact(root[0], 180),
        file: context.file.relative,
        line: lineAt(xml, root.index ?? 0),
        recommendation: "Add `xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"` to the urlset or sitemapindex root element.",
        suggestedFiles: [context.file.relative],
        tags: ["sitemap", "xml", "seo", "validation"],
        references: ["https://www.sitemaps.org/protocol.html"],
      }, 1);
    }

    const locations = [...xml.matchAll(/<(?:[A-Za-z_][\w.-]*:)?loc\b[^>]*>([\s\S]*?)<\/(?:[A-Za-z_][\w.-]*:)?loc\s*>/gi)];
    if (locations.length === 0) {
      add({
        id: "crawl-empty-sitemap",
        title: "Sitemap contains no URL locations",
        category: "SEO & crawlability",
        severity: "medium",
        description: "A sitemap with no `loc` entries cannot contribute any discoverable page or child-sitemap URLs.",
        evidence: compact(root[0], 180),
        file: context.file.relative,
        line: lineAt(xml, root.index ?? 0),
        recommendation: "Generate at least one canonical public URL, or omit the empty sitemap until indexable routes exist.",
        suggestedFiles: [context.file.relative],
        tags: ["sitemap", "seo", "crawlability"],
      }, 1);
    }

    const seenLocations = new Map();
    for (const location of locations) {
      const value = decodeXmlText(location[1]);
      const issue = absoluteWebUrlIssue(value);
      if (issue) {
        add({
          id: "crawl-invalid-sitemap-location",
          title: "Sitemap contains an invalid production URL",
          category: "SEO & crawlability",
          severity: "medium",
          description: "Sitemap locations must be absolute crawlable HTTP(S) URLs without credentials or fragments.",
          evidence: `${compact(location[0], 180)} — ${issue}.`,
          file: context.file.relative,
          line: lineAt(xml, location.index ?? 0),
          recommendation: "Emit the route's final absolute HTTPS canonical URL and remove fragments, embedded credentials, or unsupported schemes.",
          suggestedFiles: [context.file.relative],
          tags: ["sitemap", "seo", "canonical", "transport-security"],
          references: ["https://www.sitemaps.org/protocol.html"],
        });
        continue;
      }
      const parsedLocation = new URL(value);
      if (parsedLocation.protocol === "http:" && !isLoopbackUrl(parsedLocation)) {
        add({
          id: "crawl-insecure-sitemap-location",
          title: "Sitemap advertises an insecure HTTP URL",
          category: "SEO & transport security",
          severity: "low",
          description: "Advertising an HTTP route can send crawlers and users through an avoidable redirect or expose content in transit.",
          evidence: compact(location[0], 180),
          file: context.file.relative,
          line: lineAt(xml, location.index ?? 0),
          recommendation: "Publish the final HTTPS canonical URL directly in the sitemap and redirect the HTTP origin consistently.",
          suggestedFiles: [context.file.relative],
          tags: ["sitemap", "seo", "https", "transport-security"],
        });
      }
      let normalized = value;
      try {
        normalized = new URL(value).href;
      } catch {
        // The validation finding above already owns malformed values.
      }
      if (seenLocations.has(normalized)) {
        add({
          id: "crawl-duplicate-sitemap-location",
          title: "Sitemap repeats the same URL",
          category: "SEO & crawlability",
          severity: "low",
          description: "Duplicate sitemap locations add crawl noise and often indicate route-normalization or generation defects.",
          evidence: compact(location[0], 180),
          file: context.file.relative,
          line: lineAt(xml, location.index ?? 0),
          recommendation: "Deduplicate generated locations by their final canonical URL before writing the sitemap.",
          suggestedFiles: [context.file.relative],
          tags: ["sitemap", "seo", "canonical", "crawl-budget"],
        }, 1);
      } else {
        seenLocations.set(normalized, location.index ?? 0);
      }
    }
  }

  if (hasPageSurface && !signals.title && htmlContexts.length === 0) {
    projectFinding(add, entryFiles, {
      id: "seo-missing-title",
      title: "No page-title implementation was detected",
      category: "SEO",
      severity: "high",
      description: "Unique, descriptive titles are central to browser orientation, search results, sharing, and assistive technology.",
      evidence: "No HTML title or recognizable framework metadata title was found.",
      recommendation: "Provide a concise, unique title for every indexable route using the framework's supported metadata API.",
      tags: ["seo", "accessibility", "content-hierarchy"],
    });
  }
  if (hasPageSurface && !signals.description && htmlContexts.length === 0) {
    projectFinding(add, entryFiles, {
      id: "seo-missing-description",
      title: "No meta-description implementation was detected",
      category: "SEO",
      severity: "medium",
      description: "A useful route-specific description helps people understand relevance before visiting.",
      evidence: "No description meta tag or recognizable framework metadata description was found.",
      recommendation: "Add a truthful, route-specific description that summarizes the page's value without duplicating every page.",
      tags: ["seo", "conversion", "scannability"],
    });
  }
  if (hasPageSurface && !signals.canonical && htmlContexts.length === 0) {
    projectFinding(add, entryFiles, {
      id: "seo-missing-canonical",
      title: "No canonical URL strategy was detected",
      category: "SEO",
      severity: "low",
      confidence: "medium",
      description: "Canonical URLs help consolidate equivalent URL variants and clarify the preferred source.",
      evidence: "No canonical link or recognizable framework canonical metadata was found.",
      recommendation: "Emit an absolute self-referencing canonical URL for each indexable route and normalize tracking/duplicate variants.",
      tags: ["seo", "duplicate-content", "trust"],
    });
  }
  if (hasPageSurface && !signals.socialMetadata && htmlContexts.length === 0) {
    projectFinding(add, entryFiles, {
      id: "seo-missing-social-metadata",
      title: "No social sharing metadata was detected",
      category: "Discoverability",
      severity: "low",
      description: "Open Graph and social-card metadata improve link previews and recognition when pages are shared.",
      evidence: "No Open Graph or Twitter/X card metadata was found.",
      recommendation: "Add route-appropriate Open Graph title, description, canonical URL, image, and card metadata with valid absolute asset URLs.",
      tags: ["open-graph", "social", "conversion"],
    });
  }
  if (hasPageSurface && !signals.structuredData) {
    projectFinding(add, entryFiles, {
      id: "discoverability-no-structured-data",
      title: "No structured-data implementation was detected",
      category: "GEO / AEO / AIO",
      severity: "low",
      description: "Machine-readable entities and relationships can help eligible search and answer experiences understand page content.",
      evidence: "No JSON-LD, schema.org reference, or recognizable structured-data helper was found.",
      recommendation: "Where relevant, add validated JSON-LD such as Organization, WebSite, BreadcrumbList, Article, Product, or FAQ data that exactly matches visible content.",
      tags: ["geo", "aeo", "aio", "json-ld", "schema.org"],
    });
  }

  const titleGroups = new Map();
  for (const item of literalTitles.filter(({ value }) => value)) {
    if (!titleGroups.has(item.value)) titleGroups.set(item.value, []);
    titleGroups.get(item.value).push(item);
  }
  const duplicateTitle = [...titleGroups.values()].find((items) => items.length > 1);
  if (duplicateTitle) {
    const item = duplicateTitle[1];
    add({
      id: "seo-duplicate-static-title",
      title: "Multiple documents use the same static title",
      category: "SEO",
      severity: "medium",
      description: "Duplicate titles make routes harder to distinguish in search results, history, tabs, and assistive technology.",
      evidence: item.raw,
      file: item.file.relative,
      line: lineAt(contexts.find(({ file }) => file === item.file)?.text ?? "", item.index),
      recommendation: "Give each indexable route a distinct title that starts with its specific topic or purpose.",
      suggestedFiles: duplicateTitle.slice(0, 6).map(({ file }) => file.relative),
      tags: ["seo", "navigation", "content-hierarchy"],
    }, 1);
  }

  const descriptionGroups = new Map();
  for (const item of literalDescriptions.filter(({ value }) => value)) {
    if (!descriptionGroups.has(item.value)) descriptionGroups.set(item.value, []);
    descriptionGroups.get(item.value).push(item);
  }
  const duplicateDescription = [...descriptionGroups.values()].find((items) => items.length > 1);
  if (duplicateDescription) {
    const item = duplicateDescription[1];
    add({
      id: "seo-duplicate-static-description",
      title: "Multiple pages use the same static description",
      category: "SEO",
      severity: "low",
      confidence: "high",
      description: "Identical descriptions make distinct routes harder to differentiate in search results and shared previews.",
      evidence: item.raw,
      file: item.file.relative,
      line: lineAt(contexts.find(({ file }) => file === item.file)?.text ?? "", item.index),
      recommendation: "Write a concise description for each indexable route that reflects that page's specific intent and content.",
      suggestedFiles: duplicateDescription.slice(0, 6).map(({ file }) => file.relative),
      tags: ["seo", "content", "search-snippet", "conversion"],
    }, 1);
  }

  if (!signals.main && interfacePageContexts.length > 0) {
    projectFinding(add, entryFiles, {
      id: "a11y-missing-main-landmark",
      title: "No main-content landmark was detected",
      category: "Semantic HTML",
      severity: "medium",
      confidence: "medium",
      description: "A main landmark lets keyboard and screen-reader users bypass repeated navigation and reach primary content.",
      evidence: "No `<main>` element or `role=\"main\"` was found in markup sources.",
      recommendation: "Wrap each page's unique primary content in one `<main>` landmark and provide a visible-on-focus skip link.",
      tags: ["screen-reader", "keyboard", "semantic-html"],
    });
  }
  if (!signals.nav && interfacePageContexts.length > 1) {
    projectFinding(add, entryFiles, {
      id: "ux-missing-navigation-landmark",
      title: "Multi-page project has no navigation landmark",
      category: "Navigation & information architecture",
      severity: "low",
      confidence: "medium",
      description: "A labeled navigation landmark helps people find and understand the site's primary route structure.",
      evidence: `${interfacePageContexts.length} page-like interface sources were found, but no <nav> or navigation role was detected.`,
      recommendation: "Use semantic, consistently placed navigation and label multiple navigation regions by purpose.",
      tags: ["navigation", "information-architecture", "screen-reader"],
    });
  }

  if (styleContexts.length > 0 && !signals.mediaQueries && !signals.responsiveUtilities) {
    projectFinding(add, entryFiles, {
      id: "responsive-no-breakpoint-strategy",
      title: "No responsive breakpoint strategy was detected",
      category: "Responsive design",
      severity: "medium",
      confidence: "medium",
      description: "The interface may not intentionally adapt its layout, navigation, and density to available space.",
      evidence: "No CSS media/container queries or recognizable responsive utility variants were found.",
      recommendation: "Start with a usable narrow layout, add content-driven media/container queries, and test supported viewport/zoom combinations.",
      suggestedFiles: styleContexts.slice(0, 4).map(({ file }) => file.relative),
      tags: ["mobile-first", "breakpoints", "cross-platform"],
    });
  }
  if (signals.motion && !signals.reducedMotion) {
    projectFinding(add, entryFiles, {
      id: "a11y-motion-no-reduction",
      title: "Animation is present without a reduced-motion alternative",
      category: "Accessibility",
      severity: "medium",
      description: "Non-essential motion can trigger vestibular symptoms and can distract from task completion.",
      evidence: "CSS animation or transition rules were found, but no `prefers-reduced-motion` handling was detected.",
      recommendation: "Honor `prefers-reduced-motion: reduce` by removing or simplifying non-essential movement while preserving state feedback.",
      suggestedFiles: styleContexts.slice(0, 4).map(({ file }) => file.relative),
      tags: ["motion", "microinteractions", "wcag"],
    });
  }

  const appLike = interfacePageContexts.length > 0
    && ([...dependencies].some((name) => WEB_APP_LIBRARIES.has(name)) || markupContexts.length >= 5);
  if (appLike && !signals.loadingState) {
    projectFinding(add, entryFiles, {
      id: "ux-no-loading-state",
      title: "No explicit loading-state implementation was detected",
      category: "UI states",
      severity: "low",
      manual: true,
      description: "Asynchronous interfaces need immediate, non-jarring feedback while content or actions are pending.",
      evidence: "No recognizable loading route, skeleton, spinner, pending state, Suspense fallback, or aria-busy usage was found.",
      recommendation: "Review async flows and add contextual loading feedback that preserves layout, prevents duplicate actions, and exposes busy state accessibly.",
      tags: ["loading-states", "feedback", "cls"],
    });
  }
  if (appLike && !signals.errorState) {
    projectFinding(add, entryFiles, {
      id: "ux-no-error-state",
      title: "No explicit user-facing error state was detected",
      category: "UI states",
      severity: "low",
      manual: true,
      description: "Failures need clear explanations and recovery actions rather than blank or broken interfaces.",
      evidence: "No recognizable error route, boundary, alert region, or error handler UI was found.",
      recommendation: "Add route/component error boundaries and actionable inline/form errors; preserve user input and announce updates accessibly.",
      tags: ["error-states", "error-handling", "feedback"],
    });
  }
  if (appLike && !signals.emptyState) {
    projectFinding(add, entryFiles, {
      id: "ux-no-empty-state",
      title: "No explicit empty-state experience was detected",
      category: "UI states",
      severity: "info",
      manual: true,
      description: "Lists, dashboards, and search results should explain empty outcomes and offer a useful next action.",
      evidence: "No recognizable empty-state component or message was found.",
      recommendation: "For data-driven views, distinguish first-use, no-results, filtered-empty, permission, and failure states with relevant next steps.",
      tags: ["empty-states", "onboarding", "search", "cta"],
    });
  }

  const notFound = contexts.some(({ file }) => /(^|\/)(404|not-found)\.(?:html?|jsx?|tsx?|vue|svelte|astro)$/i.test(file.relative))
    || hasExplicitLocalNotFoundRoute(contexts);
  if (interfacePageContexts.length > 1 && !notFound) {
    projectFinding(add, entryFiles, {
      id: "ux-no-not-found-page",
      title: "No custom not-found experience was detected",
      category: "Error states",
      severity: "low",
      confidence: "medium",
      description: "A useful not-found route keeps broken or outdated links from becoming dead ends.",
      evidence: "No conventional 404/not-found page or explicit local catch-all component route was found.",
      recommendation: "Add a branded, index-safe not-found page with clear navigation, search/help where appropriate, and a path back to a safe destination.",
      tags: ["error-states", "navigation", "trust"],
    });
  }

  const cssColorCount = styleContexts.reduce((total, { text }) => total + (text.match(/#[0-9a-f]{3,8}\b|\b(?:rgb|hsl)a?\(/gi)?.length ?? 0), 0);
  const hasUiLibrary = [...dependencies].some((name) => UI_LIBRARIES.has(name));
  if (styleContexts.length > 0 && cssColorCount >= 12 && !signals.cssVariables && !signals.tokensOrTheme && !hasUiLibrary) {
    projectFinding(add, entryFiles, {
      id: "design-no-color-tokens",
      title: "Repeated colors are not represented by detectable design tokens",
      category: "Design system",
      severity: "low",
      confidence: "medium",
      description: "Uncentralized visual values make consistency, theming, contrast fixes, and component reuse harder.",
      evidence: `${cssColorCount} literal CSS color values were found without CSS custom properties or a recognizable theme/token source.`,
      recommendation: "Define semantic color tokens for surfaces, text, borders, focus, feedback, and actions; bind components to tokens and verify contrast by state.",
      suggestedFiles: styleContexts.slice(0, 4).map(({ file }) => file.relative),
      tags: ["color-theory", "contrast", "consistency", "component-reusability"],
    });
  }

  const hasBrowserTests = [...dependencies].some((dependency) => /(?:playwright|cypress|webdriver|browserstack|saucelabs)/i.test(dependency))
    || contexts.some(({ file }) => /(?:^|\/)(?:e2e|browser-tests?)(?:\/|$)|(?:playwright|cypress|webdriver|browserstack|saucelabs)(?:\.config)?\./i.test(normalizedPath(file)));
  const browserPolicyManifest = manifestRecords.find(({ manifest: packageManifest }) => packageManifest.browserslist);
  const browserslist = browserPolicyManifest?.manifest.browserslist
    || contexts.some(({ file }) => path.posix.basename(normalizedPath(file)) === ".browserslistrc")
    || contexts.some(({ file }) => /(^|\/)browserslist(?:\.config)?\./i.test(file.relative));
  const manifestSuggestions = manifestRecords
    .sort((left, right) => Number(manifestLooksLikeWebApp(right)) - Number(manifestLooksLikeWebApp(left)))
    .map(({ relative }) => relative);
  if (manifestRecords.length > 0 && !browserslist) {
    projectFinding(add, entryFiles, {
      id: "compat-no-browser-policy",
      title: "Supported browser policy is not declared",
      category: "Cross-browser compatibility",
      severity: "low",
      confidence: "medium",
      description: "An explicit target matrix keeps transpilation, CSS prefixing, polyfills, testing, and support expectations aligned.",
      evidence: "No package.json browserslist or browserslist configuration was detected.",
      recommendation: "Document supported browsers and connect that policy to build tooling and representative automated/manual tests.",
      suggestedFiles: [...manifestSuggestions, ".browserslistrc", ...entryFiles],
      tags: ["cross-browser", "cross-platform", "build"],
    });
  }
  if (!hasBrowserTests) {
    projectFinding(add, entryFiles, {
      id: "compat-no-browser-tests",
      title: "No browser-level test setup was detected",
      category: "Quality assurance",
      severity: "info",
      manual: true,
      description: "Static checks cannot catch layout, focus, navigation, network, and browser-engine regressions.",
      evidence: "No Playwright, Cypress, WebDriver, BrowserStack, or Sauce Labs reference was found.",
      recommendation: "Automate a small critical-flow matrix and supplement it with keyboard, screen-reader, touch, responsive, and visual checks.",
      suggestedFiles: ["tests/", "e2e/", ...manifestSuggestions, ...entryFiles],
      tags: ["cross-browser", "user-flow", "regression"],
    });
  }

  if (signals.analytics && !signals.consent && !signals.legal) {
    projectFinding(add, entryFiles, {
      id: "privacy-analytics-without-consent-signal",
      title: "Analytics is present without a detectable consent or privacy path",
      category: "Security & privacy",
      severity: "medium",
      confidence: "medium",
      manual: true,
      description: "Telemetry may require disclosure, consent, opt-out/withdrawal, retention limits, and data minimization depending on implementation and jurisdiction.",
      evidence: "Analytics code was detected, but no recognizable consent control or privacy/legal content was found.",
      recommendation: "Inventory collected data and vendors, gate non-essential tracking where required, honor withdrawal, and link a clear privacy notice near collection points.",
      tags: ["analytics", "consent", "privacy", "trust"],
    });
  }

  addManualReviews(add, entryFiles, signals, options);

  const retainedByFamily = new Map();
  for (const finding of findings) {
    const family = finding.ruleFamily ?? RULE_FAMILY_BY_FINDING[finding.id] ?? finding.id;
    retainedByFamily.set(family, (retainedByFamily.get(family) ?? 0) + 1);
  }
  const suppressedByFamily = new Map();
  for (const [findingId, count] of Object.entries(suppressedByRule)) {
    const family = RULE_FAMILY_BY_FINDING[findingId] ?? findingId;
    suppressedByFamily.set(family, (suppressedByFamily.get(family) ?? 0) + Number(count || 0));
  }

  const hasDocumentRoot = contexts.some(({ file, text }) => containsMarkup(file, text) && /<html\b/i.test(text));
  const hasImageSurface = deliveredAssets.some(({ extension }) => RASTER_IMAGE_EXTENSIONS.has(extension))
    || markupContexts.some(({ text }) => /<(?:img|Image)\b/.test(text))
    || markdownContexts.some((context) => /!\[[^\]]*\]\(|<img\b/i.test(markdownAnalyses.get(context)?.body ?? ""));
  const hasMediaSurface = deliveredAssets.some(({ extension }) => MEDIA_ASSET_EXTENSIONS.has(extension))
    || markupContexts.some(({ text }) => /<(?:audio|video)\b/i.test(text));
  const hasControlSurface = markupContexts.some(({ text }) =>
    /<(?:button|input|select|textarea|summary|dialog)\b|\brole\s*=\s*["'](?:button|checkbox|combobox|dialog|link|menuitem|radio|slider|switch|tab)["']/i.test(text));
  const hasLinkSurface = markupContexts.some(({ text }) => /<a\b/i.test(text))
    || markdownContexts.some((context) => /(?<!!)\[[^\]]+\]\(/.test(markdownAnalyses.get(context)?.body ?? ""));
  const hasFormSurface = markupContexts.some(({ text }) => /<form\b|<(?:input|select|textarea)\b/i.test(text));
  const hasAriaHiddenSurface = markupContexts.some(({ text }) => /\baria-hidden\s*=/.test(text));
  const hasSearchSurface = interfacePageContexts.some(({ file, text }) =>
    /(?:^|[/_.-])(?:search|filter|sort)(?:[/_.-]|$)|\b(?:searchQuery|searchParams|filterBy|sortBy)\b/i.test(`${file.relative} ${text}`));
  const hasConversionSurface = markupContexts.some(({ text }) => /<(?:button|form)\b|<a\b[^>]*\bhref\s*=/i.test(text));
  const applicabilityById = {
    "website-project-detection": true,
    "robots-directives": hasPageSurface,
    "xml-sitemap": hasPageSurface,
    "page-indexability": hasPageSurface,
    "document-title": hasPageSurface,
    "meta-description": hasPageSurface,
    "canonical-url": hasPageSurface,
    "social-sharing-metadata": hasPageSurface,
    "structured-data": hasPageSurface,
    "geo-aeo-aio-readiness": hasPageSurface,
    "document-language": hasDocumentRoot ? true : null,
    "character-encoding": htmlContexts.length > 0 ? true : null,
    "viewport-configuration": htmlContexts.length > 0 ? true : null,
    "heading-hierarchy": pageContexts.length > 0 || markdownContexts.length > 0,
    "heading-content-and-uniqueness": pageContexts.length > 0 || markdownContexts.length > 0,
    "markdown-content-and-frontmatter": markdownContexts.length > 0,
    "semantic-landmarks": interfacePageContexts.length > 0,
    "accessible-images": hasImageSurface,
    "accessible-controls": hasControlSurface,
    "descriptive-links": hasLinkSurface,
    "keyboard-navigation": hasControlSurface || hasLinkSurface,
    "focus-visibility": hasControlSurface && styleContexts.length > 0 ? true : (hasControlSurface ? null : false),
    "screen-reader-support": markupContexts.length > 0 || markdownContexts.length > 0,
    "media-alternatives": hasMediaSurface,
    "autoplay-media": hasMediaSurface,
    "aria-hidden-focus-safety": hasAriaHiddenSurface,
    "form-labels": hasFormSurface,
    "form-validation": hasFormSurface,
    "form-error-feedback": hasFormSurface,
    "form-purpose-and-submit-behavior": hasFormSurface,
    "responsive-layout": interfacePageContexts.length > 0 || styleContexts.length > 0,
    "responsive-breakpoints": styleContexts.length > 0 || signals.responsiveUtilities
      ? true
      : (interfacePageContexts.length > 0 ? null : false),
    "mobile-first-readiness": interfacePageContexts.length === 0
      ? false
      : (htmlContexts.length > 0 || styleContexts.length > 0 ? true : null),
    "touch-targets": hasControlSurface || hasLinkSurface,
    "typography-readability": styleContexts.length > 0
      ? true
      : (interfacePageContexts.length > 0 ? null : false),
    "color-contrast": interfacePageContexts.length > 0,
    "reduced-motion": signals.motion,
    "layout-stability": hasImageSurface,
    "image-delivery": hasImageSurface,
    "priority-image-loading": hasImageSurface,
    "render-blocking-resources": htmlContexts.length > 0 || styleContexts.length > 0,
    "source-payload-size": contexts.some(({ file }) => isSourceFile(file) || isStyleFile(file)) || deliveredAssets.length > 0,
    "core-web-vitals-readiness": hasPageSurface,
    "loading-states": appLike,
    "error-states": appLike,
    "empty-states": appLike,
    "not-found-experience": interfacePageContexts.length > 1,
    "navigation-information-architecture": interfacePageContexts.length > 1 || signals.nav,
    "search-filtering-sorting": hasSearchSurface ? true : null,
    "onboarding-personalization": appLike ? true : null,
    "interaction-feedback": hasControlSurface,
    "design-system-consistency": styleContexts.length > 0 || hasControlSurface,
    "component-reusability": markupContexts.length > 0,
    "cross-browser-compatibility": true,
    "cross-platform-compatibility": true,
    "transport-and-link-security": hasLinkSurface || markupContexts.length > 0,
    "privacy-consent": signals.analytics || signals.consent || signals.legal || hasFormSurface ? true : null,
    "trust-credibility": hasPageSurface,
    "analytics-measurement": signals.analytics ? true : null,
    "conversion-cta": hasConversionSurface,
    "experimentation-ab-testing": signals.experimentation ? true : null,
  };
  const checkLedger = checkDescriptors(applicabilityById).map((descriptor) => {
    const retainedFindings = retainedByFamily.get(descriptor.id) ?? 0;
    const suppressedFindings = suppressedByFamily.get(descriptor.id) ?? 0;
    const observedFindings = retainedFindings + suppressedFindings;
    const outcome = descriptor.status === "not-applicable"
      ? "not-applicable"
      : (descriptor.status === "unknown"
        ? "not-evaluated"
        : (descriptor.kind === "manual"
          ? "manual-review-queued"
          : (observedFindings > 0 ? "signals-observed" : "no-static-signal-observed")));
    return {
      ...descriptor,
      outcome,
      observedFindings,
      retainedFindings,
      suppressedFindings,
    };
  });

  return buildScanResult({
    mode: "mysite",
    title: "Modular Website Check",
    root,
    findings,
    checks: CHECK_IDS.length,
    filesScanned: contexts.length + assetSnapshots.length,
    startedAt,
    metadata: {
      scanner: "website-quality-static-audit",
      findingIndex,
      scannerVersion: 4,
      checkCount: CHECK_IDS.length,
      checks: checkLedger,
      checkLedger,
      checkLedgerSemantics: "completed means the applicable static rule family executed; zero observed signals is not certification or proof of conformance. Manual families remain queued for human or browser validation.",
      coverage: {
        "Automated source checks": "crawl controls and sitemap URLs, HTML and Markdown/frontmatter search metadata, JSON-LD syntax, heading integrity, Markdown links/images, semantic HTML, compound-control accessibility, focus/ARIA safety, accessible media, form purpose and submission behavior, responsive CSS and zoom, UI states, verified web-asset budgets, priority-image and payload risks, compatibility, transport, storage, privacy signals, and design-token hygiene",
        "Manual review queues": "visual/UI quality, UX and user flows, assistive technology, responsive devices, Core Web Vitals, browser/platform matrix, GEO/AEO/AIO content, conversion, analytics, experimentation, privacy, and trust",
        "Files considered": inputFiles.length,
        "Files scanned": contexts.length + assetSnapshots.length,
        "Files excluded from production analysis": excludedNonProduction + excludedNonSite + excludedGenerated,
      },
      project: {
        confidence: project.confidence,
        framework: project.framework ?? null,
        reasons: project.reasons ?? [],
        signals: project.signals ?? [],
      },
      scope: {
        discoveredFiles: inputFiles.length,
        productionCandidates,
        readableFiles: contexts.length,
        unreadableFiles: unreadable,
        verifiedAssetFiles: assetSnapshots.length,
        likelyDeliveredAssetFiles: deliveredAssets.length,
        excludedNonProductionFiles: excludedNonProduction,
        excludedNonSiteFiles: excludedNonSite,
        excludedGeneratedFiles: excludedGenerated,
        unvalidatedCrawlFiles: [...unvalidatedRobots, ...unvalidatedSitemaps].map((file) => file.relative),
        htmlDocumentFiles: htmlContexts.length,
        htmlFragmentFiles: htmlFragmentContexts.length,
        markdownFiles: markdownContexts.length,
        markupFiles: markupContexts.length,
        pageFiles: pageContexts.length,
        styleFiles: styleContexts.length,
        skipped: skipped ?? {},
      },
      assetReview: {
        method: "Repository-confined size and identity metadata only; binary contents are never loaded. Findings are limited to conventional deployable paths or assets referenced by inspected production text.",
        thresholdsBytes: { ...ASSET_BUDGET_BYTES },
        verifiedAssets: assetSnapshots.length,
        likelyDeliveredAssets: deliveredAssets.length,
      },
      options: {
        includeManualReviews: options.includeManualReviews !== false,
        includeGenerated: options.includeGenerated === true,
        includeNonProduction: options.includeNonProduction === true,
        maxFindingsPerRule,
      },
      suppressedByRule,
      suppressedSeverityByRule,
      limitations: [
        "Static analysis cannot prove rendered visual quality, runtime behavior, production headers, field performance, or legal compliance.",
        "Markdown frontmatter analysis recognizes conservative static YAML-style scalar fields; computed metadata and framework layout inheritance require build/runtime validation.",
        "Binary-asset review uses verified path, identity, extension, and size metadata only; it cannot prove transfer compression, intrinsic dimensions, animation, codec quality, or whether a bundler ultimately ships the asset.",
        "Manual-review findings identify checks that require a production build, real content, browsers/devices, assistive technology, analytics data, or legal/product context.",
      ],
    },
  });
}
