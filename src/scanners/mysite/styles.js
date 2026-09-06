import { compact, lineAt, matchAt } from "./text.js";

function cssRules(text) {
  return [...text.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((match) => ({
    selectors: match[1].split(",").map((selector) => selector.trim()).filter(Boolean),
    declarations: match[2],
    index: match.index ?? 0,
  }));
}

function focusSelectorBase(selector) {
  return selector
    .replace(/:focus:not\(\s*:focus-visible\s*\)/gi, "")
    .replace(/:focus-visible\b|:focus\b/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function hasVisibleFocusIndicator(declarations) {
  for (const match of declarations.matchAll(/(?:^|;)\s*outline\s*:\s*([^;]+)/gi)) {
    const value = match[1].trim().toLowerCase();
    if (!/^(?:none|0(?:\s+0)*)(?:\s*!important)?$/.test(value)) return true;
  }
  for (const match of declarations.matchAll(/(?:^|;)\s*box-shadow\s*:\s*([^;]+)/gi)) {
    const value = match[1].trim().toLowerCase();
    if (!/^(?:none|0)(?:\s*!important)?$/.test(value)) return true;
  }
  return false;
}

function missingFocusIndicator(text) {
  const rules = cssRules(text);
  const replacementBases = new Set();
  for (const rule of rules) {
    if (!hasVisibleFocusIndicator(rule.declarations)) continue;
    for (const selector of rule.selectors) {
      if (/:focus(?:-visible)?\b/i.test(selector)) replacementBases.add(focusSelectorBase(selector));
    }
  }

  for (const rule of rules) {
    const hidden = /(?:^|;)\s*((?:outline\s*:\s*(?:none|0(?:\s+0)*)|outline-width\s*:\s*0)(?:\s*!important)?)(?:\s*;|\s*$)/i.exec(rule.declarations);
    if (!hidden) continue;
    const hasSameRuleIndicator = hasVisibleFocusIndicator(rule.declarations);
    const uncovered = rule.selectors.filter((selector) => {
      if (hasSameRuleIndicator && /:focus(?:-visible)?\b/i.test(selector)) return false;
      return !replacementBases.has(focusSelectorBase(selector))
        && !replacementBases.has("")
        && !replacementBases.has("*");
    });
    if (uncovered.length > 0) {
      return {
        evidence: `${uncovered.join(", ")} { ${hidden[1]} }`,
        index: rule.index + rule.selectors.join(",").length + 1 + hidden.index,
      };
    }
  }
  return null;
}

export function auditStyles(context, add, bundled = false) {
  const { file, text } = context;
  const importMatch = [...text.matchAll(/@import\s+(?:url\(\s*)?["'][^"']+["']/gi)]
    .find((match) => !bundled || /@import\s+(?:url\(\s*)?["'](?:https?:)?\/\//i.test(match[0]));
  const cssImport = importMatch ? { match: importMatch, index: importMatch.index } : null;
  if (cssImport) {
    add({
      id: "performance-css-import",
      title: "Stylesheet uses a render-blocking CSS import",
      category: "Performance",
      severity: "low",
      description: "CSS `@import` can serialize stylesheet discovery and delay rendering, especially when it loads another origin.",
      evidence: cssImport.match[0],
      file: file.relative,
      line: lineAt(text, cssImport.index),
      recommendation: "Bundle the stylesheet or load it with a direct `<link rel=\"stylesheet\">`; keep critical dependencies discoverable in the initial document.",
      suggestedFiles: [file.relative],
      tags: ["page-speed", "render-blocking", "lcp", "css"],
    });
  }

  const hiddenFocus = missingFocusIndicator(text);
  if (hiddenFocus) {
    add({
      id: "a11y-focus-indicator-removed",
      title: "Focus indicator is removed without a visible replacement",
      category: "Accessibility",
      severity: "high",
      confidence: "medium",
      description: "Keyboard users need a persistent visual indication of the currently focused control.",
      evidence: hiddenFocus.evidence,
      file: file.relative,
      line: lineAt(text, hiddenFocus.index),
      recommendation: "Keep the browser outline or add a high-contrast `:focus-visible` style with sufficient area and separation.",
      suggestedFiles: [file.relative],
      tags: ["keyboard", "focus", "contrast"],
    });
  }

  const tinyText = matchAt(text, /font-size\s*:\s*(?:[0-9]|1[01])px\b/i);
  if (tinyText) {
    add({
      id: "ux-small-text",
      title: "Very small fixed text may be difficult to read",
      category: "Typography & readability",
      severity: "low",
      confidence: "medium",
      description: "Small fixed-size text increases zoom dependence and can reduce readability on mobile screens.",
      evidence: tinyText.match[0],
      file: file.relative,
      line: lineAt(text, tinyText.index),
      recommendation: "Use a readable type scale with relative units and verify text at 200% zoom and narrow viewports.",
      suggestedFiles: [file.relative],
      tags: ["typography", "mobile-first", "readability"],
    });
  }

  const rigidWidth = matchAt(text, /(?:^|[;{])\s*((?:width|min-width)\s*:\s*(?:[89]\d{2}|[1-9]\d{3,})px\b)/im);
  if (rigidWidth) {
    add({
      id: "responsive-rigid-width",
      title: "Large fixed width can cause horizontal overflow",
      category: "Responsive design",
      severity: "medium",
      confidence: "medium",
      description: "A large pixel width may not adapt to phones, split-screen windows, zoom, or translated content.",
      evidence: rigidWidth.match[1],
      file: file.relative,
      line: lineAt(text, rigidWidth.index),
      recommendation: "Prefer fluid sizing such as `width: 100%` with an appropriate `max-width`, and test at supported breakpoints.",
      suggestedFiles: [file.relative],
      tags: ["mobile-first", "breakpoints", "cross-platform"],
    });
  }

  const fixedBody = matchAt(text, /(?:html|body)\s*\{[^}]*\boverflow\s*:\s*hidden\b/i);
  if (fixedBody) {
    add({
      id: "ux-document-scroll-disabled",
      title: "Document scrolling is globally disabled",
      category: "Usability",
      severity: "medium",
      confidence: "medium",
      description: "Global overflow suppression can trap keyboard focus or hide content at zoomed and mobile sizes.",
      evidence: compact(fixedBody.match[0]),
      file: file.relative,
      line: lineAt(text, fixedBody.index),
      recommendation: "Limit scroll locking to an active modal state and restore it reliably; test zoom and orientation changes.",
      suggestedFiles: [file.relative],
      tags: ["responsive", "keyboard", "zoom"],
    });
  }

  for (const fontFace of text.matchAll(/@font-face\s*\{([^}]*)\}/gi)) {
    if (!/\bfont-display\s*:/i.test(fontFace[1])) {
      add({
        id: "performance-font-display",
        title: "Web font has no loading-display strategy",
        category: "Performance",
        severity: "low",
        description: "The default font loading behavior can hide text or cause avoidable font swaps.",
        evidence: compact(fontFace[0]),
        file: file.relative,
        line: lineAt(text, fontFace.index ?? 0),
        recommendation: "Set an intentional `font-display` value (commonly `swap` or `optional`) and use metric-compatible fallbacks.",
        suggestedFiles: [file.relative],
        tags: ["page-speed", "lcp", "cls", "typography"],
      });
    }
  }

  const transitionAll = matchAt(text, /transition(?:-property)?\s*:\s*all\b/i);
  if (transitionAll) {
    add({
      id: "performance-transition-all",
      title: "Transition animates every changed property",
      category: "Interaction design",
      severity: "low",
      description: "`transition: all` can animate layout properties unexpectedly and make interaction feedback feel sluggish.",
      evidence: transitionAll.match[0],
      file: file.relative,
      line: lineAt(text, transitionAll.index),
      recommendation: "List only the intended composited properties, such as `transform` and `opacity`, with a short duration.",
      suggestedFiles: [file.relative],
      tags: ["microinteractions", "feedback", "performance"],
    });
  }
}
