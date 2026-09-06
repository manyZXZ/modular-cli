import { htmlDocumentSurface } from "../../core/syntax.js";
import { compact, lineAt, matchAt } from "./text.js";
import {
  absoluteWebUrlIssue,
  attributeValue,
  hasAttribute,
  hasMeaningfulAttribute,
  hasUsableLanguage,
  isLoopbackUrl,
  pairedTags,
  staticAttributeValue,
  tags,
  visibleText,
} from "./markup.js";

export function auditHtmlDocument(context, add) {
  const { file, text } = context;
  const head = matchAt(text, /<head\b[^>]*>/i);
  const titleSurface = htmlDocumentSurface(text);
  const titleTags = pairedTags(titleSurface, "title");
  const title = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(titleSurface);
  if (!title || !visibleText(title[1])) {
    add({
      id: "seo-missing-title",
      title: "HTML document has no non-empty page title",
      category: "SEO",
      severity: "high",
      description: "Every concrete HTML document needs a descriptive title for search results, browser history/tabs, and assistive technology.",
      evidence: title ? title[0] : "No `<title>` element was found in this HTML document.",
      file: file.relative,
      line: lineAt(text, title?.index ?? head?.index ?? 0),
      recommendation: "Add a concise, route-specific `<title>` whose leading words identify this page rather than only the site name.",
      suggestedFiles: [file.relative],
      tags: ["seo", "accessibility", "content-hierarchy"],
    });
  }
  if (titleTags.length > 1) {
    add({
      id: "seo-multiple-titles",
      title: "HTML document declares multiple page titles",
      category: "SEO",
      severity: "medium",
      description: "Multiple title elements make the browser and crawler-selected document title ambiguous.",
      evidence: `${titleTags.length} <title> elements were found; the second starts with ${compact(titleTags[1].raw, 120)}.`,
      file: file.relative,
      line: lineAt(text, titleTags[1].index),
      recommendation: "Render exactly one non-empty title for this route and keep title ownership in one layout or metadata layer.",
      suggestedFiles: [file.relative],
      tags: ["seo", "document-head", "content-hierarchy"],
    }, 1);
  }

  const metaTags = tags(text, "meta");
  const description = metaTags.find(({ raw }) => (attributeValue(raw, "name") ?? "").toLowerCase() === "description");
  if (!description || !hasMeaningfulAttribute(description.raw, "content")) {
    add({
      id: "seo-missing-description",
      title: "HTML document has no non-empty meta description",
      category: "SEO",
      severity: "medium",
      description: "A useful route-specific description helps people understand the page's relevance before visiting.",
      evidence: description ? description.raw : "No description meta tag was found in this HTML document.",
      file: file.relative,
      line: lineAt(text, description?.index ?? head?.index ?? 0),
      recommendation: "Add a truthful, route-specific meta description that summarizes this page without duplicating every route.",
      suggestedFiles: [file.relative],
      tags: ["seo", "conversion", "scannability"],
    });
  }

  const socialTags = metaTags.map((tag) => ({
    ...tag,
    key: (staticAttributeValue(tag.raw, "property") ?? staticAttributeValue(tag.raw, "name") ?? "").toLowerCase(),
    value: staticAttributeValue(tag.raw, "content"),
  })).filter(({ key, value }) => (key.startsWith("og:") || key.startsWith("twitter:")) && value);
  const socialMetadata = socialTags.length > 0;
  if (!socialMetadata) {
    add({
      id: "seo-missing-social-metadata",
      title: "HTML document has no usable social sharing metadata",
      category: "Discoverability",
      severity: "low",
      description: "Route-specific Open Graph/card data improves recognition and presentation when this page is shared.",
      evidence: "No non-empty Open Graph or Twitter/X card metadata was found in this HTML document.",
      file: file.relative,
      line: lineAt(text, head?.index ?? 0),
      recommendation: "Add route-appropriate Open Graph title, description, canonical URL, image, and card metadata with absolute production URLs.",
      suggestedFiles: [file.relative],
      tags: ["open-graph", "social", "conversion"],
    });
  } else {
    const socialKeys = new Set(socialTags.map(({ key }) => key));
    const missing = [];
    const hasOpenGraph = socialTags.some(({ key }) => key.startsWith("og:"));
    const hasTwitter = socialTags.some(({ key }) => key.startsWith("twitter:"));
    if (hasOpenGraph) {
      for (const key of ["og:title", "og:type", "og:image", "og:url"]) {
        if (!socialKeys.has(key)) missing.push(key);
      }
    }
    if (hasTwitter) {
      if (!socialKeys.has("twitter:card")) missing.push("twitter:card");
      if (!socialKeys.has("twitter:title") && !socialKeys.has("og:title")) missing.push("twitter:title/og:title");
      if (!socialKeys.has("twitter:description") && !socialKeys.has("og:description")) missing.push("twitter:description/og:description");
      if (!socialKeys.has("twitter:image") && !socialKeys.has("og:image")) missing.push("twitter:image/og:image");
    }
    if (missing.length > 0) {
      add({
        id: "seo-incomplete-social-metadata",
        title: "Social sharing metadata is incomplete",
        category: "Discoverability",
        severity: "low",
        description: "A partial card can produce inconsistent titles, images, or destinations when a route is shared across platforms.",
        evidence: `Missing ${missing.join(", ")}.`,
        file: file.relative,
        line: lineAt(text, socialTags[0].index),
        recommendation: "Complete one coherent route-specific Open Graph/card contract with an absolute URL and representative image; verify the rendered preview.",
        suggestedFiles: [file.relative],
        tags: ["open-graph", "social", "conversion", "metadata"],
        references: ["https://ogp.me/"],
      }, 1);
    }

    for (const social of socialTags.filter(({ key }) => ["og:url", "og:image", "twitter:image"].includes(key))) {
      const issue = absoluteWebUrlIssue(social.value);
      if (!issue) continue;
      add({
        id: "seo-invalid-social-url",
        title: "Social metadata contains an invalid URL",
        category: "Discoverability",
        severity: "low",
        description: "Social crawlers need absolute HTTP(S) URLs for shared destinations and preview images.",
        evidence: `${compact(social.raw, 170)} — ${issue}.`,
        file: file.relative,
        line: lineAt(text, social.index),
        recommendation: "Emit the final absolute HTTPS production URL for this social metadata field.",
        suggestedFiles: [file.relative],
        tags: ["open-graph", "social", "metadata", "url"],
        references: ["https://ogp.me/"],
      });
    }
  }

  const linkTags = tags(text, "link");
  const canonicals = linkTags.filter(({ raw }) => (attributeValue(raw, "rel") ?? "").toLowerCase().split(/\s+/).includes("canonical"));
  const canonical = canonicals[0];
  if (!canonical || !hasMeaningfulAttribute(canonical.raw, "href")) {
    add({
      id: "seo-missing-canonical",
      title: "HTML document has no usable canonical URL",
      category: "SEO",
      severity: "low",
      confidence: "medium",
      description: "A canonical URL helps consolidate equivalent URL variants and clarifies the preferred source.",
      evidence: canonical ? canonical.raw : "No canonical link was found in this HTML document.",
      file: file.relative,
      line: lineAt(text, canonical?.index ?? head?.index ?? 0),
      recommendation: "Add an absolute self-referencing canonical URL and ensure it matches the production host and preferred route form.",
      suggestedFiles: [file.relative],
      tags: ["seo", "duplicate-content", "trust"],
    });
  }
  if (canonicals.length > 1) {
    add({
      id: "seo-multiple-canonicals",
      title: "HTML document declares multiple canonical URLs",
      category: "SEO",
      severity: "medium",
      description: "Conflicting canonical elements make the preferred indexable URL ambiguous and may cause crawlers to ignore the hint.",
      evidence: `${canonicals.length} canonical link elements were found; the second is ${compact(canonicals[1].raw, 140)}.`,
      file: file.relative,
      line: lineAt(text, canonicals[1].index),
      recommendation: "Emit exactly one absolute self-referencing canonical URL after all layouts, plugins, and route metadata are composed.",
      suggestedFiles: [file.relative],
      tags: ["seo", "canonical", "duplicate-content"],
      references: ["https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls"],
    }, 1);
  }
  if (canonical) {
    const canonicalHref = staticAttributeValue(canonical.raw, "href");
    const issue = canonicalHref === null ? null : absoluteWebUrlIssue(canonicalHref);
    if (issue) {
      add({
        id: "seo-invalid-canonical",
        title: "Canonical URL is not a valid production URL",
        category: "SEO",
        severity: "medium",
        description: "A canonical must be an absolute, public HTTP(S) URL without credentials or fragments.",
        evidence: `${compact(canonical.raw, 170)} — ${issue}.`,
        file: file.relative,
        line: lineAt(text, canonical.index),
        recommendation: "Replace this value with the route's absolute HTTPS production URL and ensure it resolves without redirects.",
        suggestedFiles: [file.relative],
        tags: ["seo", "canonical", "indexability", "trust"],
        references: ["https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls"],
      });
    } else if (canonicalHref !== null) {
      const canonicalUrl = new URL(canonicalHref);
      if (canonicalUrl.protocol === "http:" && !isLoopbackUrl(canonicalUrl)) {
        add({
          id: "seo-insecure-canonical",
          title: "Canonical URL uses insecure HTTP",
          category: "SEO & transport security",
          severity: "low",
          description: "An HTTP canonical can split indexing signals from the secure production URL and send crawlers through an avoidable redirect.",
          evidence: compact(canonical.raw, 170),
          file: file.relative,
          line: lineAt(text, canonical.index),
          recommendation: "Point the canonical directly to the final HTTPS URL and redirect the HTTP origin consistently.",
          suggestedFiles: [file.relative],
          tags: ["seo", "canonical", "https", "transport-security"],
        });
      }
    }
  }

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

  const charsetMeta = metaTags.find(({ raw }) => hasAttribute(raw, "charset"));
  const charsetValue = charsetMeta ? (attributeValue(charsetMeta.raw, "charset") ?? "").trim().toLowerCase() : "";
  const legacyCharset = metaTags.find(({ raw }) => {
    const httpEquiv = (attributeValue(raw, "http-equiv") ?? "").trim().toLowerCase();
    const content = attributeValue(raw, "content") ?? "";
    return httpEquiv === "content-type" && /\bcharset\s*=\s*utf-8\b/i.test(content);
  });
  if (charsetValue !== "utf-8" && (!legacyCharset || charsetMeta)) {
    add({
      id: "html-missing-charset",
      title: "UTF-8 character encoding is missing or invalid",
      category: "Compatibility",
      severity: "low",
      description: "An early UTF-8 declaration prevents incorrect text decoding across browsers and platforms.",
      evidence: charsetMeta?.raw ?? "No valid UTF-8 charset declaration was found in this document.",
      file: file.relative,
      line: lineAt(text, charsetMeta?.index ?? head?.index ?? 0),
      recommendation: "Add `<meta charset=\"utf-8\">` near the start of `<head>`.",
      suggestedFiles: [file.relative],
      tags: ["cross-browser", "cross-platform"],
    });
  }

  const viewport = metaTags.find(({ raw }) => (attributeValue(raw, "name") ?? "").trim().toLowerCase() === "viewport");
  const viewportContent = viewport ? attributeValue(viewport.raw, "content") ?? "" : "";
  const hasResponsiveViewport = /\bwidth\s*=\s*device-width\b/i.test(viewportContent)
    || (hasMeaningfulAttribute(viewport?.raw ?? "", "content") && /[{}%$]/.test(viewportContent));
  if (!hasResponsiveViewport) {
    add({
      id: "responsive-missing-viewport",
      title: "Mobile viewport configuration is missing or incomplete",
      category: "Responsive design",
      severity: "high",
      description: "Without a viewport declaration, mobile browsers can render the page at a desktop layout width.",
      evidence: viewport?.raw ?? "No `<meta name=\"viewport\">` declaration was found.",
      file: file.relative,
      line: lineAt(text, viewport?.index ?? head?.index ?? 0),
      recommendation: "Add `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">`.",
      suggestedFiles: [file.relative],
      tags: ["mobile-first", "responsive", "viewport"],
    });
  }

  if (viewport) {
    const staticViewport = staticAttributeValue(viewport.raw, "content");
    const maximumScale = /(?:^|,)\s*maximum-scale\s*=\s*([0-9]*\.?[0-9]+)/i.exec(staticViewport ?? "");
    const blocksZoom = /(?:^|,)\s*user-scalable\s*=\s*(?:no|0(?:\.0+)?)(?:\s*,|\s*$)/i.test(staticViewport ?? "")
      || (maximumScale && Number(maximumScale[1]) < 2);
    if (blocksZoom) {
      add({
        id: "a11y-viewport-zoom",
        title: "Viewport configuration restricts text zoom",
        category: "Accessibility",
        severity: "high",
        description: "Disabling pinch zoom or limiting scale below 200% prevents some low-vision users from enlarging content.",
        evidence: viewport.raw,
        file: file.relative,
        line: lineAt(text, viewport.index),
        recommendation: "Remove `user-scalable=no` and restrictive `maximum-scale` values; make the layout reflow cleanly when users zoom.",
        suggestedFiles: [file.relative],
        tags: ["wcag", "zoom", "mobile", "low-vision"],
        standards: [{
          id: "WCAG-1.4.4",
          title: "WCAG 2.2 — Resize text",
          url: "https://www.w3.org/WAI/WCAG22/Understanding/resize-text.html",
        }],
      });
    }
  }

  const noIndexTag = metaTags.find(({ raw }) => /^(?:robots|googlebot|googlebot-news|bingbot)$/i
    .test((attributeValue(raw, "name") ?? "").trim())
    && /(?:^|[,\s])noindex(?:[,\s]|$)/i.test(attributeValue(raw, "content") ?? ""));
  const noIndex = noIndexTag ? { index: noIndexTag.index, match: [noIndexTag.raw] } : null;
  if (noIndex) {
    add({
      id: "seo-page-noindex",
      title: "Page is explicitly excluded from search indexes",
      category: "SEO",
      severity: "medium",
      confidence: "medium",
      description: "A noindex directive removes this page from conventional search and can also reduce answer-engine discoverability.",
      evidence: noIndex.match[0],
      file: file.relative,
      line: lineAt(text, noIndex.index),
      recommendation: "Confirm this page should be private or temporary; otherwise remove the noindex directive before production.",
      suggestedFiles: [file.relative],
      tags: ["seo", "geo", "aeo", "indexability"],
    });
  }

  const refresh = metaTags.find(({ raw }) => (attributeValue(raw, "http-equiv") ?? "").trim().toLowerCase() === "refresh");
  if (refresh) {
    const refreshContent = staticAttributeValue(refresh.raw, "content");
    const delay = /^\s*([0-9]+(?:\.[0-9]+)?)/.exec(refreshContent ?? "");
    if (delay && Number(delay[1]) <= 20) {
      add({
        id: "a11y-meta-refresh",
        title: "Page automatically refreshes or redirects on a short timer",
        category: "Accessibility & usability",
        severity: Number(delay[1]) === 0 ? "medium" : "low",
        confidence: "high",
        description: "A timed refresh or redirect can interrupt reading, form entry, assistive technology, and browser history.",
        evidence: refresh.raw,
        file: file.relative,
        line: lineAt(text, refresh.index),
        recommendation: "Use a server-side redirect for permanent navigation, or let the user initiate refreshes and extend sessions explicitly.",
        suggestedFiles: [file.relative],
        tags: ["wcag", "timing", "navigation", "user-control"],
      });
    }
  }

  const scriptTags = tags(text, "script").filter(({ raw }) => /\bsrc\s*=/i.test(raw));
  const blocking = scriptTags.find(({ raw }) => !/\b(?:async|defer)\b/i.test(raw) && !/\btype\s*=\s*["']module["']/i.test(raw));
  if (blocking) {
    add({
      id: "performance-render-blocking-script",
      title: "Script may block initial rendering",
      category: "Performance",
      severity: "low",
      confidence: "medium",
      description: "Parser-blocking scripts can delay First Contentful Paint and Largest Contentful Paint.",
      evidence: blocking.raw,
      file: file.relative,
      line: lineAt(text, blocking.index),
      recommendation: "Load independent scripts with `defer`, `async`, or `type=\"module\"`; keep ordering requirements explicit.",
      suggestedFiles: [file.relative],
      tags: ["page-speed", "core-web-vitals", "lcp"],
    });
  }
}
