import { sanitizeEvidence } from "../core/sanitize.js";
import { isLoopbackHostname, redactUrlQueries, safeDisplayUrl } from "./url-policy.js";

function scoreFamilyForFinding(id) {
  if (id === "runtime.http-error") return "error-states";
  if (id === "runtime.document-content-type") return "runtime-http";
  if (id === "runtime.document-title") return "document-title";
  if (id === "runtime.missing-h1") return "heading-content-and-uniqueness";
  if (id === "runtime.missing-landmarks") return "semantic-landmarks";
  if (id === "runtime.document-language") return "document-language";
  if (id === "runtime.invalid-document-language") return "document-language";
  if (id === "runtime.duplicate-ids") return "semantic-html";
  if (id === "runtime.broken-images") return "image-delivery";
  if (id === "runtime.small-touch-targets") return "touch-targets";
  if (id === "runtime.meta-description") return "meta-description";
  if (id === "runtime.canonical-url") return "canonical-url";
  if (id === "runtime.unlabeled-controls") return "form-labels";
  if (id === "runtime.viewport") return "viewport-configuration";
  if (id === "runtime.horizontal-overflow") return "responsive-layout";
  if (["runtime.slow-lcp", "runtime.lcp-needs-improvement"].includes(id)) return "core-web-vitals-readiness";
  if (["runtime.high-cls", "runtime.cls-needs-improvement"].includes(id)) return "layout-stability";
  if (["runtime.slow-ttfb", "runtime.ttfb-needs-improvement", "runtime.slow-fcp", "runtime.fcp-needs-improvement"].includes(id)) return "runtime-loading-performance";
  if (id === "runtime.long-main-thread-tasks") return "interaction-readiness";
  if (id === "runtime.large-page-transfer") return "page-weight";
  if (id === "runtime.performance-metrics-unavailable") return "runtime-lab-performance";
  if (id.startsWith("runtime.header-")) return "security-headers";
  if ([
    "runtime.request-failures",
    "runtime.remote-requests-blocked",
    "runtime.unmediated-egress-blocked",
  ].includes(id)) return "runtime-network";
  if (id.startsWith("runtime.axe.")) {
    const rule = id.slice("runtime.axe.".length);
    if (/(?:image-alt|object-alt|svg-img-alt|input-image-alt)/.test(rule)) return "accessible-images";
    if (/(?:label|select-name|input-button-name|form-field)/.test(rule)) return "form-labels";
    if (/(?:button-name|aria-command-name)/.test(rule)) return "accessible-controls";
    if (/(?:link-name)/.test(rule)) return "descriptive-links";
    if (/(?:html-has-lang|html-lang-valid)/.test(rule)) return "document-language";
    if (/(?:document-title)/.test(rule)) return "document-title";
    if (/(?:landmark|region)/.test(rule)) return "semantic-landmarks";
    if (/(?:heading-order)/.test(rule)) return "heading-hierarchy";
    if (/(?:page-has-heading-one)/.test(rule)) return "heading-content-and-uniqueness";
    if (/(?:color-contrast)/.test(rule)) return "color-contrast";
    if (/(?:aria-hidden-focus)/.test(rule)) return "aria-hidden-focus-safety";
    if (/(?:tabindex|focus-order)/.test(rule)) return "keyboard-navigation";
    if (/(?:frame-title)/.test(rule)) return "screen-reader-support";
    if (/(?:video-caption|audio-caption)/.test(rule)) return "media-alternatives";
    return "runtime-axe-a11y";
  }
  if (["runtime.axe-failed", "runtime.axe-unavailable", "runtime.axe-incomplete-review", "runtime.axe-results-truncated"].includes(id)) return "runtime-axe-a11y";
  if ([
    "runtime.page-errors",
    "runtime.console-errors",
    "runtime.route-timeout",
    "runtime.route-failed",
    "runtime.audit-infrastructure-failed",
    "runtime.load-state-incomplete",
    "runtime.cleanup-failed",
    "runtime.total-timeout",
    "runtime.playwright-unavailable",
    "runtime.browser-launch-failed",
    "runtime.browser-cleanup-failed",
  ].includes(id)) return "runtime-browser-errors";
  return "runtime-rendered-document";
}

function ruleFamilyForFinding(id) {
  if (["runtime.http-error", "runtime.document-content-type"].includes(id)) return "runtime-http";
  if (["runtime.meta-description", "runtime.canonical-url"].includes(id)) return "runtime-rendered-metadata";
  if (id === "runtime.unlabeled-controls") return "runtime-rendered-forms";
  if (["runtime.viewport", "runtime.horizontal-overflow", "runtime.small-touch-targets"].includes(id)) return "runtime-rendered-layout";
  if ([
    "runtime.slow-lcp",
    "runtime.lcp-needs-improvement",
    "runtime.high-cls",
    "runtime.cls-needs-improvement",
    "runtime.slow-ttfb",
    "runtime.ttfb-needs-improvement",
    "runtime.slow-fcp",
    "runtime.fcp-needs-improvement",
    "runtime.long-main-thread-tasks",
    "runtime.large-page-transfer",
    "runtime.performance-metrics-unavailable",
  ].includes(id)) return "runtime-lab-performance";
  if (id.startsWith("runtime.header-")) return "runtime-security-headers";
  if ([
    "runtime.request-failures",
    "runtime.remote-requests-blocked",
    "runtime.unmediated-egress-blocked",
  ].includes(id)) return "runtime-network";
  if (id.startsWith("runtime.axe.")
    || ["runtime.axe-failed", "runtime.axe-unavailable", "runtime.axe-incomplete-review", "runtime.axe-results-truncated"].includes(id)) {
    return "runtime-axe-a11y";
  }
  if ([
    "runtime.page-errors",
    "runtime.console-errors",
    "runtime.route-timeout",
    "runtime.route-failed",
    "runtime.audit-infrastructure-failed",
    "runtime.load-state-incomplete",
    "runtime.cleanup-failed",
    "runtime.total-timeout",
    "runtime.playwright-unavailable",
    "runtime.browser-launch-failed",
    "runtime.browser-cleanup-failed",
  ].includes(id)) return "runtime-browser-errors";
  return "runtime-rendered-document";
}

export function finding(input) {
  const safeInput = { ...input };
  for (const field of ["title", "description", "recommendation", "evidence"]) {
    if (typeof safeInput[field] === "string") safeInput[field] = redactUrlQueries(safeInput[field]);
  }
  return {
    category: "Runtime & Browser",
    confidence: "high",
    description: "",
    recommendation: "",
    evidence: "",
    file: null,
    line: null,
    suggestedFiles: [],
    tags: ["runtime", "browser"],
    manual: false,
    ...safeInput,
    ruleFamily: input.ruleFamily ?? ruleFamilyForFinding(input.id),
    scoreFamily: input.scoreFamily ?? scoreFamilyForFinding(input.id),
  };
}

export function routeEvidence(routeUrl) {
  return safeDisplayUrl(routeUrl);
}

function wcagStandard(id, title, slugName) {
  return {
    id: `WCAG-2.2-${id}`,
    title,
    url: `https://www.w3.org/WAI/WCAG22/Understanding/${slugName}.html`,
  };
}

const WEB_VITALS_REFERENCE = "https://web.dev/articles/vitals";
const SECURITY_HEADERS_REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html";

function parseContentSecurityPolicies(value) {
  // CSP lists use commas; browser adapters may join repeated header fields with
  // newlines. The first occurrence of a directive in each policy takes effect.
  // https://www.w3.org/TR/CSP3/#parse-serialized-policy-list
  return String(value).split(/[,\r\n]+/).filter((policy) => policy.trim()).map((policy) => {
    const directives = new Map();
    for (const directive of policy.split(";")) {
      const [name, ...sources] = directive.trim().split(/[\t\f ]+/);
      const normalizedName = name.toLowerCase();
      if (normalizedName && !directives.has(normalizedName)) directives.set(normalizedName, sources);
    }
    return directives;
  });
}

function permitsUnsafeEval(policies) {
  // Eval consults script-src (falling back to default-src), never script-src-elem
  // or script-src-attr. Every enforcing policy must allow the operation.
  const effectiveSources = policies.map((policy) => policy.get("script-src") ?? policy.get("default-src"));
  const includesUnsafeEval = (sources) => sources.some((source) => source.toLowerCase() === "'unsafe-eval'");
  return effectiveSources.some((sources) => sources !== undefined && includesUnsafeEval(sources))
    && effectiveSources.every((sources) => sources === undefined || includesUnsafeEval(sources));
}

export function responseSecurityFindings(routeUrl, headers) {
  const output = [];
  const evidence = routeEvidence(routeUrl);
  const csp = headers["content-security-policy"] ?? "";
  const policies = parseContentSecurityPolicies(csp);
  const reportOnlyCsp = headers["content-security-policy-report-only"] ?? "";
  const nosniff = headers["x-content-type-options"] ?? "";
  const frameOptions = headers["x-frame-options"] ?? "";
  const referrerPolicy = headers["referrer-policy"] ?? "";
  const hsts = headers["strict-transport-security"] ?? "";

  if (!csp) {
    output.push(finding({
      id: "runtime.header-csp-missing",
      title: reportOnlyCsp ? "Content Security Policy is report-only" : "Live response has no enforcing Content Security Policy",
      severity: "medium",
      confidence: "medium",
      description: reportOnlyCsp
        ? "The sampled response reports CSP violations but does not enforce the policy."
        : "The sampled HTML response did not include an enforcing Content-Security-Policy header.",
      recommendation: "Deploy a tested, least-privilege Content-Security-Policy response header; begin with reporting if needed, then enforce it without broad unsafe sources.",
      evidence,
      tags: ["runtime", "security-headers", "csp", "manual-review"],
      references: [SECURITY_HEADERS_REFERENCE],
      manual: true,
    }));
  } else if (permitsUnsafeEval(policies)) {
    output.push(finding({
      id: "runtime.header-csp-unsafe-eval",
      title: "Live Content Security Policy permits unsafe-eval",
      severity: "high",
      description: "The enforcing CSP permits string-to-code evaluation in a script source directive.",
      recommendation: "Remove unsafe-eval, replace dynamic code generation, and test the tightened policy in report-only mode before enforcement.",
      evidence,
      tags: ["runtime", "security-headers", "csp", "xss"],
      standards: [{
        id: "CWE-95",
        title: "Improper Neutralization of Directives in Dynamically Evaluated Code",
        url: "https://cwe.mitre.org/data/definitions/95.html",
      }],
      references: [SECURITY_HEADERS_REFERENCE],
    }));
  }

  if (!/^\s*nosniff\s*$/i.test(nosniff)) {
    output.push(finding({
      id: "runtime.header-nosniff-missing",
      title: "Live response does not enforce MIME sniffing protection",
      severity: "low",
      confidence: "medium",
      description: "The sampled HTML response did not return X-Content-Type-Options: nosniff.",
      recommendation: "Return X-Content-Type-Options: nosniff on HTML and static assets and serve every resource with the correct Content-Type.",
      evidence,
      tags: ["runtime", "security-headers", "mime", "manual-review"],
      references: [SECURITY_HEADERS_REFERENCE],
      manual: true,
    }));
  }

  const hasFrameAncestors = policies.some((policy) => policy.get("frame-ancestors")?.length > 0);
  const hasFrameOptions = /^\s*(?:deny|sameorigin)\s*$/i.test(frameOptions);
  if (!hasFrameAncestors && !hasFrameOptions) {
    output.push(finding({
      id: "runtime.header-frame-protection-missing",
      title: "Live response has no explicit framing policy",
      severity: "low",
      confidence: "medium",
      description: "Neither CSP frame-ancestors nor a recognized X-Frame-Options value was observed on the sampled HTML response.",
      recommendation: "Define CSP frame-ancestors for the required embedding origins; add X-Frame-Options as a compatibility fallback when appropriate.",
      evidence,
      tags: ["runtime", "security-headers", "clickjacking", "manual-review"],
      standards: [{
        id: "CWE-1021",
        title: "Improper Restriction of Rendered UI Layers or Frames",
        url: "https://cwe.mitre.org/data/definitions/1021.html",
      }],
      references: [SECURITY_HEADERS_REFERENCE],
      manual: true,
    }));
  }

  const selectedReferrerPolicy = referrerPolicy.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean).at(-1);
  if (!selectedReferrerPolicy) {
    output.push(finding({
      id: "runtime.header-referrer-policy-missing",
      title: "Live response has no explicit referrer policy",
      severity: "low",
      confidence: "medium",
      description: "The sampled HTML response did not declare a Referrer-Policy header.",
      recommendation: "Choose an explicit policy such as strict-origin-when-cross-origin or a stricter value based on product requirements.",
      evidence,
      tags: ["runtime", "security-headers", "privacy", "manual-review"],
      references: [SECURITY_HEADERS_REFERENCE],
      manual: true,
    }));
  } else if (["unsafe-url", "no-referrer-when-downgrade"].includes(selectedReferrerPolicy)) {
    output.push(finding({
      id: "runtime.header-referrer-policy-weak",
      title: "Live response uses a permissive referrer policy",
      severity: "medium",
      description: `The sampled response selected ${selectedReferrerPolicy}, which can disclose more navigation context than necessary.`,
      recommendation: "Use strict-origin-when-cross-origin, same-origin, no-referrer, or another deliberately minimized policy.",
      evidence,
      tags: ["runtime", "security-headers", "privacy"],
      references: [SECURITY_HEADERS_REFERENCE],
    }));
  }

  let parsedRoute;
  try {
    parsedRoute = new URL(String(routeUrl));
  } catch {}
  if (parsedRoute?.protocol === "https:" && !isLoopbackHostname(parsedRoute.hostname)) {
    const maxAge = /(?:^|;)\s*max-age\s*=\s*(\d+)/i.exec(hsts)?.[1];
    if (!maxAge || Number(maxAge) === 0) {
      output.push(finding({
        id: "runtime.header-hsts-missing",
        title: "HTTPS response does not enforce transport security",
        severity: "medium",
        confidence: "medium",
        description: "The sampled HTTPS response had no effective Strict-Transport-Security max-age directive.",
        recommendation: "After confirming every required subdomain supports HTTPS, deploy HSTS with an appropriate max-age and consider includeSubDomains and preload deliberately.",
        evidence,
        tags: ["runtime", "security-headers", "https", "manual-review"],
        references: [SECURITY_HEADERS_REFERENCE],
        manual: true,
      }));
    }
  }
  return output;
}

export function findingsFromSnapshot(routeUrl, snapshot) {
  const evidence = routeEvidence(routeUrl);
  const output = [];
  if (!snapshot.titlePresent) {
    output.push(finding({
      id: "runtime.document-title",
      title: "Rendered document has no title",
      severity: "medium",
      description: "The browser-rendered route did not expose a non-empty document title.",
      recommendation: "Set a unique, descriptive title for this route after client rendering.",
      evidence,
      tags: ["runtime", "seo"],
    }));
  }
  if (snapshot.document.h1Count === 0) {
    output.push(finding({
      id: "runtime.missing-h1",
      title: "Rendered route has no primary heading",
      severity: "low",
      description: "No h1 element was present after the page rendered.",
      recommendation: "Provide one clear primary heading for the route.",
      evidence,
      tags: ["runtime", "accessibility", "content"],
    }));
  }
  if (snapshot.document.landmarkCount === 0) {
    output.push(finding({
      id: "runtime.missing-landmarks",
      title: "Rendered route has no semantic landmarks",
      severity: "low",
      description: "No main, navigation, banner, contentinfo, or complementary landmark was present after rendering.",
      recommendation: "Use semantic page regions or valid landmark roles to make navigation and structure discoverable.",
      evidence,
      tags: ["runtime", "accessibility", "semantics"],
    }));
  }
  if (!snapshot.document.language) {
    output.push(finding({
      id: "runtime.document-language",
      title: "Rendered document has no language",
      severity: "medium",
      description: "The rendered html element did not expose a language value.",
      recommendation: "Set a valid BCP 47 language tag on the html element for every rendered document.",
      evidence,
      tags: ["runtime", "accessibility", "internationalization"],
      standards: [wcagStandard("3.1.1", "Language of Page", "language-of-page")],
    }));
  } else if (snapshot.document.languageValid === false) {
    output.push(finding({
      id: "runtime.invalid-document-language",
      title: "Rendered document language is not a valid BCP 47 tag",
      severity: "medium",
      description: `The rendered html element used the invalid language value ${snapshot.document.language}.`,
      recommendation: "Replace it with a valid BCP 47 language tag such as en, en-US, tr, or tr-TR and verify localized routes.",
      evidence,
      tags: ["runtime", "accessibility", "internationalization"],
      standards: [wcagStandard("3.1.1", "Language of Page", "language-of-page")],
    }));
  }
  if (!snapshot.document.viewportConfigured) {
    output.push(finding({
      id: "runtime.viewport",
      title: "Rendered document has no viewport configuration",
      severity: "medium",
      description: "A viewport meta element was not present after rendering.",
      recommendation: "Add a responsive viewport declaration and validate zoom and mobile layouts.",
      evidence,
      tags: ["runtime", "responsive", "mobile"],
    }));
  }
  if (!snapshot.document.metaDescriptionPresent) {
    output.push(finding({
      id: "runtime.meta-description",
      title: "Rendered route has no meta description",
      severity: "low",
      description: "No non-empty meta description was present in the rendered document.",
      recommendation: "Provide a concise, route-specific description in the rendered head.",
      evidence,
      tags: ["runtime", "seo"],
    }));
  }
  if (!snapshot.document.canonicalPresent) {
    output.push(finding({
      id: "runtime.canonical-url",
      title: "Rendered route has no canonical URL",
      severity: "low",
      description: "No canonical link was present in the rendered document.",
      recommendation: "Emit one absolute canonical URL for the final route after rendering.",
      evidence,
      tags: ["runtime", "seo"],
    }));
  }
  if (snapshot.document.horizontalOverflowPx > 1) {
    output.push(finding({
      id: "runtime.horizontal-overflow",
      title: "Rendered layout overflows the viewport horizontally",
      severity: "medium",
      description: `The rendered document was ${Math.round(snapshot.document.horizontalOverflowPx)} px wider than the viewport.`,
      recommendation: "Find the overflowing element, make media and containers fluid, and retest at narrow breakpoints and zoom levels.",
      evidence,
      tags: ["runtime", "responsive", "usability"],
      standards: [wcagStandard("1.4.10", "Reflow", "reflow")],
    }));
  }
  if (snapshot.document.unlabeledFormControlCount > 0) {
    output.push(finding({
      id: "runtime.unlabeled-controls",
      title: "Rendered form controls may lack accessible labels",
      severity: "high",
      description: `${snapshot.document.unlabeledFormControlCount} rendered form control(s) had no associated or ARIA label.`,
      recommendation: "Associate every input, select, and textarea with visible label text or a valid accessible name.",
      evidence,
      tags: ["runtime", "accessibility", "forms"],
      standards: [wcagStandard("3.3.2", "Labels or Instructions", "labels-or-instructions")],
    }));
  }
  if (snapshot.document.duplicateIdCount > 0) {
    output.push(finding({
      id: "runtime.duplicate-ids",
      title: "Rendered document contains duplicate element ids",
      severity: "low",
      description: `${snapshot.document.duplicateIdCount} rendered element(s) participated in duplicate id groups, which can make labels, fragments, and ARIA relationships ambiguous.`,
      recommendation: "Generate unique ids for every rendered element and update matching label, fragment, and ARIA references.",
      evidence,
      tags: ["runtime", "semantic-html", "accessibility"],
    }));
  }
  if (snapshot.document.brokenImageCount > 0) {
    output.push(finding({
      id: "runtime.broken-images",
      title: "Rendered images failed to load",
      severity: "medium",
      description: `${snapshot.document.brokenImageCount} completed image request(s) rendered with zero intrinsic width.`,
      recommendation: "Fix the asset URL, deployment path, authorization, or image pipeline and provide a resilient fallback.",
      evidence,
      tags: ["runtime", "images", "reliability", "ux"],
    }));
  }
  if (snapshot.document.undersizedTargetCount > 0) {
    output.push(finding({
      id: "runtime.small-touch-targets",
      title: "Rendered interactive targets may be too small",
      severity: "low",
      confidence: "medium",
      description: `${snapshot.document.undersizedTargetCount} of ${snapshot.document.interactiveTargetCount} visible interactive target(s) measured below 24 CSS px in at least one dimension. Spacing and inline-target exceptions require review.`,
      recommendation: "Increase target size or spacing to satisfy WCAG 2.5.8, then verify the mobile viewport with touch and zoom.",
      evidence,
      tags: ["runtime", "mobile", "touch-targets", "accessibility", "manual-review"],
      standards: [wcagStandard("2.5.8", "Target Size (Minimum)", "target-size-minimum")],
      manual: true,
    }));
  }
  const lcp = snapshot.performance.largestContentfulPaintMs;
  const missingPerformanceMetrics = [
    snapshot.performance.measurementSupport?.largestContentfulPaint ? null : "LCP",
    snapshot.performance.measurementSupport?.cumulativeLayoutShift ? null : "CLS",
    snapshot.performance.measurementSupport?.longTasks ? null : "long tasks",
  ].filter(Boolean);
  if (missingPerformanceMetrics.length > 0) {
    output.push(finding({
      id: "runtime.performance-metrics-unavailable",
      title: "Some browser performance metrics were unavailable",
      severity: "info",
      description: `The selected browser did not expose ${missingPerformanceMetrics.join(", ")} for this sampled route; unavailable values are reported as unknown rather than zero.`,
      recommendation: "Rerun with current Chromium for broader lab instrumentation and use field telemetry for Core Web Vitals decisions.",
      evidence,
      tags: ["runtime", "performance", "coverage", "manual-review"],
      references: [WEB_VITALS_REFERENCE],
      manual: true,
    }));
  }
  if (lcp !== null && lcp > 4_000) {
    output.push(finding({
      id: "runtime.slow-lcp",
      title: "Rendered Largest Contentful Paint is slow",
      severity: "medium",
      description: `The observed LCP was ${Math.round(lcp)} ms in this synthetic run.`,
      recommendation: "Optimize the largest above-the-fold asset, critical rendering path, server response, and font loading, then validate with field data.",
      evidence,
      tags: ["runtime", "performance", "core-web-vitals"],
      references: [WEB_VITALS_REFERENCE],
    }));
  } else if (lcp !== null && lcp > 2_500) {
    output.push(finding({
      id: "runtime.lcp-needs-improvement",
      title: "Rendered Largest Contentful Paint needs improvement",
      severity: "low",
      description: `The observed LCP was ${Math.round(lcp)} ms in this synthetic run; the recommended good threshold is 2500 ms or less.`,
      recommendation: "Optimize the largest above-the-fold asset, critical rendering path, server response, and font loading, then validate the 75th percentile with field data.",
      evidence,
      tags: ["runtime", "performance", "core-web-vitals"],
      references: [WEB_VITALS_REFERENCE],
    }));
  }
  const cls = snapshot.performance.cumulativeLayoutShift;
  if (cls !== null && cls > 0.25) {
    output.push(finding({
      id: "runtime.high-cls",
      title: "Rendered layout shift is high",
      severity: "medium",
      description: `The observed cumulative layout shift was ${cls.toFixed(3)} in this synthetic run.`,
      recommendation: "Reserve media and component space, stabilize fonts, and avoid inserting content above existing UI.",
      evidence,
      tags: ["runtime", "performance", "core-web-vitals"],
      references: [WEB_VITALS_REFERENCE],
    }));
  } else if (cls !== null && cls > 0.1) {
    output.push(finding({
      id: "runtime.cls-needs-improvement",
      title: "Rendered layout stability needs improvement",
      severity: "low",
      description: `The observed cumulative layout shift was ${cls.toFixed(3)} in this synthetic run; the recommended good threshold is 0.1 or less.`,
      recommendation: "Reserve media and component space, stabilize fonts, and avoid inserting content above existing UI, then validate the 75th percentile with field data.",
      evidence,
      tags: ["runtime", "performance", "core-web-vitals"],
      references: [WEB_VITALS_REFERENCE],
    }));
  }
  const ttfb = snapshot.navigation?.responseStartMs;
  if (ttfb !== null && ttfb > 800) {
    const poor = ttfb > 1_800;
    output.push(finding({
      id: poor ? "runtime.slow-ttfb" : "runtime.ttfb-needs-improvement",
      title: poor ? "Observed server response is slow" : "Observed server response needs improvement",
      severity: poor ? "medium" : "low",
      description: `The navigation response started after ${Math.round(ttfb)} ms in this synthetic run.`,
      recommendation: "Reduce redirects and backend latency, use effective caching/CDN delivery, and validate TTFB across real users and regions.",
      evidence,
      tags: ["runtime", "performance", "ttfb"],
      references: ["https://web.dev/articles/ttfb"],
    }));
  }
  const fcp = snapshot.performance.firstContentfulPaintMs;
  if (fcp !== null && fcp > 1_800) {
    const poor = fcp > 3_000;
    output.push(finding({
      id: poor ? "runtime.slow-fcp" : "runtime.fcp-needs-improvement",
      title: poor ? "Observed First Contentful Paint is slow" : "Observed First Contentful Paint needs improvement",
      severity: poor ? "medium" : "low",
      description: `The observed FCP was ${Math.round(fcp)} ms in this synthetic run.`,
      recommendation: "Reduce render-blocking work, prioritize critical resources, and improve server delivery before validating with field data.",
      evidence,
      tags: ["runtime", "performance", "fcp"],
      references: ["https://web.dev/articles/fcp"],
    }));
  }
  const longTaskDuration = snapshot.performance.longTaskDurationMs;
  const maxLongTask = snapshot.performance.maxLongTaskMs;
  if (longTaskDuration !== null && maxLongTask !== null
    && (longTaskDuration > 500 || maxLongTask > 200)) {
    output.push(finding({
      id: "runtime.long-main-thread-tasks",
      title: "Long main-thread tasks reduce interaction readiness",
      severity: "medium",
      description: `${snapshot.performance.longTaskCount} long task(s) occupied ${Math.round(longTaskDuration)} ms in total; the longest was ${Math.round(maxLongTask)} ms.`,
      recommendation: "Profile the main thread, split long JavaScript tasks, defer non-critical work, and validate responsiveness with interactions and field INP.",
      evidence,
      tags: ["runtime", "performance", "responsiveness", "inp"],
      references: ["https://web.dev/articles/optimize-long-tasks"],
    }));
  }
  const transferredBytes = snapshot.performance.resourceTransferBytes + (snapshot.navigation?.transferBytes ?? 0);
  if (transferredBytes > 4 * 1024 * 1024) {
    output.push(finding({
      id: "runtime.large-page-transfer",
      title: "Rendered route transfers a large payload",
      severity: "low",
      confidence: "medium",
      description: `The sampled navigation transferred approximately ${(transferredBytes / (1024 * 1024)).toFixed(1)} MiB before the measurement point. Cache state and route intent require review.`,
      recommendation: "Set an explicit performance budget, compress and resize assets, remove unused code, and lazy-load non-critical resources.",
      evidence,
      tags: ["runtime", "performance", "page-weight", "manual-review"],
      references: ["https://web.dev/articles/performance-budgets-101"],
      manual: true,
    }));
  }
  return output;
}

const AXE_SEVERITY = Object.freeze({ critical: "critical", serious: "high", moderate: "medium", minor: "low" });

function slug(value) {
  return String(value ?? "violation").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80)
    || "violation";
}

function axeStandards(tags) {
  if (!Array.isArray(tags)) return [];
  const ids = tags.flatMap((tag) => {
    const match = /^wcag(\d)(\d)(\d+)$/i.exec(String(tag));
    return match ? [`WCAG-2.2-${match[1]}.${match[2]}.${match[3]}`] : [];
  });
  return [...new Set(ids)].map((id) => ({ id }));
}

function safeHttpsReference(value) {
  if (typeof value !== "string") return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password ? parsed.href : null;
  } catch {
    return null;
  }
}

export function normalizeAxeResults(routeUrl, results) {
  const allViolations = Array.isArray(results?.violations) ? results.violations : [];
  const violations = allViolations.slice(0, 100);
  const incomplete = Array.isArray(results?.incomplete) ? results.incomplete : [];
  const passes = Array.isArray(results?.passes) ? results.passes : [];
  const findings = violations.map((violation) => {
    const affectedNodes = Array.isArray(violation.nodes) ? violation.nodes.length : 0;
    const helpReference = safeHttpsReference(violation.helpUrl);
    return finding({
      id: `runtime.axe.${slug(violation.id)}`,
      title: sanitizeEvidence(violation.help ?? violation.id ?? "Browser accessibility violation", 140),
      severity: AXE_SEVERITY[violation.impact] ?? "info",
      description: `${affectedNodes} rendered node(s) failed the ${sanitizeEvidence(violation.id ?? "axe", 80)} rule.`,
      recommendation: sanitizeEvidence(violation.description ?? violation.help ?? "Review the affected rendered nodes.", 300),
      evidence: routeEvidence(routeUrl),
      tags: ["runtime", "accessibility", "axe"],
      standards: axeStandards(violation.tags),
      references: helpReference ? [helpReference] : [],
    });
  });
  if (incomplete.length > 0) {
    const ruleIds = incomplete
      .slice(0, 10)
      .map((entry) => sanitizeEvidence(entry?.id ?? "unknown", 80))
      .filter(Boolean);
    findings.push(finding({
      id: "runtime.axe-incomplete-review",
      title: "Axe produced results that require manual review",
      severity: "info",
      description: `${incomplete.length} accessibility check result(s) could not be decided automatically.`,
      recommendation: "Review Axe's incomplete nodes in the browser and validate them with keyboard and assistive-technology testing.",
      evidence: `${routeEvidence(routeUrl)}${ruleIds.length ? ` — ${ruleIds.join(", ")}` : ""}`,
      tags: ["runtime", "accessibility", "axe", "manual-review"],
      manual: true,
    }));
  }
  if (allViolations.length > violations.length) {
    findings.push(finding({
      id: "runtime.axe-results-truncated",
      title: "Axe detail output was capped",
      severity: "info",
      description: `${allViolations.length} violation groups were detected; ${violations.length} were retained as detailed findings.`,
      recommendation: "Inspect the full Axe result in a focused accessibility run and resolve repeated violation groups systematically.",
      evidence: routeEvidence(routeUrl),
      tags: ["runtime", "accessibility", "axe", "coverage"],
      manual: true,
    }));
  }
  return {
    findings,
    metrics: {
      status: "completed",
      violations: allViolations.length,
      reportedViolations: violations.length,
      affectedNodes: allViolations.reduce((sum, violation) => sum + (Array.isArray(violation.nodes) ? violation.nodes.length : 0), 0),
      incomplete: incomplete.length,
      passes: passes.length,
    },
  };
}

export function eventFindings(routeUrl, counters) {
  const evidence = routeEvidence(routeUrl);
  const output = [];
  if (counters.pageErrors > 0) {
    output.push(finding({
      id: "runtime.page-errors",
      title: "Unhandled browser errors occurred",
      severity: "high",
      description: `${counters.pageErrors} unhandled page error(s) occurred while rendering this route.`,
      recommendation: "Fix the first unhandled exception and add a browser regression test for the affected flow.",
      evidence: `${evidence} — ${counters.pageErrorDetails[0] ?? "details unavailable"}`,
    }));
  }
  if (counters.consoleErrors > 0) {
    output.push(finding({
      id: "runtime.console-errors",
      title: "Browser console errors were emitted",
      severity: "medium",
      description: `${counters.consoleErrors} console error(s) were observed while rendering this route.`,
      recommendation: "Review and resolve application, network, CSP, and hydration errors in the browser console.",
      evidence: `${evidence} — ${counters.consoleErrorDetails[0] ?? "details unavailable"}`,
    }));
  }
  if (counters.requestFailures > 0) {
    output.push(finding({
      id: "runtime.request-failures",
      title: "Browser requests failed",
      severity: "low",
      description: `${counters.requestFailures} request(s) failed during the runtime audit.`,
      recommendation: "Check the failed resource/API URLs and verify resilient loading and error states.",
      evidence: `${evidence} — ${counters.requestFailureDetails[0] ?? "details unavailable"}`,
    }));
  }
  if (counters.blockedRequests > 0) {
    output.push(finding({
      id: "runtime.remote-requests-blocked",
      title: "Remote requests were blocked by the local-only policy",
      severity: "info",
      description: `${counters.blockedRequests} non-loopback request(s) were blocked, so this route was only partially exercised.`,
      recommendation: "Keep the scan local, mock external services, or explicitly allow remote auditing after reviewing the privacy and network impact.",
      evidence: `${evidence} — ${counters.blockedUrls[0] ?? "remote URL hidden"}`,
      manual: true,
    }));
  }
  if (counters.blockedEgressAttempts > 0) {
    output.push(finding({
      id: "runtime.unmediated-egress-blocked",
      title: "Unmediated browser egress APIs were blocked",
      severity: "info",
      description: `${counters.blockedEgressAttempts} worker or browser-transport attempt(s) were blocked by the local-only policy.`,
      recommendation: "Keep these features mocked for local auditing, or explicitly allow remote runtime traffic after reviewing its privacy impact.",
      evidence: `${evidence} — ${counters.blockedEgressKinds.join(", ") || "API details unavailable"}`,
      manual: true,
    }));
  }
  return output;
}
