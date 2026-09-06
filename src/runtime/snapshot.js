import { sanitizeEvidence } from "../core/sanitize.js";
import { safeDisplayUrl } from "./url-policy.js";

function finiteNumber(value) {
  return Number.isFinite(value) ? Math.max(0, value) : null;
}

export function normalizeSnapshot(snapshot) {
  const document = snapshot?.document ?? {};
  const navigation = snapshot?.navigation ?? null;
  const performance = snapshot?.performance ?? {};
  const policy = snapshot?.policy ?? {};
  return {
    titlePresent: typeof snapshot?.title === "string" && snapshot.title.trim().length > 0,
    document: {
      elementCount: finiteNumber(document.elementCount) ?? 0,
      h1Count: finiteNumber(document.h1Count) ?? 0,
      landmarkCount: finiteNumber(document.landmarkCount) ?? 0,
      formControlCount: finiteNumber(document.formControlCount) ?? 0,
      unlabeledFormControlCount: finiteNumber(document.unlabeledFormControlCount) ?? 0,
      imageCount: finiteNumber(document.imageCount) ?? 0,
      imagesWithoutDimensions: finiteNumber(document.imagesWithoutDimensions) ?? 0,
      brokenImageCount: finiteNumber(document.brokenImageCount) ?? 0,
      duplicateIdCount: finiteNumber(document.duplicateIdCount) ?? 0,
      interactiveTargetCount: finiteNumber(document.interactiveTargetCount) ?? 0,
      undersizedTargetCount: finiteNumber(document.undersizedTargetCount) ?? 0,
      language: typeof document.language === "string" ? sanitizeEvidence(document.language, 40) : null,
      languageValid: document.languageValid === true
        ? true
        : (document.languageValid === false ? false : null),
      viewportConfigured: document.viewportConfigured === true,
      metaDescriptionPresent: document.metaDescriptionPresent === true,
      canonicalPresent: document.canonicalPresent === true,
      canonicalUrl: document.canonicalUrl ? safeDisplayUrl(document.canonicalUrl) : null,
      viewportWidth: finiteNumber(document.viewportWidth) ?? 0,
      viewportHeight: finiteNumber(document.viewportHeight) ?? 0,
      documentWidth: finiteNumber(document.documentWidth) ?? 0,
      horizontalOverflowPx: finiteNumber(document.horizontalOverflowPx) ?? 0,
    },
    navigation: navigation ? {
      responseStartMs: finiteNumber(navigation.responseStartMs),
      domContentLoadedMs: finiteNumber(navigation.domContentLoadedMs),
      loadEventMs: finiteNumber(navigation.loadEventMs),
      durationMs: finiteNumber(navigation.durationMs),
      transferBytes: finiteNumber(navigation.transferBytes),
      decodedBodyBytes: finiteNumber(navigation.decodedBodyBytes),
    } : null,
    performance: {
      firstContentfulPaintMs: finiteNumber(performance.firstContentfulPaintMs),
      largestContentfulPaintMs: finiteNumber(performance.largestContentfulPaintMs),
      cumulativeLayoutShift: finiteNumber(performance.cumulativeLayoutShift),
      longTaskCount: finiteNumber(performance.longTaskCount),
      longTaskDurationMs: finiteNumber(performance.longTaskDurationMs),
      maxLongTaskMs: finiteNumber(performance.maxLongTaskMs),
      measurementSupport: {
        largestContentfulPaint: performance.measurementSupport?.largestContentfulPaint === true
          || finiteNumber(performance.largestContentfulPaintMs) !== null,
        cumulativeLayoutShift: performance.measurementSupport?.cumulativeLayoutShift === true
          || finiteNumber(performance.cumulativeLayoutShift) !== null,
        longTasks: performance.measurementSupport?.longTasks === true
          || finiteNumber(performance.longTaskCount) !== null,
      },
      measurementStatus: Object.fromEntries([
        ["largestContentfulPaint", "largestContentfulPaintMs"],
        ["cumulativeLayoutShift", "cumulativeLayoutShift"],
        ["longTasks", "longTaskCount"],
      ].map(([name, field]) => [name, finiteNumber(performance[field]) !== null
        ? "measured" : performance.measurementSupport?.[name] ? "no-entry" : "unavailable"])),
      resourceCount: finiteNumber(performance.resourceCount) ?? 0,
      resourceTransferBytes: finiteNumber(performance.resourceTransferBytes) ?? 0,
      resourceDecodedBodyBytes: finiteNumber(performance.resourceDecodedBodyBytes) ?? 0,
    },
    policy: {
      blockedEgressAttempts: finiteNumber(policy.blockedEgressAttempts) ?? 0,
      blockedEgressKinds: Array.isArray(policy.blockedEgressKinds)
        ? policy.blockedEgressKinds.slice(0, 10).map((value) => sanitizeEvidence(value, 40))
        : [],
    },
  };
}
