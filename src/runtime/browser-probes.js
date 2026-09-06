// These functions are serialized by Playwright and evaluated in the page.
// Keep each probe self-contained: browser execution cannot access module imports.

export function runtimeInitScript({ allowRemote }) {
  const state = {
    cls: null,
    lcpMs: null,
    longTasks: null,
    longTaskDurationMs: null,
    maxLongTaskMs: null,
    supported: { cls: false, lcp: false, longTask: false },
    blockedEgressAttempts: 0,
    blockedEgressKinds: [],
  };
  Object.defineProperty(globalThis, "__modularRuntimeMetrics", {
    value: state,
    configurable: false,
    enumerable: false,
    writable: false,
  });

  try {
    if (Array.isArray(PerformanceObserver.supportedEntryTypes)
      && !PerformanceObserver.supportedEntryTypes.includes("layout-shift")) throw new Error("unsupported");
    state.cls = 0;
    let sessionStart = 0;
    let previousShift = 0;
    let sessionValue = 0;
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.hadRecentInput) continue;
        if (sessionValue > 0 && entry.startTime - previousShift < 1000
          && entry.startTime - sessionStart < 5000) sessionValue += entry.value;
        else { sessionStart = entry.startTime; sessionValue = entry.value; }
        previousShift = entry.startTime;
        state.cls = Math.max(state.cls, sessionValue);
      }
    }).observe({ type: "layout-shift", buffered: true });
    state.supported.cls = true;
  } catch {}
  try {
    if (Array.isArray(PerformanceObserver.supportedEntryTypes)
      && !PerformanceObserver.supportedEntryTypes.includes("largest-contentful-paint")) throw new Error("unsupported");
    new PerformanceObserver((list) => {
      const entries = list.getEntries();
      const last = entries[entries.length - 1];
      if (last) state.lcpMs = last.startTime;
    }).observe({ type: "largest-contentful-paint", buffered: true });
    state.supported.lcp = true;
  } catch {}
  try {
    if (Array.isArray(PerformanceObserver.supportedEntryTypes)
      && !PerformanceObserver.supportedEntryTypes.includes("longtask")) throw new Error("unsupported");
    state.longTasks = 0;
    state.longTaskDurationMs = 0;
    state.maxLongTaskMs = 0;
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        state.longTasks += 1;
        state.longTaskDurationMs += entry.duration;
        state.maxLongTaskMs = Math.max(state.maxLongTaskMs, entry.duration);
      }
    }).observe({ type: "longtask", buffered: true });
    state.supported.longTask = true;
  } catch {}

  if (allowRemote) return;
  const localHost = (hostname) => {
    const host = String(hostname).replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
    return host === "localhost" || host.endsWith(".localhost") || host === "::1"
      || host === "0:0:0:0:0:0:0:1" || /^127(?:\.\d{1,3}){3}$/.test(host)
      || /^::ffff:127(?:\.\d{1,3}){3}$/.test(host);
  };
  const permitted = (raw) => {
    try {
      const parsed = new URL(String(raw), location.href);
      return ["data:", "about:"].includes(parsed.protocol)
        || (["http:", "https:", "ws:", "wss:"].includes(parsed.protocol) && localHost(parsed.hostname));
    } catch {
      return false;
    }
  };
  const recordBlockedEgress = (name) => {
    state.blockedEgressAttempts += 1;
    if (!state.blockedEgressKinds.includes(name) && state.blockedEgressKinds.length < 10) {
      state.blockedEgressKinds.push(name);
    }
  };
  const replaceConstructor = (name, construct) => {
    const Native = globalThis[name];
    if (typeof Native !== "function") return;
    try {
      const Guarded = new Proxy(Native, { construct });
      try {
        Object.defineProperty(Native.prototype, "constructor", {
          configurable: false,
          enumerable: false,
          value: Guarded,
          writable: false,
        });
      } catch {}
      Object.defineProperty(globalThis, name, {
        configurable: false,
        enumerable: false,
        value: Guarded,
        writable: false,
      });
    } catch {
      recordBlockedEgress(`${name} guard unavailable`);
    }
  };
  for (const name of ["WebSocket", "EventSource"]) {
    replaceConstructor(name, (target, args, newTarget) => {
      if (!permitted(args[0])) {
        recordBlockedEgress(name);
        throw new DOMException("Remote runtime request blocked", "SecurityError");
      }
      return Reflect.construct(target, args, newTarget);
    });
  }
  // HTTP interception applies inside workers, but browser-level transports such
  // as WebSocket/WebTransport do not reliably pass through it. Blocking worker
  // creation prevents a local worker script from becoming an uninstrumented
  // egress trampoline during a local-only audit.
  for (const name of [
    "Worker",
    "SharedWorker",
    "RTCPeerConnection",
    "webkitRTCPeerConnection",
    "WebTransport",
  ]) {
    replaceConstructor(name, () => {
      recordBlockedEgress(name);
      throw new DOMException(`${name} is disabled during a local-only runtime audit`, "SecurityError");
    });
  }
}

export function runtimeReadiness({ quietMs }) {
  const now = performance.now();
  let state = globalThis.__modularReadiness;
  if (!state) {
    state = { changedAt: now };
    Object.defineProperty(globalThis, "__modularReadiness", { value: state });
    const observer = new MutationObserver(() => { state.changedAt = performance.now(); });
    observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  }
  const pending = [...document.querySelectorAll('[aria-busy="true"], [role="progressbar"], [role="status"]')].some((element) => {
    if (element.hidden || element.closest('[hidden], [aria-hidden="true"]')) return false;
    if (element.getClientRects().length === 0) return false;
    const style = getComputedStyle(element);
    if (style.display === "none" || style.visibility === "hidden") return false;
    if (element.getAttribute("role") !== "status") return true;
    return /\b(?:loading|yükleniyor|chargement|cargando|laden|caricamento)\b/i.test(element.textContent ?? "");
  });
  if (pending) state.changedAt = now;
  return !pending && now - state.changedAt >= quietMs;
}

export function runtimeSnapshot() {
  const navigation = performance.getEntriesByType("navigation")[0];
  const resources = performance.getEntriesByType("resource");
  const paints = Object.fromEntries(performance.getEntriesByType("paint").map((entry) => [entry.name, entry.startTime]));
  const state = globalThis.__modularRuntimeMetrics ?? {};
  const isRendered = (element) => {
    if (element.hidden || element.closest?.("[hidden], [inert], [aria-hidden='true']")) return false;
    try {
      // A child of display:none can have display:inline-block itself, but has no
      // layout boxes. Do not check viewport intersection: offscreen controls and
      // visually hidden accessible controls still need names.
      if (typeof element.getClientRects === "function" && element.getClientRects().length === 0) return false;
      const style = globalThis.getComputedStyle?.(element);
      if (["hidden", "collapse"].includes(style?.visibility)) return false;
      for (let ancestor = element; ancestor; ancestor = ancestor.parentElement) {
        const ancestorStyle = ancestor === element ? style : globalThis.getComputedStyle?.(ancestor);
        if (ancestorStyle?.display === "none" || ancestorStyle?.contentVisibility === "hidden") return false;
      }
      // visibility can be overridden by a child, so only its computed value
      // above applies; display/content-visibility cannot be overridden this way.
      return true;
    } catch {
      return true;
    }
  };
  const controls = [...document.querySelectorAll('input:not([type="hidden"]), select, textarea')]
    .filter(isRendered);
  const text = (value) => String(value ?? "").trim();
  const controlName = (control) => {
    const references = text(control.getAttribute("aria-labelledby")).split(/\s+/).filter(Boolean);
    const referencedName = references.map((id) => {
      const element = document.getElementById?.(id) ?? document.querySelector(`[id="${CSS.escape(id)}"]`);
      return text(element?.textContent);
    }).filter(Boolean).join(" ");
    if (referencedName) return referencedName;
    const ariaLabel = text(control.getAttribute("aria-label"));
    if (ariaLabel) return ariaLabel;
    const id = control.getAttribute("id");
    const labels = control.labels ? [...control.labels] : [
      id ? document.querySelector(`label[for="${CSS.escape(id)}"]`) : null, control.closest("label"),
    ];
    const labelText = labels.map((label) => text(label?.textContent)).filter(Boolean).join(" ");
    if (labelText) return labelText;
    const type = text(control.getAttribute("type")).toLowerCase();
    if (["button", "submit", "reset"].includes(type)) {
      const value = control.getAttribute("value");
      if (text(value)) return text(value);
      if (value === null && ["submit", "reset"].includes(type)) return type;
    }
    if (type === "image" && text(control.getAttribute("alt"))) return text(control.getAttribute("alt"));
    return text(control.getAttribute("title"));
  };
  const unlabeledControls = controls.filter((control) => !controlName(control)).length;
  const images = [...document.images];
  const idCounts = new Map();
  for (const element of document.querySelectorAll("[id]")) {
    const id = element.getAttribute("id")?.trim();
    if (id) idCounts.set(id, (idCounts.get(id) ?? 0) + 1);
  }
  const interactive = [...document.querySelectorAll([
    "a[href]",
    "button",
    "input:not([type='hidden'])",
    "select",
    "textarea",
    "summary",
    "[role='button']",
    "[role='link']",
    "[tabindex]:not([tabindex='-1'])",
  ].join(","))].filter((element) => {
    if (!isRendered(element)) return false;
    try {
      const rect = element.getBoundingClientRect?.();
      return Number(rect?.width) > 0
        && Number(rect?.height) > 0;
    } catch {
      return false;
    }
  });
  const undersizedTargets = interactive.filter((element) => {
    const rect = element.getBoundingClientRect();
    return rect.width < 24 || rect.height < 24;
  }).length;
  const transferBytes = resources.reduce((sum, entry) => sum + (Number(entry.transferSize) || 0), 0);
  const decodedBodyBytes = resources.reduce((sum, entry) => sum + (Number(entry.decodedBodySize) || 0), 0);
  const canonical = document.querySelector('link[rel~="canonical"]');
  const metaDescription = document.querySelector('meta[name="description"]');
  const language = document.documentElement.lang || null;
  let languageValid = null;
  if (language) {
    try {
      Intl.getCanonicalLocales(language);
      languageValid = true;
    } catch {
      languageValid = false;
    }
  }
  const viewportWidth = Math.max(0, Number(globalThis.innerWidth) || 0);
  const documentWidth = Math.max(
    Number(document.documentElement?.scrollWidth) || 0,
    Number(document.body?.scrollWidth) || 0,
  );
  return {
    title: document.title,
    document: {
      elementCount: document.querySelectorAll("*").length,
      h1Count: document.querySelectorAll("h1").length,
      landmarkCount: document.querySelectorAll("main, nav, header, footer, aside, [role='main'], [role='navigation'], [role='banner'], [role='contentinfo']").length,
      formControlCount: controls.length,
      unlabeledFormControlCount: unlabeledControls,
      imageCount: images.length,
      imagesWithoutDimensions: images.filter((image) => !image.getAttribute("width") || !image.getAttribute("height")).length,
      brokenImageCount: images.filter((image) => image.complete && Boolean(image.currentSrc || image.src) && image.naturalWidth === 0).length,
      duplicateIdCount: [...idCounts.values()].filter((count) => count > 1).reduce((sum, count) => sum + count, 0),
      interactiveTargetCount: interactive.length,
      undersizedTargetCount: undersizedTargets,
      language,
      languageValid,
      viewportConfigured: Boolean(document.querySelector('meta[name="viewport"]')),
      metaDescriptionPresent: Boolean(metaDescription?.getAttribute("content")?.trim()),
      canonicalPresent: Boolean(canonical?.href),
      canonicalUrl: canonical?.href || null,
      viewportWidth,
      viewportHeight: Math.max(0, Number(globalThis.innerHeight) || 0),
      documentWidth,
      horizontalOverflowPx: Math.max(0, documentWidth - viewportWidth),
    },
    navigation: navigation ? {
      responseStartMs: navigation.responseStart,
      domContentLoadedMs: navigation.domContentLoadedEventEnd,
      loadEventMs: navigation.loadEventEnd,
      durationMs: navigation.duration,
      transferBytes: navigation.transferSize,
      decodedBodyBytes: navigation.decodedBodySize,
    } : null,
    performance: {
      firstContentfulPaintMs: paints["first-contentful-paint"] ?? null,
      largestContentfulPaintMs: state.supported?.lcp ? (state.lcpMs ?? null) : null,
      cumulativeLayoutShift: state.supported?.cls ? (state.cls ?? 0) : null,
      longTaskCount: state.supported?.longTask ? (state.longTasks ?? 0) : null,
      longTaskDurationMs: state.supported?.longTask ? (state.longTaskDurationMs ?? 0) : null,
      maxLongTaskMs: state.supported?.longTask ? (state.maxLongTaskMs ?? 0) : null,
      measurementSupport: {
        largestContentfulPaint: state.supported?.lcp === true,
        cumulativeLayoutShift: state.supported?.cls === true,
        longTasks: state.supported?.longTask === true,
      },
      resourceCount: resources.length,
      resourceTransferBytes: transferBytes,
      resourceDecodedBodyBytes: decodedBodyBytes,
    },
    policy: {
      blockedEgressAttempts: state.blockedEgressAttempts ?? 0,
      blockedEgressKinds: Array.isArray(state.blockedEgressKinds) ? state.blockedEgressKinds : [],
    },
  };
}
