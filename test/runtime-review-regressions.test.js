import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { responseSecurityFindings } from "../src/runtime/audit-findings.js";
import { runtimeSnapshot } from "../src/runtime/browser-probes.js";

function element({ parentElement = null, style = {}, rects = [{ width: 160, height: 30, left: 0, top: 0 }] } = {}) {
  return {
    parentElement,
    style: { display: "inline-block", visibility: "visible", contentVisibility: "visible", ...style },
    getAttribute: () => null,
    closest: () => null,
    getClientRects: () => rects,
    getBoundingClientRect: () => rects[0] ?? { width: 0, height: 0 },
  };
}

function snapshot(controls) {
  const document = {
    title: "Runtime review regression",
    documentElement: { lang: "en" },
    body: {},
    images: [],
    querySelectorAll(selector) {
      return selector.startsWith("input:") || selector.startsWith("a[href]") ? controls : [];
    },
    querySelector: () => null,
  };
  return vm.runInNewContext(`(${runtimeSnapshot.toString()})()`, {
    document,
    performance: { getEntriesByType: () => [] },
    getComputedStyle: (node) => node.style,
  });
}

test("runtime form visibility follows rendered boxes and hiding ancestors", () => {
  const hiddenParent = element({ style: { display: "none" } });
  const hiddenContentParent = element({ style: { contentVisibility: "hidden" } });
  const controls = [
    element(),
    element({ parentElement: hiddenParent, rects: [] }),
    element({ parentElement: element({ parentElement: hiddenParent }) }),
    element({ parentElement: hiddenContentParent }),
    element({ style: { visibility: "hidden" } }),
    element({ style: { visibility: "collapse" } }),
    element({ rects: [] }),
  ];
  const metrics = snapshot(controls).document;
  assert.equal(metrics.formControlCount, 1);
  assert.equal(metrics.unlabeledFormControlCount, 1);
  assert.equal(metrics.interactiveTargetCount, 1);
});

test("runtime keeps offscreen, visually hidden and visibility-overridden controls in name checks", () => {
  const controls = [
    element({ rects: [{ width: 160, height: 30, left: -10000, top: 0 }] }),
    element({ rects: [{ width: 1, height: 1, left: 0, top: 0 }], style: { clipPath: "inset(50%)" } }),
    element({ style: { opacity: "0" } }),
    element({ parentElement: element({ style: { visibility: "hidden" } }) }),
    element({ parentElement: element({ style: { display: "contents" } }) }),
  ];
  const metrics = snapshot(controls).document;
  assert.equal(metrics.formControlCount, controls.length);
  assert.equal(metrics.unlabeledFormControlCount, controls.length);
  assert.equal(metrics.interactiveTargetCount, controls.length);
});

test("CSP eval analysis follows effective script sources, first directives and all enforcing policies", () => {
  const cases = [
    ["explicit script permission", "default-src 'self'; script-src 'self' 'unsafe-eval'", true],
    ["default fallback", "default-src 'self' 'unsafe-eval'", true],
    ["case insensitive keywords", "SCRIPT-SRC 'SELF' 'UNSAFE-EVAL'", true],
    ["overridden default", "default-src 'self' 'unsafe-eval'; script-src 'self' 'unsafe-inline'", false],
    ["empty script override", "default-src 'unsafe-eval'; script-src", false],
    ["element directive", "script-src 'self'; script-src-elem 'unsafe-eval'", false],
    ["attribute directive", "script-src 'self'; script-src-attr 'unsafe-eval'", false],
    ["element directive alone", "script-src-elem 'unsafe-eval'", false],
    ["element directive does not tighten eval", "script-src 'unsafe-eval'; script-src-elem 'none'", true],
    ["element directive does not override fallback", "default-src 'unsafe-eval'; script-src-elem 'self'", true],
    ["first script directive blocks", "script-src 'self'; script-src 'unsafe-eval'", false],
    ["first script directive allows", "script-src 'unsafe-eval'; script-src 'none'", true],
    ["first default directive blocks", "default-src 'self'; default-src 'unsafe-eval'", false],
    ["second comma policy blocks", "script-src 'unsafe-eval', script-src 'self'", false],
    ["first comma policy blocks", "default-src 'none', script-src 'unsafe-eval'", false],
    ["second newline policy blocks", "script-src 'unsafe-eval'\nscript-src 'self'", false],
    ["all policies allow", "script-src 'unsafe-eval', default-src 'unsafe-eval'", true],
    ["unrelated policy does not restrict eval", "script-src 'unsafe-eval', img-src 'none'", true],
    ["missing script directives", "img-src 'self'", false],
    ["double quotes are not keyword syntax", 'script-src "unsafe-eval"', false],
    ["wasm permission is not string eval", "script-src 'wasm-unsafe-eval'", false],
  ];
  for (const [name, csp, expected] of cases) {
    const findings = responseSecurityFindings("https://example.test/", { "content-security-policy": csp });
    assert.equal(findings.some(({ id }) => id === "runtime.header-csp-unsafe-eval"), expected, name);
  }
  const reportOnly = responseSecurityFindings("https://example.test/", {
    "content-security-policy": "script-src 'self'",
    "content-security-policy-report-only": "script-src 'unsafe-eval'",
  });
  assert.equal(reportOnly.some(({ id }) => id === "runtime.header-csp-unsafe-eval"), false);
});
