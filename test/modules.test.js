import assert from "node:assert/strict";
import test from "node:test";
import { SCAN_MODULES, createScanModuleRegistry, getScanModule } from "../src/index.js";
import { REPORT_FILES } from "../src/core/reporter.js";

test("built-in module contracts drive runners, capabilities and report mappings", async () => {
  for (const module of SCAN_MODULES) {
    assert.equal(getScanModule(module.id), module);
    assert.equal(typeof await module.load(), "function");
    assert.deepEqual(module.reports.map(({ file }) => file), REPORT_FILES[module.id]);
    assert.ok(Object.isFrozen(module) && Object.isFrozen(module.reports) && Object.isFrozen(module.capabilities));
  }
  assert.equal(getScanModule("security").capabilities.dependencyAudit, true);
  assert.equal(getScanModule("mysite").capabilities.runtime, true);
  assert.throws(() => getScanModule("unknown"), /Unknown/);
});

test("module registration rejects ambiguous identities and unsafe report mappings without loading code", () => {
  const module = SCAN_MODULES[0];
  assert.throws(() => createScanModuleRegistry([module, module]), /duplicate/);
  assert.throws(() => createScanModuleRegistry(null), /array/);
  assert.throws(() => createScanModuleRegistry([{ ...module, runnerKey: "__proto__" }]), /Invalid/);
  assert.throws(() => createScanModuleRegistry([module, { ...SCAN_MODULES[1], runnerKey: module.runnerKey }]), /duplicate/);
  assert.throws(() => createScanModuleRegistry([{ ...module, id: "../escape" }]), /Invalid/);
  assert.throws(() => createScanModuleRegistry([{ ...module, reports: [{ file: "../report.md", title: "x" }, module.reports[1]] }]), /Invalid/);
  let loaded = false;
  const registry = createScanModuleRegistry([{ ...module, id: "local-review", load: async () => { loaded = true; } }]);
  assert.equal(registry[0].id, "local-review");
  assert.equal(loaded, false);
});
