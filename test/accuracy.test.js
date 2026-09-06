import assert from "node:assert/strict";
import test from "node:test";
import { measureSecurityAccuracy } from "../scripts/check-accuracy.js";

test("labeled security cases and semantics-preserving transformations stay correct", async () => {
  const result = await measureSecurityAccuracy();
  assert.deepEqual(result.mismatches, []);
  assert.ok(result.groups.some(({ group }) => group.startsWith("validation/")));
  assert.ok(result.groups.some(({ group }) => group.startsWith("metamorphic/")));
});
