import assert from "node:assert/strict";
import test from "node:test";
import { validateRepositoryPaths } from "../scripts/verify-repository.js";

const required = ["README.md", "LICENSE", "package.json", "package-lock.json", ".gitignore", ".github/workflows/ci.yml", "bin/modular.js", "src/index.js", "examples/basic-site/index.html"];
test("public repository contract accepts source and synthetic examples", () => {
  assert.deepEqual(validateRepositoryPaths([...required, "test/fixtures/security-accuracy.json", "docs/README.tr.md"]), []);
});
test("ignored-but-tracked private outputs and credentials cannot pass repository review", () => {
  for (const candidate of ["audit/client/report.md", "examples/basic-site/Modular/modular-results.json", "src/.env.production", "src/key.pem", "node_modules/pkg/index.js", "notes.txt"]) {
    assert.ok(validateRepositoryPaths([...required, candidate]).length > 0, candidate);
  }
});
test("repository paths must be portable and complete", () => {
  assert.ok(validateRepositoryPaths(required.slice(1)).some(error => error.includes("README.md")));
  assert.ok(validateRepositoryPaths([...required, "src/../notes.md"]).some(error => error.includes("non-portable")));
  assert.ok(validateRepositoryPaths([...required, "src/Core.js", "src/core.js"]).some(error => error.includes("Case-colliding")));
  for (const candidate of ["src/AUX.js", "src/file:name.js", "src/trailing.", "src/COM1.txt", "src/name "]) {
    assert.ok(validateRepositoryPaths([...required, candidate]).some(error => error.includes("non-portable")), candidate);
  }
});
