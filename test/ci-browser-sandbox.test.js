import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildChromiumSandboxProfile, resolveChromiumExecutables } from "../scripts/ci/chromium-sandbox-profile.js";

const browsers = [
  { name: "chromium", executablePath: "/ci/browser cache/chromium-1243/chrome-linux64/chrome" },
  { name: "chromium-headless-shell", executablePath: "/ci/browser cache/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell" },
];

test("CI sandbox profile permits user namespaces for exactly both pinned browser binaries", () => {
  const profile = buildChromiumSandboxProfile(browsers);
  assert.equal(profile, `abi <abi/4.0>,

profile modular-ci-chromium "${browsers[0].executablePath}" flags=(unconfined) {
  userns,
}

profile modular-ci-chromium-headless-shell "${browsers[1].executablePath}" flags=(unconfined) {
  userns,
}
`);
  assert.equal((profile.match(/userns,/g) || []).length, 2);
});

test("CI sandbox profile refuses incomplete targets and AppArmor rule injection", () => {
  for (const entries of [[], [browsers[0]], [browsers[0], browsers[0]], [browsers[0], { name: "firefox", executablePath: "/ci/firefox" }]]) {
    assert.throws(() => buildChromiumSandboxProfile(entries));
  }
  for (const executablePath of ["chrome", "/ci/*/chrome", "/ci/**/chrome", "/ci/@{HOME}/chrome", "/ci/{a,b}/chrome",
    "/ci/[ab]/chrome", "/ci/?/chrome", '/ci/"/chrome', "/ci/\nuserns,/chrome", "/ci/../chrome", "/ci//chrome",
    "/ci/\\/chrome", "/ci/chrome#bad", "/ci/not-chrome", "C:/ci/chrome"]) {
    assert.throws(() => buildChromiumSandboxProfile([{ ...browsers[0], executablePath }, browsers[1]]), undefined, executablePath);
  }
});

test("CI browser discovery requires installed regular files inside their own installation", async t => {
  const temp = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(temp, "modular-ci-browser-profile-"));
  t.after(async () => {
    const real = await fs.realpath(root);
    assert.equal(path.dirname(real).toLowerCase(), temp.toLowerCase());
    assert.ok(path.basename(real).startsWith("modular-ci-browser-profile-"));
    await fs.rm(real, { recursive: true, force: true });
  });
  const fixtures = new Map();
  for (const { name } of browsers) {
    const directory = path.join(root, name);
    const executablePath = path.join(directory, "browser.exe");
    await fs.mkdir(directory);
    await fs.writeFile(executablePath, "fixture", { mode: 0o755 });
    fixtures.set(name, { directory, executablePath: () => executablePath });
  }
  // Windows does not preserve POSIX executable mode. Model that single metadata
  // bit without skipping the path-confinement or regular-file checks there.
  if (process.platform === "win32") {
    const original = fs.lstat.bind(fs);
    t.mock.method(fs, "lstat", async target => {
      const stat = await original(target);
      stat.mode |= 0o111;
      return stat;
    });
  }
  const registry = { findExecutable: name => fixtures.get(name) };
  assert.equal((await resolveChromiumExecutables(registry)).length, 2);
  const original = fixtures.get("chromium");
  fixtures.set("chromium", { ...original, executablePath: () => fixtures.get("chromium-headless-shell").executablePath() });
  await assert.rejects(resolveChromiumExecutables(registry), /unconfined/);
  fixtures.set("chromium", { ...original, executablePath: () => original.directory });
  await assert.rejects(resolveChromiumExecutables(registry), /non-executable/);
  fixtures.delete("chromium");
  await assert.rejects(resolveChromiumExecutables(registry), /not found/);
});

test("CI profile generator refuses local and self-hosted use before emitting a profile", () => {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("../scripts/ci/chromium-sandbox-profile.js", import.meta.url))], {
    encoding: "utf8",
    env: { ...process.env, GITHUB_ACTIONS: "false", RUNNER_ENVIRONMENT: "self-hosted" },
    windowsHide: true,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /only for the disposable GitHub-hosted Linux CI runner/);
});
