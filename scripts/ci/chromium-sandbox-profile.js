import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BROWSERS = new Map([
  ["chromium", "chrome"],
  ["chromium-headless-shell", "chrome-headless-shell"],
]);

// Ubuntu 24.04 restricts user namespaces for otherwise unconfined applications.
// Grant this permission only to the installed, pinned CI browsers. Keep both the
// Chromium sandbox and the system-wide AppArmor restriction enabled.
// https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md
export function buildChromiumSandboxProfile(executables) {
  if (!Array.isArray(executables) || executables.length !== BROWSERS.size) {
    throw new Error("Expected the pinned Chromium and Chromium headless-shell executables.");
  }
  const seen = new Set();
  const profiles = executables.map(({ name, executablePath }) => {
    if (!BROWSERS.has(name) || seen.has(name)) throw new Error("Unexpected or duplicate CI browser.");
    seen.add(name);
    // A deliberately narrow alphabet prevents AppArmor glob/variable/quote/rule
    // injection. Quoted attachments permit spaces without broadening the match.
    if (typeof executablePath !== "string" || !/^\/[A-Za-z0-9_./ -]+$/.test(executablePath)
      || path.posix.normalize(executablePath) !== executablePath
      || path.posix.basename(executablePath) !== BROWSERS.get(name)) {
      throw new Error("Expected a normalized, exact Linux CI browser executable path.");
    }
    return `profile modular-ci-${name} "${executablePath}" flags=(unconfined) {\n  userns,\n}`;
  });
  return `abi <abi/4.0>,\n\n${profiles.join("\n\n")}\n`;
}

export async function resolveChromiumExecutables(registry) {
  const executables = [];
  for (const name of BROWSERS.keys()) {
    const entry = registry.findExecutable(name);
    const candidate = entry?.executablePath();
    if (!candidate || !entry.directory) throw new Error(`Pinned ${name} installation was not found.`);
    const [directory, executablePath, stat] = await Promise.all([
      fs.realpath(entry.directory), fs.realpath(candidate), fs.lstat(candidate),
    ]);
    const relative = path.relative(directory, executablePath);
    if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)
      || !stat.isFile() || stat.isSymbolicLink() || !(stat.mode & 0o111)) {
      throw new Error(`Refusing a non-executable or unconfined ${name} installation path.`);
    }
    executables.push({ name, executablePath });
  }
  return executables;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.platform !== "linux" || process.env.GITHUB_ACTIONS !== "true"
      || process.env.RUNNER_ENVIRONMENT !== "github-hosted") {
      throw new Error("This profile generator is only for the disposable GitHub-hosted Linux CI runner.");
    }
    // CI-only access to the pinned dev dependency's registry resolves the real
    // headless-shell path too; chromium.executablePath() resolves only full Chrome.
    const require = createRequire(import.meta.url);
    const { registry: { registry } } = require("playwright-core/lib/coreBundle");
    process.stdout.write(buildChromiumSandboxProfile(await resolveChromiumExecutables(registry)));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
