import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT_FILES = new Set([".editorconfig", ".gitattributes", ".gitignore", "CHANGELOG.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "LICENSE", "README.md", "RELEASING.md", "SECURITY.md", "modular.schema.json", "package.json", "package-lock.json"]);
const ROOT_DIRECTORIES = new Set([".github", "assets", "bin", "docs", "examples", "scripts", "src", "test", "type-tests"]);
const FORBIDDEN = /(?:^|\/)(?:audit|Modular|node_modules|coverage|dist|\.git|\.env(?:\.[^/]*)?|\.npmrc|\.yarnrc\.yml|\.pnpmfile\.cjs)(?:\/|$)|\.(?:log|tgz|zip|pem|key|p12|pfx)$/i;

export function validateRepositoryPaths(paths) {
  const unique = [...new Set(paths)];
  const errors = [];
  const portable = new Set();
  for (const entry of unique) {
    const top = entry.split("/", 1)[0];
    if (!entry || entry.includes("\\") || entry.split("/").some(part => !part || part === "." || part === ".."
      || /[<>:"|?*]|[. ]$/.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)) || /[\x00-\x1f\x7f]/.test(entry)) {
      errors.push("Git inventory contains a non-portable path.");
      continue;
    }
    if (!(ROOT_FILES.has(entry) || ROOT_DIRECTORIES.has(top)) || FORBIDDEN.test(entry)) errors.push(`Private, generated or unreviewed repository path: ${entry}`);
    if (portable.has(entry.toLowerCase())) errors.push(`Case-colliding repository path: ${entry}`);
    portable.add(entry.toLowerCase());
  }
  for (const required of ["README.md", "LICENSE", "package.json", "package-lock.json", ".gitignore", ".github/workflows/ci.yml", "bin/modular.js", "src/index.js", "examples/basic-site/index.html"]) {
    if (!unique.includes(required)) errors.push(`Required repository file missing: ${required}`);
  }
  return errors;
}

export async function verifyRepository(root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")) {
  const realRoot = await fs.realpath(root);
  const gitRoot = execFileSync("git", ["-C", realRoot, "rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
  if ((await fs.realpath(gitRoot)).toLowerCase() !== realRoot.toLowerCase()) throw new Error("Run repository verification from the Modular Git root.");
  // Cached entries deliberately remain in scope even when .gitignore matches.
  const inventory = execFileSync("git", ["-C", realRoot, "ls-files", "--cached", "--others", "--exclude-standard", "-z"], { maxBuffer: 8 * 1024 * 1024 }).toString("utf8");
  const paths = [...new Set(inventory.split("\0").filter(Boolean))].sort();
  const errors = validateRepositoryPaths(paths);
  for (const relative of paths) {
    const absolute = path.join(realRoot, relative);
    const stat = await fs.lstat(absolute);
    const real = await fs.realpath(absolute);
    const relation = path.relative(realRoot, real);
    if (!stat.isFile() || stat.isSymbolicLink() || relation === ".." || relation.startsWith(`..${path.sep}`) || path.isAbsolute(relation)) {
      errors.push(`Repository entry is not a confined regular file: ${relative}`);
      continue;
    }
    if (stat.size > 2 * 1024 * 1024) errors.push(`Repository file exceeds the 2 MiB review budget: ${relative}`);
    if (/\.(?:js|ts|json|md|ya?ml|html|css|py)$/.test(relative) && stat.size <= 2 * 1024 * 1024) {
      const text = await fs.readFile(absolute, "utf8");
      if (/(?:[A-Za-z]:[\\/]Users[\\/][^\s"'`]+|\/(?:Users|home)\/[^\s"'`]+\/)/.test(text)) errors.push(`Machine-local home path in public source: ${relative}`);
    }
  }
  if (errors.length) throw new Error(errors.join("\n"));
  return { files: paths.length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyRepository();
    console.log(`Repository contract OK: ${result.files} public candidate files; private/generated paths excluded.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
