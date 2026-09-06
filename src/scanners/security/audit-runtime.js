import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { normalizeName, unique } from "./shared.js";
import { sanitizedAuditManifest, lockfilePrivacyBlockReason } from "./audit-privacy.js";

const MAX_AUDIT_LOCKFILE_BYTES = 64 * 1024 * 1024;

export function runExecFile(command, args, options) {
  return new Promise((resolve) => {
    try {
      execFile(command, args, options, (error, stdout, stderr) => {
        resolve({ error, stdout: String(stdout ?? ""), stderr: String(stderr ?? "") });
      });
    } catch (error) {
      resolve({ error, stdout: "", stderr: "" });
    }
  });
}

function pathInsideOrEqual(parent, candidate) {
  const relation = path.relative(parent, candidate);
  return relation === "" || (relation !== ".." && !relation.startsWith(`..${path.sep}`) && !path.isAbsolute(relation));
}

async function pathResolvesInsideWorkspace(candidate, workspaceRoot) {
  if (!workspaceRoot) return false;
  const lexicalRoot = path.resolve(workspaceRoot);
  const lexicalCandidate = path.resolve(candidate);
  if (pathInsideOrEqual(lexicalRoot, lexicalCandidate)) return true;
  try {
    const [realRoot, realCandidate] = await Promise.all([fs.realpath(lexicalRoot), fs.realpath(lexicalCandidate)]);
    return pathInsideOrEqual(realRoot, realCandidate);
  } catch {
    return false;
  }
}

async function safeAuditPathEntries(workspaceRoot) {
  const entries = [];
  for (const rawEntry of String(process.env.PATH ?? "").split(path.delimiter)) {
    const entry = rawEntry.trim().replace(/^"(.*)"$/, "$1");
    // Empty and relative PATH entries implicitly search the scan cwd. Never let an
    // opted-in advisory lookup turn repository files into executable commands.
    if (!entry || !path.isAbsolute(entry)) continue;
    const absoluteEntry = path.resolve(entry);
    if (await pathResolvesInsideWorkspace(absoluteEntry, workspaceRoot)) continue;
    if (!entries.some((existing) => path.relative(existing, absoluteEntry) === "")) entries.push(absoluteEntry);
  }
  return entries;
}

async function readableAuditExecutable(candidate, workspaceRoot) {
  if (!path.isAbsolute(candidate) || await pathResolvesInsideWorkspace(candidate, workspaceRoot)) return false;
  try {
    const stat = await fs.stat(candidate);
    return stat.isFile();
  } catch {
    return false;
  }
}

function expandShimScriptReference(reference, contents, candidate) {
  const directory = path.dirname(candidate);
  let expanded = reference
    .replace(/%~dp0/gi, `${directory}${path.sep}`)
    .replace(/\$PSScriptRoot\b/gi, directory);
  if (/%dp0%/i.test(expanded)) {
    // npm's cmd-shim initializes dp0 in :find_dp0. Read the known directory
    // assignment without executing the batch file or expanding environment vars.
    const assignments = [...contents.matchAll(/\bset\s+(?:\/[ap]\s+)?"?dp0\s*=[^\r\n]*/gi)];
    if (assignments.length !== 1
      || !/^set\s+"?dp0=%~dp0"?\s*$/i.test(assignments[0][0])) return null;
    expanded = expanded.replace(/%dp0%/gi, `${directory}${path.sep}`);
  }
  if (/\$basedir\b/i.test(expanded)) {
    // npm's PowerShell shim derives basedir from its own path. Reject altered
    // or additional assignments instead of interpreting arbitrary PowerShell.
    const assignments = [...contents.matchAll(/\$basedir\s*(?:[+?]?=)[^\r\n]*/gi)];
    if (assignments.length !== 1
      || !/^\$basedir\s*=\s*Split-Path\s+\$MyInvocation\.MyCommand\.Definition\s+-Parent\s*$/i.test(assignments[0][0])
      || /\b(?:Set|New|Clear|Remove)-Variable\b|\bSet-Item\s+(?:-Path\s+)?["']?variable:/i.test(contents)) return null;
    expanded = expanded.replace(/\$basedir\b/gi, directory);
  }
  return /%[^%]+%|\$[A-Za-z_]/.test(expanded) ? null : expanded;
}

export async function resolveAuditInvocation(manager, args, workspaceRoot) {
  const safePathEntries = await safeAuditPathEntries(workspaceRoot);
  const safePath = safePathEntries.join(path.delimiter);

  const environmentCli = process.env.npm_execpath;
  if (manager === "npm" && environmentCli && path.isAbsolute(environmentCli)
    && /npm-cli\.(?:[cm]?js)$/i.test(environmentCli)
    && await readableAuditExecutable(environmentCli, workspaceRoot)) {
    return { command: process.execPath, args: [environmentCli, ...args], path: safePath };
  }

  const besideNode = manager === "npm"
    ? path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js")
    : null;
  if (besideNode && await readableAuditExecutable(besideNode, workspaceRoot)) {
    return { command: process.execPath, args: [besideNode, ...args], path: safePath };
  }

  if (process.platform !== "win32") {
    for (const directory of safePathEntries) {
      const candidate = path.join(directory, manager);
      if (await readableAuditExecutable(candidate, workspaceRoot)) {
        return { command: candidate, args, path: safePath };
      }
    }
    return null;
  }

  const pathExtensions = unique([
    ...String(process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";")
      .map((extension) => extension.trim().toLowerCase())
      .filter((extension) => [".com", ".exe", ".bat", ".cmd"].includes(extension)),
    ".ps1",
  ]);
  for (const directory of safePathEntries) {
    for (const extension of pathExtensions) {
      const candidate = path.join(directory, `${manager}${extension}`);
      if (!await readableAuditExecutable(candidate, workspaceRoot)) continue;
      if (/\.(?:com|exe)$/i.test(candidate)) return { command: candidate, args, path: safePath };

      let contents;
      try {
        contents = await fs.readFile(candidate, "utf8");
      } catch {
        continue;
      }
      const scriptCandidates = [...contents.matchAll(/["']([^"'\r\n]+\.(?:[cm]?js))["']/gi)]
        .map((match) => match[1])
        .filter((entry) => !/prefix/i.test(path.basename(entry)));
      for (const scriptReference of scriptCandidates) {
        const expanded = expandShimScriptReference(scriptReference, contents, candidate);
        if (expanded === null) continue;
        const scriptPath = path.resolve(path.dirname(candidate), expanded);
        if (await readableAuditExecutable(scriptPath, workspaceRoot)) {
          return { command: process.execPath, args: [scriptPath, ...args], path: safePath };
        }
      }
    }
  }
  return null;
}

async function repositoryFileForAudit(root, relative) {
  const lexicalRoot = path.resolve(root);
  const lexicalFile = path.resolve(lexicalRoot, String(relative ?? ""));
  if (!pathInsideOrEqual(lexicalRoot, lexicalFile)) {
    throw new Error("The selected dependency lockfile is outside the repository.");
  }
  const [realRoot, realFile] = await Promise.all([fs.realpath(lexicalRoot), fs.realpath(lexicalFile)]);
  if (!pathInsideOrEqual(realRoot, realFile)) {
    throw new Error("The selected dependency lockfile resolves outside the repository.");
  }
  const stat = await fs.stat(realFile);
  if (!stat.isFile()) throw new Error("The selected dependency lockfile is not a regular file.");
  return realFile;
}

async function copyAuditLockfile(source, destination) {
  const sourceHandle = await fs.open(source, "r");
  let destinationHandle;
  try {
    const stat = await sourceHandle.stat();
    if (stat.size > MAX_AUDIT_LOCKFILE_BYTES) {
      const error = new Error(`lockfile exceeds the ${MAX_AUDIT_LOCKFILE_BYTES / (1024 * 1024)} MiB isolated-audit limit`);
      error.code = "AUDIT_LOCKFILE_TOO_LARGE";
      throw error;
    }
    destinationHandle = await fs.open(destination, "wx", 0o600);
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let copied = 0;
    for (;;) {
      const { bytesRead } = await sourceHandle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      copied += bytesRead;
      if (copied > MAX_AUDIT_LOCKFILE_BYTES) {
        const error = new Error(`lockfile exceeds the ${MAX_AUDIT_LOCKFILE_BYTES / (1024 * 1024)} MiB isolated-audit limit`);
        error.code = "AUDIT_LOCKFILE_TOO_LARGE";
        throw error;
      }
      let written = 0;
      while (written < bytesRead) {
        const result = await destinationHandle.write(buffer, written, bytesRead - written, null);
        written += result.bytesWritten;
      }
    }
  } catch (error) {
    await fs.rm(destination, { force: true }).catch(() => {});
    throw error;
  } finally {
    await destinationHandle?.close().catch(() => {});
    await sourceHandle.close().catch(() => {});
  }
}

export async function createAuditSandbox(root, auditContext, auditCommand) {
  const sandboxRoot = await fs.mkdtemp(path.join(os.tmpdir(), "modular-dependency-audit-"));
  try {
    const configuration = path.join(sandboxRoot, "config");
    const cache = path.join(sandboxRoot, "cache");
    const temporary = path.join(sandboxRoot, "tmp");
    await Promise.all([
      fs.mkdir(configuration, { recursive: true }),
      fs.mkdir(cache, { recursive: true }),
      fs.mkdir(temporary, { recursive: true }),
    ]);
    await fs.writeFile(
      path.join(sandboxRoot, "package.json"),
      `${JSON.stringify(sanitizedAuditManifest(auditContext.manifest), null, 2)}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    const sourceLockfile = await repositoryFileForAudit(root, auditCommand.lockfile.relative);
    const lockfileName = normalizeName(auditCommand.lockfile);
    const isolatedLockfile = path.join(sandboxRoot, lockfileName);
    await copyAuditLockfile(sourceLockfile, isolatedLockfile);
    const isolatedLockfileContents = await fs.readFile(isolatedLockfile, "utf8");
    const privacyBlockReason = lockfilePrivacyBlockReason(isolatedLockfileContents);
    if (privacyBlockReason) {
      throw Object.assign(new Error(privacyBlockReason), { code: "AUDIT_PRIVACY_BLOCKED" });
    }
    const userConfig = path.join(configuration, "user.npmrc");
    const globalConfig = path.join(configuration, "global.npmrc");
    const yarnConfig = path.join(sandboxRoot, ".modular-empty-yarnrc.yml");
    await fs.writeFile(userConfig, "ignore-scripts=true\n", { encoding: "utf8", mode: 0o600 });
    await fs.writeFile(globalConfig, "ignore-scripts=true\n", { encoding: "utf8", mode: 0o600 });
    await fs.writeFile(yarnConfig, "", { encoding: "utf8", mode: 0o600 });
    return {
      cwd: sandboxRoot,
      cache,
      temporary,
      userConfig,
      globalConfig,
      yarnConfig,
      async cleanup() {
        await fs.rm(sandboxRoot, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await fs.rm(sandboxRoot, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

export function isolatedAuditEnvironment(invocation, sandbox) {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    const normalized = name.toLowerCase();
    if (normalized === "path"
      || normalized === "node_options"
      || normalized === "node_path"
      || normalized === "init_cwd"
      || normalized.startsWith("npm_config_")
      || normalized.startsWith("npm_package_")
      || normalized.startsWith("pnpm_")
      || normalized.startsWith("yarn_")
      || normalized.startsWith("bun_")) {
      delete environment[name];
    }
  }
  environment.PATH = invocation.path;
  environment.COREPACK_HOME = path.join(sandbox.cache, "corepack");
  environment.INIT_CWD = sandbox.cwd;
  environment.TMPDIR = sandbox.temporary;
  environment.TMP = sandbox.temporary;
  environment.TEMP = sandbox.temporary;
  environment.npm_config_userconfig = sandbox.userConfig;
  environment.NPM_CONFIG_USERCONFIG = sandbox.userConfig;
  environment.npm_config_globalconfig = sandbox.globalConfig;
  environment.NPM_CONFIG_GLOBALCONFIG = sandbox.globalConfig;
  environment.npm_config_cache = path.join(sandbox.cache, "npm");
  environment.NPM_CONFIG_CACHE = path.join(sandbox.cache, "npm");
  environment.npm_config_ignore_scripts = "true";
  environment.NPM_CONFIG_IGNORE_SCRIPTS = "true";
  environment.npm_config_ignore_pnpmfile = "true";
  environment.NPM_CONFIG_IGNORE_PNPMFILE = "true";
  environment.YARN_RC_FILENAME = path.basename(sandbox.yarnConfig);
  environment.PNPM_HOME = path.join(sandbox.cache, "pnpm-home");
  environment.BUN_INSTALL_CACHE_DIR = path.join(sandbox.cache, "bun");
  return environment;
}
