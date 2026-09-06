import { constants as fsConstants, promises as fs } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileDeviceKey, readPathIdentity, sameFilesystemIdentity } from "./file-identity.js";

export const DEFAULT_IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".next",
  ".nuxt",
  ".svelte-kit",
  ".turbo",
  ".cache",
  ".lhci",
  ".lighthouseci",
  ".parcel-cache",
  ".vite",
  "node_modules",
  "bower_components",
  "coverage",
  "dist",
  "build",
  "lighthouse-report",
  "lighthouse-reports",
  "playwright-report",
  "test-results",
  "blob-report",
  "out",
  "target",
  "vendor",
]);

const BINARY_EXTENSIONS = new Set([
  ".7z", ".avi", ".avif", ".bin", ".bmp", ".class", ".db", ".dll", ".dmg", ".doc", ".docx",
  ".eot", ".exe", ".gif", ".gz", ".ico", ".jar", ".jpeg", ".jpg", ".lockb",
  ".mov", ".mp3", ".mp4", ".ogg", ".otf", ".pdf", ".png", ".rar", ".so", ".sqlite",
  ".sqlite3", ".tar", ".tiff", ".ttf", ".wasm", ".wav", ".webm", ".webp", ".woff", ".woff2", ".zip",
]);

export const WEB_ASSET_EXTENSIONS = new Set([
  ".avif", ".bmp", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".mov", ".mp3", ".mp4",
  ".ogg", ".otf", ".png", ".tiff", ".ttf", ".wasm", ".wav", ".webm", ".webp", ".woff", ".woff2",
]);

const ALWAYS_INCLUDE = new Set([
  ".env", ".env.local", ".env.development", ".env.production", ".npmrc", ".yarnrc",
  "dockerfile", "robots.txt", "sitemap.xml", "package-lock.json", "npm-shrinkwrap.json",
  "yarn.lock", "pnpm-lock.yaml", "bun.lock",
]);

// Presence alone is security-relevant, even when the file is too large to
// load (or binary, as with bun.lockb). Keep a metadata-only descriptor so a
// scanner never turns "not read" into the false claim "does not exist".
const DEPENDENCY_LOCKFILES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
]);

const PACKAGE_MANAGER_CONFIG_FILES = new Set([
  ".npmrc",
  ".yarnrc",
  ".yarnrc.yml",
  ".yarnrc.yaml",
  "pnpm-workspace.yml",
  "pnpm-workspace.yaml",
  "bunfig.toml",
]);

const PRESENCE_SENSITIVE_FILES = new Set([
  ...DEPENDENCY_LOCKFILES,
  ...PACKAGE_MANAGER_CONFIG_FILES,
  "robots.txt",
  "sitemap.xml",
]);

const SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".ts", ".tsx", ".vue", ".svelte", ".astro", ".html", ".htm"]);
const MARKUP_EXTENSIONS = new Set([".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".astro"]);
const STYLE_EXTENSIONS = new Set([".css", ".scss", ".sass", ".less", ".styl"]);

function slash(value) {
  return value.split(path.sep).join("/");
}

function platformKey(value) {
  return process.platform === "win32" ? value.toLowerCase() : value;
}

const PLATFORM_IGNORED_DIRECTORIES = new Set([...DEFAULT_IGNORED_DIRECTORIES].map(platformKey));

function shouldIgnoreDirectory(name, extraIgnores) {
  const key = platformKey(name);
  return PLATFORM_IGNORED_DIRECTORIES.has(key) || extraIgnores.has(key);
}

function isProbablyText(name) {
  return ALWAYS_INCLUDE.has(name.toLowerCase()) || !BINARY_EXTENSIONS.has(path.extname(name).toLowerCase());
}

function fileIdentity(stat) {
  const timestamp = (nanoseconds, milliseconds) => (
    typeof nanoseconds === "bigint"
      ? nanoseconds.toString()
      : String(Math.round(Number(milliseconds) * 1_000_000))
  );
  return {
    dev: fileDeviceKey(stat.dev),
    ino: String(stat.ino),
    size: Number(stat.size),
    mtimeNs: timestamp(stat.mtimeNs, stat.mtimeMs),
    ctimeNs: timestamp(stat.ctimeNs, stat.ctimeMs),
  };
}

function sameFileIdentity(left, right) {
  if (!sameFilesystemIdentity(left, right)) return false;
  return ["size", "mtimeNs", "ctimeNs"]
    .every((key) => left[key] !== undefined && right[key] !== undefined && left[key] === right[key]);
}

function pathInside(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative !== ""
    && relative !== ".."
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

async function hasLinkedPathComponent(root, candidate) {
  const relative = path.relative(root, candidate);
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink()) return true;
  }
  return false;
}

async function safeCanonicalFile(root, candidate) {
  const lexicalRoot = path.resolve(root);
  const lexicalFile = path.resolve(candidate);
  if (!pathInside(lexicalRoot, lexicalFile)) return null;
  const [canonicalRoot, canonicalFile, linked] = await Promise.all([
    fs.realpath(lexicalRoot),
    fs.realpath(lexicalFile),
    hasLinkedPathComponent(lexicalRoot, lexicalFile),
  ]);
  if (linked || !pathInside(canonicalRoot, canonicalFile)) return null;
  return { canonicalRoot, canonicalFile, lexicalRoot, lexicalFile };
}

async function contentDigest(candidate, expectedIdentity, root) {
  let handle;
  try {
    const initialCanonical = await safeCanonicalFile(root, candidate);
    if (!initialCanonical) return null;
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    handle = await fs.open(candidate, fsConstants.O_RDONLY | noFollow);
    const before = await handle.stat({ bigint: true });
    const beforeIdentity = fileIdentity(before);
    if (!before.isFile() || !sameFileIdentity(expectedIdentity, beforeIdentity)) return null;
    const finalCanonical = await safeCanonicalFile(root, candidate);
    if (!finalCanonical || finalCanonical.canonicalFile !== initialCanonical.canonicalFile) return null;

    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    const expectedSize = Number(before.size);
    while (offset < expectedSize) {
      const length = Math.min(buffer.length, expectedSize - offset);
      const { bytesRead } = await handle.read(buffer, 0, length, offset);
      if (bytesRead === 0) return null;
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (offset !== expectedSize || !sameFileIdentity(beforeIdentity, fileIdentity(after))) return null;
    return hash.digest("hex");
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function collectFiles(root, options = {}) {
  const maxFileBytes = options.maxFileBytes ?? 1_500_000;
  const maxFiles = options.maxFiles ?? 20_000;
  const maxTotalBytes = options.maxTotalBytes ?? 128 * 1024 * 1024;
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes <= 0) {
    throw new TypeError("maxFileBytes must be a positive integer.");
  }
  if (!Number.isSafeInteger(maxFiles) || maxFiles <= 0) {
    throw new TypeError("maxFiles must be a positive integer.");
  }
  if (!Number.isSafeInteger(maxTotalBytes) || maxTotalBytes <= 0) {
    throw new TypeError("maxTotalBytes must be a positive integer.");
  }

  const resolvedRoot = path.resolve(root);
  const extraIgnores = new Set((options.ignore ?? []).map((entry) => platformKey(String(entry))));
  const excludedDirectories = (options.excludeDirectories ?? [])
    .map((entry) => path.resolve(resolvedRoot, entry))
    .filter((entry) => entry !== resolvedRoot)
    .map(platformKey);
  const files = [];
  const skipped = { binary: 0, assetMetadata: 0, large: 0, inaccessible: 0, links: 0, limit: 0, totalBytes: 0 };
  let visitedFiles = 0;
  let totalReadableBytes = 0;
  let limitReached = false;

  function isExcludedDirectory(directory) {
    const candidate = platformKey(path.resolve(directory));
    return excludedDirectories.some((excluded) => candidate === excluded || candidate.startsWith(`${excluded}${path.sep}`));
  }

  async function walk(directory) {
    if (limitReached) return;
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      skipped.inaccessible += 1;
      return;
    }

    entries.sort((a, b) => (a.name === b.name ? 0 : a.name < b.name ? -1 : 1));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const lowerName = entry.name.toLowerCase();
      if (entry.isSymbolicLink()) {
        // Never follow repository links: they can escape the selected root and
        // make a static scan read unrelated files. Keep the omission visible
        // unless this is an already-ignored vendor/output directory name.
        if (shouldIgnoreDirectory(entry.name, extraIgnores) || isExcludedDirectory(absolute)) continue;
        visitedFiles += 1;
        if (visitedFiles > maxFiles) {
          skipped.limit += 1;
          limitReached = true;
          return;
        }
        skipped.links += 1;
        if (PACKAGE_MANAGER_CONFIG_FILES.has(lowerName)) {
          files.push({
            absolute,
            relative: slash(path.relative(resolvedRoot, absolute)),
            name: entry.name,
            extension: path.extname(entry.name).toLowerCase(),
            maxFileBytes,
            contentReadable: false,
            skippedReason: "link",
          });
        }
        continue;
      }
      if (entry.isDirectory()) {
        if (!shouldIgnoreDirectory(entry.name, extraIgnores) && !isExcludedDirectory(absolute)) await walk(absolute);
        if (limitReached) return;
        continue;
      }
      visitedFiles += 1;
      if (visitedFiles > maxFiles) {
        skipped.limit += 1;
        limitReached = true;
        return;
      }
      if (!entry.isFile()) continue;
      const preserveAssetMetadata = WEB_ASSET_EXTENSIONS.has(path.extname(lowerName));
      const preserveMetadata = PRESENCE_SENSITIVE_FILES.has(lowerName) || preserveAssetMetadata;
      const probablyText = isProbablyText(entry.name);
      if (!probablyText && !preserveMetadata) {
        skipped.binary += 1;
        continue;
      }

      try {
        const stat = await readPathIdentity(absolute);
        const size = Number(stat.size);
        if (stat.isSymbolicLink()) {
          skipped.links += 1;
          if (PACKAGE_MANAGER_CONFIG_FILES.has(lowerName)) {
            files.push({
              absolute,
              relative: slash(path.relative(resolvedRoot, absolute)),
              name: entry.name,
              extension: path.extname(entry.name).toLowerCase(),
              maxFileBytes,
              contentReadable: false,
              skippedReason: "link",
            });
          }
          continue;
        }
        if (!stat.isFile()) continue;
        const identity = fileIdentity(stat);
        if (!probablyText && preserveAssetMetadata) {
          skipped.binary += 1;
          skipped.assetMetadata += 1;
          files.push({
            absolute,
            relative: slash(path.relative(resolvedRoot, absolute)),
            name: entry.name,
            extension: path.extname(entry.name).toLowerCase(),
            size,
            identity,
            maxFileBytes,
            contentReadable: false,
            skippedReason: "binary",
            assetMetadata: true,
          });
          continue;
        }
        if (size > maxFileBytes) {
          skipped.large += 1;
          if (preserveMetadata) {
            files.push({
              absolute,
              relative: slash(path.relative(resolvedRoot, absolute)),
              name: entry.name,
              extension: path.extname(entry.name).toLowerCase(),
              size,
              maxFileBytes,
              contentReadable: false,
              skippedReason: "large",
            });
          }
          continue;
        }
        if (!probablyText && DEPENDENCY_LOCKFILES.has(lowerName)) {
          skipped.binary += 1;
          files.push({
            absolute,
            relative: slash(path.relative(resolvedRoot, absolute)),
            name: entry.name,
            extension: path.extname(entry.name).toLowerCase(),
            size,
            maxFileBytes,
            contentReadable: false,
            skippedReason: "binary",
          });
          continue;
        }
        if (totalReadableBytes + size > maxTotalBytes) {
          skipped.totalBytes += 1;
          limitReached = true;
          return;
        }
        const digest = await contentDigest(absolute, identity, resolvedRoot);
        if (!digest) {
          skipped.inaccessible += 1;
          continue;
        }
        totalReadableBytes += size;
        files.push({
          absolute,
          relative: slash(path.relative(resolvedRoot, absolute)),
          name: entry.name,
          extension: path.extname(entry.name).toLowerCase(),
          size,
          identity,
          digest,
          maxFileBytes,
        });
      } catch {
        skipped.inaccessible += 1;
        if (PACKAGE_MANAGER_CONFIG_FILES.has(lowerName)) {
          files.push({
            absolute,
            relative: slash(path.relative(resolvedRoot, absolute)),
            name: entry.name,
            extension: path.extname(entry.name).toLowerCase(),
            maxFileBytes,
            contentReadable: false,
            skippedReason: "inaccessible",
          });
        }
      }
    }
  }

  await walk(resolvedRoot);
  return { files, skipped, totalReadableBytes, maxTotalBytes };
}

/**
 * Revalidates a metadata-only descriptor without reading asset contents.
 * Returns a minimal immutable snapshot or null when the file moved, changed,
 * became linked, or escaped the selected repository after discovery.
 */
export async function verifyFileMetadata(file, options = {}) {
  if (!file?.identity || typeof file.absolute !== "string" || options.root === undefined) return null;
  try {
    const root = path.resolve(String(options.root));
    const candidate = path.resolve(file.absolute);
    const canonical = await safeCanonicalFile(root, candidate);
    if (!canonical) return null;
    const stat = await readPathIdentity(candidate);
    if (!stat.isFile() || stat.isSymbolicLink()) return null;
    const identity = fileIdentity(stat);
    if (!sameFileIdentity(file.identity, identity)) return null;
    return Object.freeze({
      absolute: candidate,
      relative: slash(path.relative(root, candidate)),
      extension: path.extname(candidate).toLowerCase(),
      size: Number(stat.size),
    });
  } catch {
    return null;
  }
}

export async function readTextFile(file, options = {}) {
  if (file?.contentReadable === false) return null;
  let handle;
  try {
    const candidate = path.resolve(String(file?.absolute ?? ""));
    const root = options.root === undefined ? null : path.resolve(String(options.root));
    const initialCanonical = root ? await safeCanonicalFile(root, candidate) : null;
    if (root && !initialCanonical) return null;
    const lexical = await readPathIdentity(candidate);
    if (!lexical.isFile() || lexical.isSymbolicLink()) return null;

    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    handle = await fs.open(candidate, fsConstants.O_RDONLY | noFollow);
    const before = await handle.stat({ bigint: true });
    const beforeIdentity = fileIdentity(before);
    if (!before.isFile() || !sameFileIdentity(fileIdentity(lexical), beforeIdentity)) return null;
    if (file.identity && !sameFileIdentity(file.identity, beforeIdentity)) return null;
    if (root) {
      const finalCanonical = await safeCanonicalFile(root, candidate);
      if (!finalCanonical || finalCanonical.canonicalFile !== initialCanonical.canonicalFile) return null;
    }
    const maximum = Number.isSafeInteger(file.maxFileBytes) && file.maxFileBytes > 0
      ? file.maxFileBytes
      : 1_500_000;
    const beforeSize = Number(before.size);
    if (!before.isFile() || beforeSize > maximum) return null;
    if (Number.isSafeInteger(file.size) && beforeSize !== file.size) return null;

    const buffer = Buffer.alloc(beforeSize);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameFileIdentity(beforeIdentity, fileIdentity(after)) || offset !== beforeSize) return null;
    if (buffer.includes(0)) return null;
    if (typeof file.digest === "string"
      && createHash("sha256").update(buffer).digest("hex") !== file.digest) return null;
    return buffer.toString("utf8");
  } catch {
    return null;
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

export function lineOf(text, index) {
  if (index < 0) return null;
  let line = 1;
  for (let i = 0; i < index; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

export function isSourceFile(file) {
  return SOURCE_EXTENSIONS.has(file.extension);
}

export function isMarkupFile(file) {
  return MARKUP_EXTENSIONS.has(file.extension);
}

export function isStyleFile(file) {
  return STYLE_EXTENSIONS.has(file.extension);
}

export function isWebAssetFile(file) {
  return Boolean(file?.assetMetadata) && WEB_ASSET_EXTENSIONS.has(String(file.extension).toLowerCase());
}

export function isTestFile(file) {
  return /(^|\/)(__tests__|test|tests|spec|specs)(\/|$)|\.(test|spec)\.[^.]+$/i.test(file.relative);
}
