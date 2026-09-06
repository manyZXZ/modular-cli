export function sanitizedAuditManifest(manifest) {
  const sanitized = {
    name: "modular-isolated-dependency-audit",
    version: "0.0.0",
    private: true,
  };
  for (const sectionName of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const section = manifest?.[sectionName];
    if (!section || typeof section !== "object" || Array.isArray(section)) continue;
    sanitized[sectionName] = Object.fromEntries(
      Object.entries(section).filter(([name, version]) => (
        isPublicRegistryPackageName(name)
        && isPublicRegistryDependencySpecifier(version)
      )),
    );
  }
  return sanitized;
}

const PUBLIC_REGISTRY_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);

function isOfficialPublicRegistry(value) {
  try {
    const parsed = new URL(String(value).trim().replace(/^['"]|['"]$/g, ""));
    return parsed.protocol === "https:"
      && PUBLIC_REGISTRY_HOSTS.has(parsed.hostname.toLowerCase())
      && parsed.username === ""
      && parsed.password === ""
      && parsed.port === ""
      && parsed.search === "";
  } catch {
    return false;
  }
}

function isPublicRegistryPackageName(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 214) return false;
  const segment = "[A-Za-z0-9][A-Za-z0-9._~-]*";
  return new RegExp(`^(?:${segment}|@${segment}/${segment})$`).test(value);
}

function isPublicRegistryVersionRange(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) return false;
  if (value !== value.trim() || /[\r\n\t]/.test(value)) return false;
  if (value === "." || value === "..") return false;
  if (/^(?:\.|\.\.|~)[\\/]|[\\/]|:|@|\$|%/.test(value)) return false;
  if (/\.(?:tar(?:\.gz)?|tgz|zip)$/i.test(value)) return false;
  return /^[A-Za-z0-9*^~<>=|.,+_ -]+$/.test(value);
}

function parseNpmAlias(value) {
  if (!value.startsWith("npm:")) return null;
  const body = value.slice(4);
  let separator = -1;
  if (body.startsWith("@")) {
    const slash = body.indexOf("/");
    if (slash < 2) return null;
    separator = body.indexOf("@", slash + 1);
  } else {
    separator = body.indexOf("@");
  }
  const packageName = separator === -1 ? body : body.slice(0, separator);
  const range = separator === -1 ? "latest" : body.slice(separator + 1);
  return isPublicRegistryPackageName(packageName) && isPublicRegistryVersionRange(range)
    ? { packageName, range }
    : null;
}

function isPublicRegistryDependencySpecifier(value) {
  if (typeof value !== "string") return false;
  return value.startsWith("npm:") ? parseNpmAlias(value) !== null : isPublicRegistryVersionRange(value);
}

function maskIntegrityDigests(contents) {
  // Registry integrity metadata is Base64, where // is an ordinary character
  // pair. Exempt only complete, canonical digests in integrity fields; source
  // URLs and arbitrary strings must still pass the privacy checks below.
  const field = /\bintegrity["']?\s*(?::\s*|\s+)(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^,}\]\r\n]+))/gi;
  const digestBytes = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };
  return contents.replace(field, (match, doubleQuoted, singleQuoted, bare) => {
    const value = (doubleQuoted ?? singleQuoted ?? bare).trim();
    const digests = value.split(/\s+/);
    if (!value || !digests.every((digest) => {
      const parts = /^(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/.exec(digest);
      if (!parts) return false;
      const bytes = Buffer.from(parts[2], "base64");
      const canonical = bytes.toString("base64");
      return bytes.length === digestBytes[parts[1]]
        && (canonical === parts[2] || canonical.replace(/=+$/, "") === parts[2]);
    })) return match;
    const offset = match.indexOf(value);
    return `${match.slice(0, offset)}${" ".repeat(value.length)}${match.slice(offset + value.length)}`;
  });
}

export function lockfilePrivacyBlockReason(contents) {
  if (typeof contents !== "string" || contents.includes("\u0000") || contents.includes("\uFFFD")) {
    return "was not sent because the lockfile could not be safely inspected as UTF-8 text";
  }

  // JSON permits escaped slashes, which otherwise conceal a network location
  // from a raw-text scan. Obfuscated URI punctuation is not produced by the
  // supported package managers, so fail closed instead of attempting to guess.
  if (/\\(?:u00(?:2f|3a|40|5c)|x(?:2f|3a|40|5c))/i.test(contents)) {
    return "was not sent because the lockfile contains an encoded or obfuscated dependency source";
  }
  const normalized = maskIntegrityDigests(contents.replace(/\\\//g, "/"));
  let unsafeUrl = false;
  const withoutUrls = normalized.replace(
    /\b[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s"'<>`]+/gi,
    (candidate) => {
      const cleaned = candidate.replace(/[),\]}]+$/, "");
      if (!isOfficialPublicRegistry(cleaned)) unsafeUrl = true;
      return " ".repeat(candidate.length);
    },
  );
  if (unsafeUrl) {
    return "was not sent because the lockfile references a non-public registry or direct dependency source";
  }

  if (/\$\{[^}\r\n]+\}|%[A-Za-z_][A-Za-z0-9_]*%/.test(withoutUrls)) {
    return "was not sent because the lockfile contains a dynamic dependency source";
  }
  if (/%(?:2f|3a|40|5c)/i.test(withoutUrls)) {
    return "was not sent because the lockfile contains an encoded or obfuscated dependency source";
  }
  if (/\/\//.test(withoutUrls)) {
    return "was not sent because the lockfile references a protocol-relative dependency source";
  }
  if (/\b(?:git|hg|svn)@[A-Za-z0-9.-]+:[^\s"',}\]]+/i.test(withoutUrls)
    || /\b[A-Za-z0-9._-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:[^\s"',}\]]+/i.test(withoutUrls)) {
    return "was not sent because the lockfile references an SSH or repository dependency source";
  }
  if (/(?:^|[^A-Za-z0-9+.-])(?:github|gitlab|bitbucket|gist|git(?:\+[A-Za-z0-9+.-]+)?|ssh|file|link|portal|workspace|patch|path):(?=[^\s,}\]])/im.test(withoutUrls)) {
    return "was not sent because the lockfile references a local, workspace, Git, or non-registry dependency source";
  }
  const sourceSchemes = [...withoutUrls.matchAll(/(?:^|[^A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*):(?=[^\s,}\]])/g)];
  if (sourceSchemes.some((match) => match[1].toLowerCase() !== "npm")) {
    return "was not sent because the lockfile references a dependency source outside the public npm registry";
  }
  if (/(?:^|[\s"'(=:[,{])(?:\.\.?[\\/]|~[\\/]|[A-Za-z]:[\\/]|\\\\)/m.test(withoutUrls)) {
    return "was not sent because the lockfile references a relative or absolute filesystem dependency source";
  }
  if (/["']?link["']?\s*:\s*true\b/i.test(withoutUrls)) {
    return "was not sent because the lockfile contains a linked filesystem dependency";
  }

  const sourceField = /["']?(resolved|tarball|from|specifier|version|resolution|path)["']?\s*:\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^,\s}\]\r\n]+))/gi;
  for (const match of withoutUrls.matchAll(sourceField)) {
    const field = match[1].toLowerCase();
    const value = String(match[2] ?? match[3] ?? match[4] ?? "").trim();
    if (!value || value === "null" || value.startsWith("{") || value.startsWith("[")) continue;
    if (value === "." || value === "..") {
      return "was not sent because the lockfile contains a relative filesystem dependency source";
    }
    if (field === "path" || field === "resolved" || field === "tarball") {
      return "was not sent because the lockfile contains a dependency source outside an official public registry";
    }
    // Slashes in normal lockfile versions are limited to scoped package names
    // (for example pnpm peer suffixes). Any remaining slash denotes a path or
    // repository shorthand such as owner/repository.
    const withoutScopedNames = value.replace(/@[A-Za-z0-9][A-Za-z0-9._~-]*\/[A-Za-z0-9][A-Za-z0-9._~-]*/g, "@scoped-package");
    if (/[\\/]/.test(withoutScopedNames)) {
      return "was not sent because the lockfile contains a path or repository dependency reference";
    }
  }
  return null;
}

function isPackageManagerConfig(file) {
  return /(?:^|\/)(?:\.npmrc|\.yarnrc(?:\.ya?ml)?|pnpm-workspace\.ya?ml|bunfig\.toml)$/i
    .test(String(file?.relative ?? "").replace(/\\/g, "/"));
}

export function dependencyAuditPrivacyBlockReason(auditContext, readableContents, inventoryFiles) {
  const manifest = auditContext.manifest ?? {};
  if (manifest.publishConfig?.registry) {
    return "was not sent because the manifest declares a custom publication registry";
  }
  for (const sectionName of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const section = manifest[sectionName];
    if (section === undefined) continue;
    if (!section || typeof section !== "object" || Array.isArray(section)) {
      return "was not sent because the manifest contains a malformed dependency section";
    }
    for (const [name, version] of Object.entries(section)) {
      if (!isPublicRegistryPackageName(name) || !isPublicRegistryDependencySpecifier(version)) {
        return "was not sent because the manifest contains a dependency that is not an unambiguous public-registry package and version";
      }
    }
  }

  const managerConfigs = readableContents.filter(({ file }) => isPackageManagerConfig(file));
  const readableConfigPaths = new Set(managerConfigs.map(({ file }) => (
    String(file.relative).replace(/\\/g, "/").toLowerCase()
  )));
  const hiddenManagerConfig = inventoryFiles.find((file) => (
    isPackageManagerConfig(file)
    && (file.contentReadable === false
      || !readableConfigPaths.has(String(file.relative).replace(/\\/g, "/").toLowerCase()))
  ));
  if (hiddenManagerConfig) {
    return "was not sent because a repository package-manager configuration file is large, unreadable, or linked and could not be safely inspected";
  }
  for (const { text } of managerConfigs) {
    if (text.includes("\uFFFD")) {
      return "was not sent because a repository package-manager configuration file could not be safely decoded as UTF-8";
    }
    if (/(?:_auth(?:Token)?|npmAuthToken|npmAlwaysAuth|always-auth)\s*[:=]/i.test(text)) {
      return "was not sent because repository package-manager configuration contains registry authentication settings";
    }
    const registryValues = [...text.matchAll(/(?:^|\n)\s*(?:@[^:\s]+:)?(?:registry|npmRegistryServer)\s*[:=]\s*([^#\r\n]+)/gi)];
    if (registryValues.some((match) => !isOfficialPublicRegistry(match[1]))) {
      return "was not sent because repository package-manager configuration selects a custom or dynamic registry";
    }
    if (/\bnpmScopes\s*:/i.test(text)) {
      return "was not sent because repository package-manager configuration defines scoped registry behavior";
    }
  }

  return null;
}
