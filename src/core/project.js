import path from "node:path";
import { readTextFile } from "./files.js";

const UI_SOURCE_EXTENSIONS = new Set([".astro", ".jsx", ".svelte", ".tsx", ".vue"]);

const APPLICATION_FRAMEWORKS = [
  {
    name: "Next.js",
    dependencies: ["next"],
    configs: [/^next\.config\.(?:js|mjs|cjs|ts|mts|cts)$/],
  },
  {
    name: "Nuxt",
    dependencies: ["nuxt", "nuxt3", "@nuxt/core"],
    configs: [/^nuxt\.config\.(?:js|mjs|cjs|ts|mts|cts)$/],
  },
  {
    name: "Astro",
    dependencies: ["astro"],
    configs: [/^astro\.config\.(?:js|mjs|cjs|ts|mts|cts)$/],
  },
  {
    name: "Gatsby",
    dependencies: ["gatsby"],
    configs: [/^gatsby-config\.(?:js|mjs|cjs|ts|mts|cts)$/],
  },
  {
    name: "Remix",
    dependencyPrefixes: ["@remix-run/"],
    configs: [/^remix\.config\.(?:js|mjs|cjs|ts|mts|cts)$/],
  },
  {
    name: "SvelteKit",
    dependencies: ["@sveltejs/kit"],
    configs: [/^svelte\.config\.(?:js|mjs|cjs|ts|mts|cts)$/],
  },
];

const WEB_SCRIPT_PATTERN = /(?:^|[\s;&|])(?:vite(?:\s+(?:dev|build|preview))?|next\s+(?:dev|build|start)|nuxt(?:i)?\s+(?:dev|build|start|preview)|astro\s+(?:dev|build|preview)|gatsby\s+(?:develop|build|serve)|remix(?:-serve|\s+vite:dev|\s+build)|ng\s+(?:serve|build)|react-scripts\s+(?:start|build)|vue-cli-service\s+(?:serve|build)|webpack(?:-dev-server)?(?:\s|$)|parcel(?:\s|$)|http-server(?:\s|$)|serve\s+(?:-|\.?\/|dist|build|public))/i;
const DOM_PATTERN = /\b(?:document\.(?:getElementById|querySelector|createElement)|window\.(?:addEventListener|location)|createRoot\s*\(|hydrateRoot\s*\(|createApp\s*\([^)]*\)\.mount\s*\()/;

const BACKEND_DEPENDENCIES = new Set([
  "@hapi/hapi",
  "@nestjs/core",
  "express",
  "fastify",
  "koa",
  "restify",
]);

const DESKTOP_APP_DEPENDENCIES = new Set([
  "electron",
  "@tauri-apps/api",
  "@tauri-apps/cli",
]);

const NON_PRODUCTION_DETECTION_SEGMENTS = new Set([
  ".storybook",
  "__fixtures__",
  "__generated__",
  "__mocks__",
  "__snapshots__",
  "__tests__",
  "coverage",
  "docs",
  "documentation",
  "fixture",
  "fixtures",
  "generated",
  "mocks",
  "snapshot",
  "snapshots",
  "spec",
  "specs",
  "stories",
  "storybook",
  "storybook-static",
  "test",
  "test-results",
  "tests",
]);

function isDetectionRelevant(relative) {
  const normalized = relative.toLowerCase().replace(/\\/g, "/");
  // Complete apps under top-level test/docs/showcase containers are evidence
  // about that auxiliary project, not the repository being classified.
  const firstSegment = normalized.split("/", 1)[0];
  if (NON_PRODUCTION_DETECTION_SEGMENTS.has(firstSegment)
    || /^(?:examples?|demos?)$/.test(firstSegment)) return false;
  // Once inside a production workspace, route names such as docs, test,
  // generated, demo, and examples are all legitimate URL segments.
  if (/(?:^|\/)(?:src\/)?(?:app|pages|routes)\//.test(normalized)) return true;
  if (/\.(?:fixture|stories?|story|test|spec|snap)(?:\.[^.]+)+$/.test(normalized)) return false;
  return !normalized.split("/").some((segment) => NON_PRODUCTION_DETECTION_SEGMENTS.has(segment));
}

function clamp(value, minimum, maximum) {
  return Math.min(maximum, Math.max(minimum, value));
}

function normalizeRelative(root, file) {
  const supplied = typeof file === "string" ? file : file?.absolute ?? file?.relative;
  if (!supplied) return null;
  const absolute = path.isAbsolute(supplied)
    ? path.resolve(supplied)
    : insideRoot(root, supplied);
  if (!absolute) return null;

  if (typeof file === "object" && file?.absolute && file?.relative) {
    const declared = insideRoot(root, file.relative);
    if (!declared || path.relative(absolute, declared) !== "") return null;
  }

  return path.relative(root, absolute).replace(/\\/g, "/").replace(/^\.\/+/, "");
}

function insideRoot(root, relative) {
  const absolute = path.resolve(root, relative);
  const relation = path.relative(root, absolute);
  return relation !== ".." && !relation.startsWith(`..${path.sep}`) && !path.isAbsolute(relation)
    ? absolute
    : null;
}

async function readProjectFile(root, relative, limit = 512_000) {
  const absolute = insideRoot(root, relative);
  if (!absolute) return null;
  return readTextFile({
    absolute,
    relative,
    name: path.basename(relative),
    extension: path.extname(relative).toLowerCase(),
    maxFileBytes: limit,
  }, { root });
}

function isValidHtmlDocument(source) {
  if (!source) return false;
  const withoutComments = source.replace(/<!--[^]*?-->/g, "");
  const hasHtml = /<html(?:\s|>)/i.test(withoutComments);
  const hasBody = /<body(?:\s|>)/i.test(withoutComments);
  const hasDoctype = /<!doctype\s+html(?:\s|>)/i.test(withoutComments);
  const hasPageMarkup = /<(?:a|article|button|div|footer|form|h1|header|img|main|nav|p|script|section)(?:\s|>)/i.test(withoutComments);
  return hasBody && hasPageMarkup && (hasHtml || hasDoctype);
}

function dependenciesFromSections(manifest, sectionNames) {
  return new Set(
    sectionNames
      .map((sectionName) => manifest[sectionName])
      .filter((section) => section && typeof section === "object")
      .flatMap((section) => Object.keys(section))
      .map((name) => name.toLowerCase()),
  );
}

function installedDependencies(manifest) {
  return dependenciesFromSections(manifest, ["dependencies", "devDependencies", "optionalDependencies"]);
}

function peerDependencies(manifest) {
  return dependenciesFromSections(manifest, ["peerDependencies"]);
}

function hasAnyDependency(dependencies, names) {
  return names?.some((name) => dependencies.has(name)) ?? false;
}

function hasDependencyPrefix(dependencies, prefixes) {
  return prefixes?.some((prefix) => [...dependencies].some((name) => name.startsWith(prefix))) ?? false;
}

function hasMatchingConfig(fileNames, patterns) {
  return patterns.some((pattern) => fileNames.some((name) => pattern.test(path.posix.basename(name))));
}

function extensionOf(relative) {
  return path.posix.extname(relative).toLowerCase();
}

async function findSourceMatching(root, paths, pattern, limit) {
  const batchSize = 12;
  for (let start = 0; start < paths.length; start += batchSize) {
    const batch = paths.slice(start, start + batchSize);
    const sources = await Promise.all(batch.map((relative) => readProjectFile(root, relative, limit)));
    const matchIndex = sources.findIndex((source) => source && pattern.test(source));
    if (matchIndex !== -1) return batch[matchIndex];
  }
  return null;
}

async function mapInBatches(items, mapper, batchSize = 16) {
  const results = [];
  for (let start = 0; start < items.length; start += batchSize) {
    results.push(...await Promise.all(items.slice(start, start + batchSize).map(mapper)));
  }
  return results;
}

/**
 * Estimate whether a collected repository is a website project.
 *
 * Confidence is a 0..1 website-likelihood score, rather than confidence in the
 * boolean classification. Evidence is grouped so that many files of one kind
 * cannot overwhelm the absence of a browser entry point.
 */
export async function detectWebProject({ root = process.cwd(), files = [] } = {}) {
  const projectRoot = path.resolve(root);
  const allRelativeFiles = [...new Set(files.map((file) => normalizeRelative(projectRoot, file)).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  const relativeFiles = allRelativeFiles.filter(isDetectionRelevant);
  const lowerFiles = relativeFiles.map((relative) => relative.toLowerCase());
  const lowerFileSet = new Set(lowerFiles);
  const signals = new Set();
  const reasons = new Set();
  const evidenceGroups = new Map();

  function addEvidence(group, weight, signal, reason) {
    evidenceGroups.set(group, Math.max(evidenceGroups.get(group) ?? 0, weight));
    signals.add(signal);
    reasons.add(reason);
  }

  function addObservation(signal, reason) {
    signals.add(signal);
    if (reason) reasons.add(reason);
  }

  const viteConfigPaths = relativeFiles.filter((relative) => /^vite\.config\.(?:js|mjs|cjs|ts|mts|cts)$/i.test(path.posix.basename(relative)));
  const viteLibraryConfig = await findSourceMatching(
    projectRoot,
    viteConfigPaths,
    /\bbuild\s*:\s*\{[\s\S]{0,8000}?\blib\s*:/i,
    256_000,
  );
  const hasViteLibraryMode = Boolean(viteLibraryConfig);
  if (viteLibraryConfig) {
    addObservation("tooling:vite-library-mode", `Vite library-mode configuration was detected in ${viteLibraryConfig}.`);
  }

  const packagePaths = relativeFiles.filter((relative) => path.posix.basename(relative).toLowerCase() === "package.json");
  if (!lowerFileSet.has("package.json")) packagePaths.unshift("package.json");

  const manifests = (await mapInBatches([...new Set(packagePaths)], async (packagePath) => {
    const source = await readProjectFile(projectRoot, packagePath);
    if (!source) return null;
    try {
      const manifest = JSON.parse(source);
      return manifest && typeof manifest === "object" && !Array.isArray(manifest)
        ? { manifest, relative: packagePath }
        : null;
    } catch {
      // A malformed package file is not useful evidence, but should not make
      // project detection itself fail.
      return null;
    }
  })).filter(Boolean);

  const dependencies = new Set();
  const peerDependencyNames = new Set();
  const scripts = [];
  for (const { manifest } of manifests) {
    for (const dependency of installedDependencies(manifest)) dependencies.add(dependency);
    for (const dependency of peerDependencies(manifest)) peerDependencyNames.add(dependency);
    if (manifest.scripts && typeof manifest.scripts === "object") {
      for (const command of Object.values(manifest.scripts)) {
        if (typeof command === "string") scripts.push(command);
      }
    }
  }

  const isLibraryManifest = (manifest) => (
    Boolean(manifest.exports || manifest.main || manifest.module || manifest.types || manifest.typings)
  );
  const hasLibraryPackage = manifests.some(({ manifest }) => isLibraryManifest(manifest));
  const hasCliPackage = manifests.some(({ manifest }) => Boolean(manifest.bin));
  const manifestDirectory = (relative) => {
    const directory = path.posix.dirname(relative);
    return directory === "." ? "" : directory;
  };
  const workspaceRelativePath = (relative, directory) => {
    if (!directory) return relative;
    const prefix = `${directory}/`;
    return relative.startsWith(prefix) ? relative.slice(prefix.length) : null;
  };
  const manifestDirectories = [...new Set(manifests.map(({ relative }) => manifestDirectory(relative)))];
  const owningManifestDirectory = (relative) => manifestDirectories
    .filter((directory) => !directory || relative.startsWith(`${directory}/`))
    .sort((left, right) => right.length - left.length)[0] ?? "";
  const desktopApplicationDirectories = new Set(manifests.flatMap(({ manifest, relative }) => {
    const packageDependencies = installedDependencies(manifest);
    const desktopRuntime = [...packageDependencies].some((name) => (
      DESKTOP_APP_DEPENDENCIES.has(name) || name.startsWith("@electron/")
    ));
    return desktopRuntime ? [manifestDirectory(relative)] : [];
  }));
  const extensionManifestPaths = (await mapInBatches(
    relativeFiles.filter((relative) => path.posix.basename(relative).toLowerCase() === "manifest.json"),
    async (relative) => {
      const source = await readProjectFile(projectRoot, relative, 128_000);
      if (!source) return null;
      try {
        const manifest = JSON.parse(source);
        return manifest && [2, 3].includes(manifest.manifest_version) ? relative : null;
      } catch {
        return null;
      }
    },
  )).filter(Boolean);
  const extensionApplicationDirectories = new Set(extensionManifestPaths.map(owningManifestDirectory));
  const nonWebsiteApplicationDirectories = new Set([
    ...desktopApplicationDirectories,
    ...extensionApplicationDirectories,
  ]);
  if (desktopApplicationDirectories.size > 0) {
    addObservation("runtime:desktop-app", "Electron or Tauri application dependencies were detected.");
  }
  if (extensionManifestPaths.length > 0) {
    addObservation("runtime:browser-extension", "A browser-extension manifest was detected.");
  }
  const applicationWorkspaceDirectories = [...new Set(manifests.flatMap(({ manifest, relative }) => {
    if (isLibraryManifest(manifest) || manifest.bin) return [];
    const commands = manifest.scripts && typeof manifest.scripts === "object"
      ? Object.values(manifest.scripts).filter((command) => typeof command === "string")
      : [];
    return commands.some((command) => WEB_SCRIPT_PATTERN.test(command))
      ? [manifestDirectory(relative)]
      : [];
  }))];

  const scriptText = scripts.join("\n");
  const hasWebScript = WEB_SCRIPT_PATTERN.test(scriptText);
  const hasNativeMobileRuntime = dependencies.has("react-native")
    || dependencies.has("expo")
    || dependencies.has("expo-router");
  const hasMobileOnlyRuntime = hasNativeMobileRuntime
    && !dependencies.has("react-dom")
    && !dependencies.has("react-native-web");
  if (hasWebScript) {
    addEvidence("web-script", 0.18, "package:web-script", "package.json contains a browser-oriented development, build, or preview command.");
  }
  if (hasMobileOnlyRuntime) {
    addObservation("runtime:native-mobile", "React Native or Expo dependencies were found without a browser rendering runtime.");
  }

  const uiFiles = relativeFiles.filter((relative) => UI_SOURCE_EXTENSIONS.has(extensionOf(relative)));
  if (uiFiles.length > 0) {
    addEvidence(
      "ui-source",
      0.19,
      `ui-source:${Math.min(uiFiles.length, 999)}`,
      `${uiFiles.length} browser UI component ${uiFiles.length === 1 ? "file was" : "files were"} found.`,
    );
  }

  const clientEntryPattern = /^(?:(?:src|client|web)\/)?(?:main|index|app|entry-client)\.(?:js|jsx|mjs|cjs|mts|cts|ts|tsx|vue|svelte|astro)$/i;
  const clientEntries = relativeFiles.filter((relative) => (
    clientEntryPattern.test(relative)
    || applicationWorkspaceDirectories.some((directory) => {
      const nested = workspaceRelativePath(relative, directory);
      return nested !== null && clientEntryPattern.test(nested);
    })
  ));
  const routeFiles = relativeFiles.filter((relative) => !hasMobileOnlyRuntime && (
    /(?:^|\/)(?:pages|app)\/.*\.(?:astro|html|js|jsx|mjs|cjs|mts|cts|svelte|ts|tsx|vue)$/i.test(relative)
      || /(?:^|\/)routes\/.*\.(?:astro|html|jsx|svelte|tsx|vue)$/i.test(relative)
  ));
  if (routeFiles.length > 0) {
    addEvidence("route-structure", 0.21, "source:web-routes", `Website page or route modules were found (for example, ${routeFiles[0]}).`);
  }

  const entryHtmlPattern = /^(?:index\.html?|public\/index\.html?|src\/index\.html?|site\/index\.html?|web\/index\.html?|www\/index\.html?)$/i;
  const entryHtmlPaths = relativeFiles.filter((relative) => (
    entryHtmlPattern.test(relative)
    || applicationWorkspaceDirectories.some((directory) => {
      const nested = workspaceRelativePath(relative, directory);
      return nested !== null && entryHtmlPattern.test(nested);
    })
  ));
  const validHtmlEntries = [];
  for (const entryPath of entryHtmlPaths) {
    const source = await readProjectFile(projectRoot, entryPath);
    if (isValidHtmlDocument(source)) {
      validHtmlEntries.push(entryPath);
    }
  }
  const validHtmlEntry = validHtmlEntries[0] ?? null;
  if (validHtmlEntry) {
    addEvidence("html-entry", 0.7, "entry:valid-index-html", `A valid website entry document was found at ${validHtmlEntry}.`);
  }

  const unrelatedHtml = relativeFiles.filter((relative) => /\.html?$/i.test(relative) && !entryHtmlPaths.includes(relative));
  if (!validHtmlEntry && unrelatedHtml.length > 0) {
    addObservation("html:non-entry", "HTML documents exist, but none is a validated website entry point.");
  }

  const allSourceCandidates = relativeFiles
    .filter((relative) => /\.(?:js|jsx|mjs|cjs|mts|cts|ts|tsx)$/i.test(relative));
  // Inspect likely browser entry points first, then exhaust the remaining
  // production sources in small batches. Alphabetical file order must not make
  // a real app disappear merely because it contains many utility modules.
  const readableSourceCandidates = [...new Set([
    ...clientEntries,
    ...routeFiles.filter((relative) => /\.(?:js|jsx|mjs|cjs|mts|cts|ts|tsx)$/i.test(relative)),
    ...allSourceCandidates,
  ])];
  const domSource = await findSourceMatching(projectRoot, readableSourceCandidates, DOM_PATTERN, 160_000);
  if (domSource) {
    addEvidence("browser-code", 0.2, "source:browser-dom", `Browser DOM usage was found in ${domSource}.`);
  }

  const applicationPageEvidence = Boolean(validHtmlEntry) || routeFiles.length > 0;
  let framework = null;
  let peerFramework = null;
  let hasStrongFramework = false;
  let hasFrameworkConfigEntry = false;
  for (const candidate of APPLICATION_FRAMEWORKS) {
    const dependencyMatch = hasAnyDependency(dependencies, candidate.dependencies)
      || hasDependencyPrefix(dependencies, candidate.dependencyPrefixes);
    const peerMatch = hasAnyDependency(peerDependencyNames, candidate.dependencies)
      || hasDependencyPrefix(peerDependencyNames, candidate.dependencyPrefixes);
    const configMatch = hasMatchingConfig(lowerFiles, candidate.configs);
    if (!dependencyMatch && !peerMatch && !configMatch) continue;
    if (peerMatch) {
      peerFramework ??= candidate.name;
      addObservation(
        `framework-peer:${candidate.name.toLowerCase()}`,
        `${candidate.name} is declared as a peer dependency; peer support alone is not website evidence.`,
      );
    }
    if (!dependencyMatch && !configMatch) continue;

    framework ??= candidate.name;
    if (configMatch && hasWebScript) hasFrameworkConfigEntry = true;
    const runnableEvidence = applicationPageEvidence || (configMatch && hasWebScript);
    const libraryBlocked = hasLibraryPackage && !applicationPageEvidence;

    if (dependencyMatch && runnableEvidence && !libraryBlocked) {
      framework = candidate.name;
      hasStrongFramework = true;
      addEvidence(
        "application-framework",
        configMatch ? 0.74 : 0.68,
        `framework:${candidate.name.toLowerCase()}`,
        `${candidate.name} application dependencies and runnable site evidence were detected.`,
      );
    } else {
      if (dependencyMatch) {
        addEvidence(
          "framework-package",
          0.22,
          `framework-package:${candidate.name.toLowerCase()}`,
          `${candidate.name} is installed, but a runnable application entry has not been established.`,
        );
      }
      if (configMatch) {
        addEvidence(
          "application-framework-config",
          0.24,
          `framework-config:${candidate.name.toLowerCase()}`,
          `${candidate.name} configuration was detected without sufficient runnable application evidence.`,
        );
      }
    }
    if (hasStrongFramework) break;
  }
  framework ??= peerFramework;

  const angularConfigPath = relativeFiles.find((relative) => relative.toLowerCase() === "angular.json");
  const angularConfig = angularConfigPath ? await readProjectFile(projectRoot, angularConfigPath) : null;
  const angularApplication = angularConfig ? /"projectType"\s*:\s*"application"/i.test(angularConfig) : false;
  const hasAngularRuntime = dependencies.has("@angular/core") && dependencies.has("@angular/platform-browser");
  const hasAngularPeer = peerDependencyNames.has("@angular/core") || peerDependencyNames.has("@angular/platform-browser");
  if (!framework && (hasAngularRuntime || hasAngularPeer || angularConfigPath)) framework = "Angular";
  if (hasAngularRuntime && (angularApplication || applicationPageEvidence) && !(hasLibraryPackage && !applicationPageEvidence && !angularApplication)) {
    hasStrongFramework = true;
    addEvidence("application-framework", 0.7, "framework:angular", "An Angular browser application workspace was detected.");
  } else if (hasAngularRuntime || angularApplication) {
    addEvidence("frontend-runtime", 0.27, "framework:angular", "Angular browser dependencies or application configuration were detected without a confirmed app entry.");
  }
  if (hasAngularPeer) {
    addObservation("framework-peer:angular", "Angular is declared as a peer dependency; peer support alone is not website evidence.");
  }

  const hasReactRuntime = dependencies.has("react-dom")
    || (!hasMobileOnlyRuntime && dependencies.has("react") && uiFiles.some((file) => /\.(?:jsx|tsx)$/i.test(file)));
  const hasReactPeer = peerDependencyNames.has("react") || peerDependencyNames.has("react-dom");
  const hasVueRuntime = dependencies.has("vue");
  const hasVuePeer = peerDependencyNames.has("vue");
  const hasSvelteRuntime = dependencies.has("svelte");
  const hasSveltePeer = peerDependencyNames.has("svelte");
  const hasVite = dependencies.has("vite") || lowerFiles.some((file) => /^vite\.config\.(?:js|mjs|cjs|ts|mts|cts)$/.test(path.posix.basename(file)));

  if (!framework && (hasReactRuntime || hasReactPeer)) framework = "React";
  if (!framework && (hasVueRuntime || hasVuePeer)) framework = "Vue";
  if (!framework && (hasSvelteRuntime || hasSveltePeer)) framework = "Svelte";
  if (!framework && hasVite) framework = "Vite";

  if (hasReactRuntime) addEvidence("frontend-runtime", 0.3, "framework:react", "React browser rendering dependencies and UI source files were detected.");
  if (hasVueRuntime) addEvidence("frontend-runtime", 0.3, "framework:vue", "The Vue browser runtime was detected.");
  if (hasSvelteRuntime) addEvidence("frontend-runtime", 0.28, "framework:svelte", "The Svelte UI framework was detected.");
  if (hasReactPeer) addObservation("framework-peer:react", "React is declared as a peer dependency; peer support alone is not website evidence.");
  if (hasVuePeer) addObservation("framework-peer:vue", "Vue is declared as a peer dependency; peer support alone is not website evidence.");
  if (hasSveltePeer) addObservation("framework-peer:svelte", "Svelte is declared as a peer dependency; peer support alone is not website evidence.");
  if (hasVite) addEvidence("web-tooling", 0.2, "tooling:vite", "Vite browser tooling or configuration was detected.");

  if (clientEntries.length > 0 && (hasReactRuntime || hasVueRuntime || hasSvelteRuntime || hasVite)) {
    addEvidence("client-entry", 0.19, "source:client-entry", `A likely browser entry module was found at ${clientEntries[0]}.`);
  }

  const siteMetadata = relativeFiles.filter((relative) =>
    /(?:^|\/)(?:robots\.txt|sitemap\.xml|manifest\.webmanifest)$/i.test(relative));
  if (siteMetadata.length > 0) {
    addEvidence("site-metadata", 0.08, "site:metadata", `Website metadata was found at ${siteMetadata[0]}.`);
  }

  const backendDependencies = [...dependencies].filter((name) => BACKEND_DEPENDENCIES.has(name));
  const hasFrontendAnchor = hasStrongFramework || hasReactRuntime || hasVueRuntime || hasSvelteRuntime || hasAngularRuntime || hasVite || Boolean(validHtmlEntry) || Boolean(domSource);

  let penalty = 0;
  const packageApplicationEvidence = applicationPageEvidence || angularApplication;
  if (hasCliPackage && !packageApplicationEvidence) {
    penalty += 0.3;
    addObservation("package:cli", "The package exposes a command-line executable without a strong website entry signal.");
  }
  if (hasLibraryPackage && !packageApplicationEvidence) {
    penalty += 0.42;
    addObservation("package:library", "Package metadata describes a library-shaped entry rather than an application page.");
  }
  if (backendDependencies.length > 0 && !hasFrontendAnchor) {
    penalty += 0.3;
    addObservation("runtime:backend-only", `Server runtime dependencies were found (${backendDependencies.join(", ")}) without a browser application.`);
  }

  const positiveScore = [...evidenceGroups.values()].reduce((total, weight) => total + weight, 0);
  const confidence = Math.round(clamp(positiveScore - penalty, 0, 1) * 100) / 100;
  const strongWebsiteSignal = hasStrongFramework || Boolean(validHtmlEntry);
  const hasViteApplicationEntry = hasVite && !hasViteLibraryMode
    && applicationWorkspaceDirectories.some((directory) => {
      const hasWorkspaceConfig = viteConfigPaths.some((relative) => {
        const nested = workspaceRelativePath(relative, directory);
        return nested !== null && /^vite\.config\.(?:js|mjs|cjs|ts|mts|cts)$/i.test(nested);
      });
      const hasWorkspaceClientEntry = clientEntries.some((relative) => {
        const nested = workspaceRelativePath(relative, directory);
        return nested !== null && clientEntryPattern.test(nested);
      });
      return hasWorkspaceConfig && hasWorkspaceClientEntry;
    });
  const runnableSiteEvidence = applicationPageEvidence
    || hasFrameworkConfigEntry
    || angularApplication
    || hasViteApplicationEntry;
  const applicationFrameworkConfigPatterns = APPLICATION_FRAMEWORKS.flatMap(({ configs }) => configs);
  const independentWebApplicationDirectories = applicationWorkspaceDirectories.filter((directory) => {
    if (nonWebsiteApplicationDirectories.has(directory)) return false;
    const localPath = (relative) => workspaceRelativePath(relative, directory);
    const hasHtmlEntry = validHtmlEntries.some((relative) => localPath(relative) !== null);
    const hasRoute = routeFiles.some((relative) => localPath(relative) !== null);
    const hasFrameworkConfig = relativeFiles.some((relative) => {
      const local = localPath(relative);
      return local !== null && applicationFrameworkConfigPatterns.some((pattern) => pattern.test(path.posix.basename(local)));
    });
    const hasViteEntry = viteConfigPaths.some((relative) => localPath(relative) !== null)
      && clientEntries.some((relative) => localPath(relative) !== null);
    return hasHtmlEntry || hasRoute || hasFrameworkConfig || hasViteEntry;
  });
  const enoughIndependentEvidence = evidenceGroups.size >= 3 && hasFrontendAnchor && runnableSiteEvidence;
  let isWebsite = confidence >= 0.58 && (strongWebsiteSignal || enoughIndependentEvidence);

  // Library and CLI repositories frequently contain framework peer dependencies,
  // UI components, build scripts, or generated documentation. Require an actual
  // page/route or explicit application-workspace entry before treating those
  // package types as websites; generic DOM usage is also common in widgets.
  if ((hasLibraryPackage || hasCliPackage) && !packageApplicationEvidence) {
    isWebsite = false;
  }
  if (hasViteLibraryMode && !validHtmlEntry && routeFiles.length === 0) {
    isWebsite = false;
  }
  if (nonWebsiteApplicationDirectories.size > 0 && independentWebApplicationDirectories.length === 0) {
    isWebsite = false;
    reasons.add("The detected browser-extension or desktop runtime does not establish a separately runnable website.");
  }

  if (!isWebsite && evidenceGroups.size === 0) {
    reasons.add("No framework, browser entry point, route structure, or client-side source evidence was found.");
  } else if (!isWebsite && !strongWebsiteSignal) {
    reasons.add("The available signals do not establish that this repository is a runnable website.");
  }

  return {
    isWebsite,
    confidence,
    signals: [...signals],
    reasons: [...reasons],
    framework,
  };
}
