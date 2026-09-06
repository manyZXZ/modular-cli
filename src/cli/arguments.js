import path from "node:path";
import { SCAN_MODULES, getScanModule } from "../core/modules.js";
import { MAX_RUNTIME_ROUTES, RUNTIME_AUDIT_DEFAULTS, isLoopbackHostname } from "../runtime/index.js";
import { CliError } from "./errors.js";
import { isInsideOrEqual } from "./paths.js";

const VALID_MODES = new Set([...SCAN_MODULES.map(({ id }) => id), "all"]);
const VALID_THRESHOLDS = new Set(["critical", "high", "medium", "low", "info", "none"]);
const VALID_BROWSERS = new Set(["chromium", "firefox", "webkit"]);
const VALID_RUNTIME_VIEWPORTS = new Set(["mobile", "desktop"]);
const VALID_BROWSER_CHANNELS = new Set([
  "chrome", "chrome-beta", "chrome-dev", "chrome-canary",
  "msedge", "msedge-beta", "msedge-dev", "msedge-canary",
]);

export const CLI_SPECIFIED = Symbol("modular.cli-specified");

function readValue(args, index, option) {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new CliError(`${option} requires a value.`);
  return value;
}

function positiveInteger(value, option) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new CliError(`${option} must be a positive integer.`);
  return number;
}

function exactDirectoryName(value, option) {
  if (value === "." || value === ".." || /[\\/]/.test(value) || path.isAbsolute(value)) {
    throw new CliError(`${option} requires an exact directory name, not a path.`);
  }
  return value;
}

function validateRuntimeUrlOptions(parsed) {
  if (parsed.runtimeMaxRoutes > MAX_RUNTIME_ROUTES) {
    throw new CliError(`--runtime-max-routes cannot exceed ${MAX_RUNTIME_ROUTES}.`);
  }
  if (parsed.runtimeTimeoutMs > 600_000) {
    throw new CliError("--runtime-timeout cannot exceed 600000 ms.");
  }
  if (parsed.runtimeSpaFallback && !parsed.runtimeStaticDir) {
    throw new CliError("--runtime-spa-fallback requires --runtime-static-dir.");
  }
  if (!parsed.runtimeUrl) {
    const localBase = new URL("http://127.0.0.1/");
    for (const [index, value] of parsed.runtimeRoutes.entries()) {
      let route;
      try {
        route = new URL(value, localBase);
      } catch {
        throw new CliError(`--route ${index + 1} is not a valid URL path.`);
      }
      if (!["http:", "https:"].includes(route.protocol)
        || route.origin !== localBase.origin
        || route.username
        || route.password) {
        throw new CliError(`--route ${index + 1} must be a relative HTTP path for a static-directory target.`);
      }
    }
    return;
  }

  let baseUrl;
  try {
    baseUrl = new URL(parsed.runtimeUrl);
  } catch {
    throw new CliError("--url must be an absolute HTTP or HTTPS URL.");
  }
  if (!["http:", "https:"].includes(baseUrl.protocol)) {
    throw new CliError("--url must use HTTP or HTTPS.");
  }
  if (baseUrl.username || baseUrl.password) {
    throw new CliError("--url must not contain embedded credentials.");
  }
  if (!parsed.runtimeAllowRemote && !isLoopbackHostname(baseUrl.hostname)) {
    throw new CliError("Remote runtime targets require explicit --allow-remote permission.");
  }
  for (const [index, value] of parsed.runtimeRoutes.entries()) {
    let route;
    try {
      route = new URL(value, baseUrl);
    } catch {
      throw new CliError(`--route ${index + 1} is not a valid URL path.`);
    }
    if (!["http:", "https:"].includes(route.protocol) || route.origin !== baseUrl.origin) {
      throw new CliError(`--route ${index + 1} must remain on the runtime target origin.`);
    }
    if (route.username || route.password) {
      throw new CliError(`--route ${index + 1} must not contain embedded credentials.`);
    }
  }
}

export function parseCliArguments(argv) {
  const args = [...argv];
  if (args.includes("--help") || args.includes("-h")) return { help: true };
  if (args.includes("--version") || args.includes("-v")) return { version: true };
  if (args[0] === "doctor") {
    const valueOptions = new Set([
      "--root", "--output", "--ignore", "--max-files", "--max-file-size",
      "--max-total-size", "--config", "--baseline",
    ]);
    const flagOptions = new Set(["--no-config", "--no-color"]);
    for (let index = 1; index < args.length; index += 1) {
      const argument = args[index];
      if (valueOptions.has(argument)) {
        index += 1;
        continue;
      }
      if (!flagOptions.has(argument)) {
        throw new CliError(`Unknown doctor option: ${argument}`);
      }
    }
    const parsed = parseCliArguments(["check", "security", ...args.slice(1)]);
    parsed.command = "doctor";
    parsed.mode = "doctor";
    return parsed;
  }
  if (args.length < 2 || args[0] !== "check" || !VALID_MODES.has(args[1])) {
    throw new CliError("Choose one of: modular check security, modular check mysite, modular check all, modular doctor.");
  }

  const specified = new Set();
  const parsed = {
    mode: args[1],
    command: "check",
    root: process.cwd(),
    output: null,
    color: true,
    quiet: false,
    failOn: "none",
    failOnNew: "none",
    failOnRegression: "none",
    failOnIncomplete: false,
    maxFiles: 20_000,
    maxFileBytes: 1_500_000,
    maxTotalBytes: 128 * 1024 * 1024,
    maxFindingsPerRule: null,
    ignore: [],
    config: null,
    configDisabled: false,
    baseline: null,
    writeBaseline: null,
    suppressions: [],
    machineFormats: [],
    auditDependencies: false,
    runtimeAudit: false,
    runtimeOptionsSpecified: false,
    runtimeUrl: null,
    runtimeStaticDir: null,
    runtimeRoutes: [],
    runtimeAllowRemote: false,
    runtimeBrowser: RUNTIME_AUDIT_DEFAULTS.browserName,
    runtimeBrowserChannel: null,
    runtimeViewport: "mobile",
    runtimeMaxRoutes: RUNTIME_AUDIT_DEFAULTS.maxRoutes,
    runtimeTimeoutMs: RUNTIME_AUDIT_DEFAULTS.totalTimeoutMs,
    runtimeSpaFallback: false,
  };
  Object.defineProperty(parsed, CLI_SPECIFIED, { value: specified });

  for (let index = 2; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--root") {
      parsed.root = readValue(args, index, argument);
      index += 1;
    } else if (argument === "--output") {
      parsed.output = readValue(args, index, argument);
      index += 1;
    } else if (argument === "--ignore") {
      parsed.ignore.push(exactDirectoryName(readValue(args, index, argument), argument));
      specified.add("ignore");
      index += 1;
    } else if (argument === "--max-files") {
      parsed.maxFiles = positiveInteger(readValue(args, index, argument), argument);
      index += 1;
    } else if (argument === "--max-file-size") {
      parsed.maxFileBytes = positiveInteger(readValue(args, index, argument), argument);
      index += 1;
    } else if (argument === "--max-total-size") {
      parsed.maxTotalBytes = positiveInteger(readValue(args, index, argument), argument);
      index += 1;
    } else if (argument === "--max-findings-per-rule") {
      parsed.maxFindingsPerRule = positiveInteger(readValue(args, index, argument), argument);
      specified.add("maxFindingsPerRule");
      index += 1;
    } else if (argument === "--fail-on") {
      const threshold = readValue(args, index, argument).toLowerCase();
      if (!VALID_THRESHOLDS.has(threshold)) {
        throw new CliError("--fail-on must be critical, high, medium, low, info or none.");
      }
      parsed.failOn = threshold;
      specified.add("failOn");
      index += 1;
    } else if (argument === "--fail-on-new") {
      const threshold = readValue(args, index, argument).toLowerCase();
      if (!VALID_THRESHOLDS.has(threshold)) {
        throw new CliError("--fail-on-new must be critical, high, medium, low, info or none.");
      }
      parsed.failOnNew = threshold;
      specified.add("failOnNew");
      index += 1;
    } else if (argument === "--fail-on-regression") {
      const threshold = readValue(args, index, argument).toLowerCase();
      if (!VALID_THRESHOLDS.has(threshold)) throw new CliError("--fail-on-regression requires a severity or none.");
      parsed.failOnRegression = threshold;
      specified.add("failOnRegression");
      index += 1;
    } else if (argument === "--fail-on-incomplete") {
      parsed.failOnIncomplete = true;
      specified.add("failOnIncomplete");
    } else if (argument === "--config") {
      parsed.config = readValue(args, index, argument);
      specified.add("config");
      index += 1;
    } else if (argument === "--no-config") {
      parsed.configDisabled = true;
    } else if (argument === "--baseline") {
      parsed.baseline = readValue(args, index, argument);
      specified.add("baseline");
      index += 1;
    } else if (argument === "--write-baseline") {
      parsed.writeBaseline = readValue(args, index, argument);
      index += 1;
    } else if (argument === "--json") {
      parsed.machineFormats.push("json");
      specified.add("machineFormats");
    } else if (argument === "--sarif") {
      parsed.machineFormats.push("sarif");
      specified.add("machineFormats");
    } else if (argument === "--no-color") {
      parsed.color = false;
    } else if (argument === "--quiet") {
      parsed.quiet = true;
    } else if (argument === "--dependency-audit") {
      parsed.auditDependencies = true;
    } else if (argument === "--no-dependency-audit") {
      parsed.auditDependencies = false;
    } else if (argument === "--runtime") {
      parsed.runtimeAudit = true;
    } else if (argument === "--url") {
      parsed.runtimeUrl = readValue(args, index, argument);
      parsed.runtimeOptionsSpecified = true;
      index += 1;
    } else if (argument === "--runtime-static-dir") {
      parsed.runtimeStaticDir = readValue(args, index, argument);
      parsed.runtimeOptionsSpecified = true;
      index += 1;
    } else if (argument === "--route") {
      parsed.runtimeRoutes.push(readValue(args, index, argument));
      parsed.runtimeOptionsSpecified = true;
      index += 1;
    } else if (argument === "--allow-remote") {
      parsed.runtimeAllowRemote = true;
      parsed.runtimeOptionsSpecified = true;
    } else if (argument === "--browser") {
      const browser = readValue(args, index, argument).toLowerCase();
      if (!VALID_BROWSERS.has(browser)) throw new CliError("--browser must be chromium, firefox or webkit.");
      parsed.runtimeBrowser = browser;
      parsed.runtimeOptionsSpecified = true;
      index += 1;
    } else if (argument === "--browser-channel") {
      const channel = readValue(args, index, argument).toLowerCase();
      if (!VALID_BROWSER_CHANNELS.has(channel)) {
        throw new CliError("--browser-channel must name a supported installed Chrome or Edge channel.");
      }
      parsed.runtimeBrowserChannel = channel;
      parsed.runtimeOptionsSpecified = true;
      index += 1;
    } else if (argument === "--runtime-viewport") {
      const viewport = readValue(args, index, argument).toLowerCase();
      if (!VALID_RUNTIME_VIEWPORTS.has(viewport)) {
        throw new CliError("--runtime-viewport must be mobile or desktop.");
      }
      parsed.runtimeViewport = viewport;
      parsed.runtimeOptionsSpecified = true;
      index += 1;
    } else if (argument === "--runtime-max-routes") {
      parsed.runtimeMaxRoutes = positiveInteger(readValue(args, index, argument), argument);
      parsed.runtimeOptionsSpecified = true;
      index += 1;
    } else if (argument === "--runtime-timeout") {
      parsed.runtimeTimeoutMs = positiveInteger(readValue(args, index, argument), argument);
      parsed.runtimeOptionsSpecified = true;
      index += 1;
    } else if (argument === "--runtime-spa-fallback") {
      parsed.runtimeSpaFallback = true;
      parsed.runtimeOptionsSpecified = true;
    } else {
      throw new CliError(`Unknown option: ${argument}`);
    }
  }

  if (parsed.config && parsed.configDisabled) {
    throw new CliError("--config and --no-config cannot be used together.");
  }

  if (!parsed.runtimeAudit && parsed.runtimeOptionsSpecified) {
    throw new CliError("Runtime options require explicit --runtime opt-in.");
  }
  if (parsed.runtimeAudit && parsed.mode !== "all" && !getScanModule(parsed.mode).capabilities.runtime) {
    throw new CliError("--runtime is available with `check mysite` or `check all`; security uses its own static and dependency checks.");
  }
  if (parsed.runtimeAudit && Boolean(parsed.runtimeUrl) === Boolean(parsed.runtimeStaticDir)) {
    throw new CliError("--runtime requires exactly one target: --url <http-url> or --runtime-static-dir <built-directory>.");
  }
  if (parsed.runtimeAudit && parsed.runtimeRoutes.length + 1 > parsed.runtimeMaxRoutes) {
    throw new CliError(`The base URL plus --route values exceed --runtime-max-routes (${parsed.runtimeMaxRoutes}).`);
  }
  if (parsed.runtimeBrowserChannel && parsed.runtimeBrowser !== "chromium") {
    throw new CliError("--browser-channel can only be used with --browser chromium.");
  }
  if (parsed.auditDependencies && parsed.mode !== "all" && !getScanModule(parsed.mode).capabilities.dependencyAudit) {
    throw new CliError("--dependency-audit is available with `check security` or `check all`.");
  }
  validateRuntimeUrlOptions(parsed);

  const requestedOutput = parsed.output;
  const requestedConfig = parsed.config;
  const requestedBaseline = parsed.baseline;
  const requestedWriteBaseline = parsed.writeBaseline;
  parsed.root = path.resolve(parsed.root);
  if (parsed.runtimeStaticDir) parsed.runtimeStaticDir = path.resolve(parsed.root, parsed.runtimeStaticDir);
  if (requestedOutput && !path.isAbsolute(requestedOutput)) {
    const resolvedOutput = path.resolve(parsed.root, requestedOutput);
    if (!isInsideOrEqual(parsed.root, resolvedOutput)) {
      throw new CliError("A relative --output path must stay inside the repository. Use an explicit absolute path to write elsewhere.");
    }
  }
  parsed.output = requestedOutput ? path.resolve(parsed.root, requestedOutput) : path.join(parsed.root, "Modular");
  if (path.relative(parsed.root, parsed.output) === "") {
    throw new CliError("--output must be a dedicated report directory and cannot be the repository root.");
  }
  const resolvePolicyPath = (value, option) => {
    if (!value) return null;
    if (path.isAbsolute(value)) return path.resolve(value);
    const resolved = path.resolve(parsed.root, value);
    if (!isInsideOrEqual(parsed.root, resolved)) {
      throw new CliError(`A relative ${option} path must stay inside the repository. Use an explicit absolute path to access elsewhere.`);
    }
    return resolved;
  };
  parsed.config = resolvePolicyPath(requestedConfig, "--config");
  parsed.baseline = resolvePolicyPath(requestedBaseline, "--baseline");
  parsed.writeBaseline = resolvePolicyPath(requestedWriteBaseline, "--write-baseline");
  parsed.machineFormats = [...new Set(parsed.machineFormats)].sort();
  return parsed;
}

export function usage() {
  return `
MODULAR — Repository intelligence

Usage:
  modular check security [options]
  modular check mysite [options]
  modular check all [options]
  modular doctor [options]

Commands:
  check security   Application security, secrets, supply chain and configuration
  check mysite     Site quality, UX, accessibility, SEO, AI search and performance
  check all        Run both complete scans with one discovery and website gate
  doctor           Validate the local runtime, project, policy and report target

Options:
  --root <path>             Repository to scan (default: current directory)
  --output <path>           Dedicated report directory (relative paths use <root>)
  --ignore <directory>      Add an exact directory name to ignore; repeatable
  --max-files <number>      Safety limit (default: 20000)
  --max-file-size <bytes>   Per-file text limit (default: 1500000)
  --max-total-size <bytes>  Total readable source limit (default: 134217728)
  --max-findings-per-rule <number>  Detail cap per rule (defaults: security 50, site 50)
  --fail-on <severity>      CI exit 3 at/above: critical|high|medium|low|info|none
  --fail-on-new <severity>  CI exit 3 only for baseline-new unsuppressed findings
  --fail-on-regression <severity>  CI exit 3 for new or severity-increased findings
  --fail-on-incomplete      Exit 1 when discovered source coverage is incomplete
  --baseline <file>         Compare stable finding fingerprints with a baseline
  --write-baseline <file>   Atomically create or update a Modular baseline
  --config <file>           Use a JSON policy file (default: <root>/.modular.json)
  --no-config               Disable automatic project configuration discovery
  --json                    Write deterministic modular-results.json
  --sarif                   Write SARIF 2.1.0 for GitHub Code Scanning and CI
  --dependency-audit        Opt in to a registry network advisory audit (security/all)
  --runtime                 Opt in to a disposable browser audit (mysite/all only)
  --url <http-url>          Audit an already-running site; loopback only by default
  --runtime-static-dir <directory>  Safely serve an existing build; no scripts are run
  --route <path>            Add a same-origin runtime route; repeatable (base URL included)
  --browser <name>          chromium|firefox|webkit (default: chromium)
  --browser-channel <name>  Use an installed Chrome/Edge channel with chromium
  --runtime-viewport <name> mobile (390x844) or desktop (1280x720; default: mobile)
  --runtime-max-routes <n>  Hard route limit (default: 5, maximum: 25)
  --runtime-timeout <ms>    Total browser-audit timeout (default: 60000)
  --runtime-spa-fallback    Serve index.html for missing build paths
  --allow-remote            Permit a remote target and remote page resources
  --no-color                Disable ANSI colors
  --quiet                   Only print failures
  -h, --help                Show help
  -v, --version             Show version

Doctor accepts root/output, discovery-limit, ignore, config, baseline and color
options only. It is read-only and never opts in to dependency or browser execution.

Supported npm/pnpm audits use a temporary sanitized manifest and lockfile; repository
scripts, package-manager configuration, plugins and workspace code are not loaded.
Runtime auditing is separately opt-in and never runs repository scripts. It uses an
installed Playwright browser and Axe when available; incomplete requested coverage exits 1.
At most five Markdown reports are written (default: <root>/Modular). JSON and SARIF
are additional explicit outputs. Configuration cannot opt in to network or browser work.
`;
}
