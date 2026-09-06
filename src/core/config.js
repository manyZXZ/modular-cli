import { promises as fs } from "node:fs";
import path from "node:path";

export const DEFAULT_CONFIG_FILE = ".modular.json";

const MAX_CONFIG_BYTES = 1024 * 1024;
const VALID_THRESHOLDS = new Set(["critical", "high", "medium", "low", "info", "none"]);
const VALID_FORMATS = new Set(["json", "sarif"]);
const ROOT_KEYS = new Set([
  "$schema",
  "baseline",
  "failOn",
  "failOnNew",
  "failOnRegression",
  "failOnIncomplete",
  "ignore",
  "maxFindingsPerRule",
  "outputFormats",
  "suppressions",
]);
const SUPPRESSION_KEYS = new Set(["rule", "path", "reason", "expires"]);

function invalid(message) {
  const error = new TypeError(`Invalid Modular configuration: ${message}`);
  error.code = "INVALID_CONFIG";
  return error;
}

function exactDirectoryName(value, field) {
  if (typeof value !== "string" || value.length === 0
    || value === "." || value === ".." || /[\\/]/.test(value) || path.isAbsolute(value)) {
    throw invalid(`${field} must contain exact directory names, not paths.`);
  }
  if (/\p{C}/u.test(value)) throw invalid(`${field} cannot contain control characters.`);
  return value;
}

function threshold(value, field) {
  if (typeof value !== "string" || !VALID_THRESHOLDS.has(value.toLowerCase())) {
    throw invalid(`${field} must be critical, high, medium, low, info or none.`);
  }
  return value.toLowerCase();
}

function repositoryRelativePath(root, value, field) {
  if (typeof value !== "string" || value.length === 0 || /\p{C}/u.test(value)) {
    throw invalid(`${field} must be a non-empty path without control characters.`);
  }
  if (path.isAbsolute(value)) throw invalid(`${field} must be relative to the repository root.`);
  const resolved = path.resolve(root, value);
  const relation = path.relative(root, resolved);
  if (relation === ".." || relation.startsWith(`..${path.sep}`) || path.isAbsolute(relation)) {
    throw invalid(`${field} must stay inside the repository.`);
  }
  return resolved;
}

function validDate(value, field) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw invalid(`${field} must use YYYY-MM-DD.`);
  }
  const date = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(date.valueOf()) || date.toISOString().slice(0, 10) !== value) {
    throw invalid(`${field} is not a real calendar date.`);
  }
  return value;
}

function glob(value, field, { pathPattern = false } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > 500 || /\p{C}/u.test(value)) {
    throw invalid(`${field} must be a non-empty glob of at most 500 characters.`);
  }
  if (pathPattern) {
    const normalized = value.replaceAll("\\", "/");
    if (normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)
      || normalized.split("/").includes("..")) {
      throw invalid(`${field} must be a repository-relative glob without parent traversal.`);
    }
    return normalized.replace(/^\.\//, "");
  }
  if (value.includes("/")) throw invalid(`${field} must match a rule id, not a file path.`);
  return value;
}

function suppression(value, index) {
  const field = `suppressions[${index}]`;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${field} must be an object.`);
  }
  const unknown = Object.keys(value).filter((key) => !SUPPRESSION_KEYS.has(key));
  if (unknown.length) throw invalid(`${field} contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.sort().join(", ")}.`);
  if (typeof value.reason !== "string" || value.reason.trim().length < 8 || value.reason.length > 1000) {
    throw invalid(`${field}.reason must explain the accepted risk in 8–1000 characters.`);
  }
  return {
    rule: glob(value.rule, `${field}.rule`),
    ...(value.path === undefined ? {} : { path: glob(value.path, `${field}.path`, { pathPattern: true }) }),
    reason: value.reason.trim(),
    ...(value.expires === undefined ? {} : { expires: validDate(value.expires, `${field}.expires`) }),
  };
}

export function validateProjectConfiguration(value, root) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid("the root value must be an object.");
  }
  const unknown = Object.keys(value).filter((key) => !ROOT_KEYS.has(key));
  if (unknown.length) throw invalid(`unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.sort().join(", ")}.`);

  const output = {};
  if (value.$schema !== undefined) {
    if (typeof value.$schema !== "string" || value.$schema.length === 0
      || value.$schema.length > 2048 || /\p{C}/u.test(value.$schema)) {
      throw invalid("$schema must be a non-empty string of at most 2048 characters without control characters.");
    }
    output.$schema = value.$schema;
  }
  if (value.failOn !== undefined) output.failOn = threshold(value.failOn, "failOn");
  if (value.failOnNew !== undefined) output.failOnNew = threshold(value.failOnNew, "failOnNew");
  if (value.failOnRegression !== undefined) output.failOnRegression = threshold(value.failOnRegression, "failOnRegression");
  if (value.failOnIncomplete !== undefined) {
    if (typeof value.failOnIncomplete !== "boolean") throw invalid("failOnIncomplete must be a boolean.");
    output.failOnIncomplete = value.failOnIncomplete;
  }
  if (value.maxFindingsPerRule !== undefined) {
    if (!Number.isSafeInteger(value.maxFindingsPerRule) || value.maxFindingsPerRule <= 0) {
      throw invalid("maxFindingsPerRule must be a positive integer.");
    }
    output.maxFindingsPerRule = value.maxFindingsPerRule;
  }
  if (value.ignore !== undefined) {
    if (!Array.isArray(value.ignore) || value.ignore.length > 100) {
      throw invalid("ignore must be an array of no more than 100 exact directory names.");
    }
    output.ignore = value.ignore.map((item) => exactDirectoryName(item, "ignore"));
    if (new Set(output.ignore).size !== output.ignore.length) throw invalid("ignore cannot contain duplicate directory names.");
  }
  if (value.outputFormats !== undefined) {
    if (!Array.isArray(value.outputFormats)) throw invalid("outputFormats must be an array.");
    const formats = value.outputFormats.map((item) => String(item).toLowerCase());
    const unsupported = formats.filter((item) => !VALID_FORMATS.has(item));
    if (unsupported.length) throw invalid(`outputFormats supports only json and sarif; found: ${[...new Set(unsupported)].sort().join(", ")}.`);
    if (new Set(formats).size !== formats.length) throw invalid("outputFormats cannot contain duplicate values.");
    output.outputFormats = formats;
  }
  if (value.baseline !== undefined) {
    output.baseline = repositoryRelativePath(root, value.baseline, "baseline");
  }
  if (value.suppressions !== undefined) {
    if (!Array.isArray(value.suppressions) || value.suppressions.length > 1000) {
      throw invalid("suppressions must be an array of no more than 1000 entries.");
    }
    output.suppressions = value.suppressions.map(suppression);
  }
  return output;
}

export async function loadProjectConfiguration({ root, file = null, disabled = false } = {}) {
  if (disabled) return null;
  const projectRoot = path.resolve(root ?? process.cwd());
  const configPath = path.resolve(file ?? path.join(projectRoot, DEFAULT_CONFIG_FILE));
  let stat;
  try {
    stat = await fs.lstat(configPath);
  } catch (error) {
    if (error?.code === "ENOENT" && !file) return null;
    if (error?.code === "ENOENT") throw invalid(`configuration file does not exist: ${configPath}`);
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw invalid(`configuration must be a regular file and cannot be a symbolic link: ${configPath}`);
  }
  if (stat.size > MAX_CONFIG_BYTES) throw invalid(`configuration exceeds the ${MAX_CONFIG_BYTES}-byte safety limit.`);

  let value;
  try {
    value = JSON.parse(await fs.readFile(configPath, "utf8"));
  } catch (error) {
    throw invalid(`configuration is not valid JSON: ${error.message}`);
  }
  return {
    path: configPath,
    config: validateProjectConfiguration(value, projectRoot),
  };
}
