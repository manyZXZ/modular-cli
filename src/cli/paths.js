import { promises as fs } from "node:fs";
import path from "node:path";
import { generatedReportNames } from "../core/modules.js";
import { MACHINE_REPORT_FILES, MACHINE_REPORT_LOCK_FILE, isOwnedMachineReport } from "../core/machine-reporter.js";
import { REPORT_LOCK_FILE, REPORT_MARKER } from "../core/reporter.js";
import { EXIT, CliError } from "./errors.js";

const OUTPUT_NAMES_ARE_CASE_INSENSITIVE = process.platform === "win32";
const outputNameKey = (name) => OUTPUT_NAMES_ARE_CASE_INSENSITIVE ? name.toLowerCase() : name;
const GENERATED_REPORT_NAMES = new Set(generatedReportNames().map(outputNameKey));
const MACHINE_REPORT_NAMES = new Map(Object.entries(MACHINE_REPORT_FILES)
  .map(([format, name]) => [outputNameKey(name), format]));

export async function validateRoot(root) {
  let stat;
  try {
    stat = await fs.stat(root);
  } catch (error) {
    if (["ENOENT", "ENOTDIR"].includes(error?.code)) {
      throw new CliError(`Repository path does not exist: ${root}`);
    }
    const code = error?.code ? ` (${error.code})` : "";
    throw new CliError(`Repository path could not be accessed${code}: ${root}`, EXIT.failed);
  }
  if (!stat.isDirectory()) throw new CliError(`Repository path is not a directory: ${root}`);
}

function isGeneratedReportTemporaryFile(name) {
  const names = generatedReportNames().map((file) => file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = `^\\.(?:${names.join("|")})\\.\\d+\\.[0-9a-f-]+\\.tmp$`;
  return new RegExp(pattern, OUTPUT_NAMES_ARE_CASE_INSENSITIVE ? "i" : "").test(name);
}

async function hasGeneratedReportMarker(filePath) {
  const expectedBytes = Buffer.byteLength(REPORT_MARKER);
  const buffer = Buffer.alloc(expectedBytes);
  let handle;
  try {
    handle = await fs.open(filePath, "r");
    const { bytesRead } = await handle.read(buffer, 0, expectedBytes, 0);
    return bytesRead === expectedBytes && buffer.toString("utf8") === REPORT_MARKER;
  } finally {
    await handle?.close();
  }
}

export function reportDirectoryDisplay(root, directory) {
  const relative = path.relative(root, directory);
  if (relative === "") return ".";
  if (isInside(root, directory)) return relative.split(path.sep).join("/");
  return path.resolve(directory);
}

export async function findOtherGeneratedReportDirectories(files, outputDirectory) {
  const selectedKey = outputNameKey(path.resolve(outputDirectory));
  const directories = new Map();
  for (const file of Array.isArray(files) ? files : []) {
    if (!file?.absolute || !GENERATED_REPORT_NAMES.has(outputNameKey(path.basename(file.absolute)))) continue;
    const directory = path.dirname(path.resolve(file.absolute));
    const directoryKey = outputNameKey(directory);
    if (directoryKey === selectedKey || directories.has(directoryKey)) continue;
    try {
      if (await hasGeneratedReportMarker(file.absolute)) directories.set(directoryKey, directory);
    } catch {
      // An unreadable candidate is already represented by scan coverage; never
      // classify it as Modular-owned without verifying the marker.
    }
  }
  return [...directories.values()].sort((left, right) => left === right ? 0 : left < right ? -1 : 1);
}

export function withReportDirectoryContext(result, root, outputDirectory, otherDirectories) {
  return {
    ...result,
    metadata: {
      ...(result.metadata ?? {}),
      reporting: {
        ...(result.metadata?.reporting ?? {}),
        outputDirectory: reportDirectoryDisplay(root, outputDirectory),
        otherGeneratedReportDirectories: otherDirectories.map((directory) => reportDirectoryDisplay(root, directory)),
      },
    },
  };
}

export async function validateOutputTarget(output) {
  let stat;
  try {
    stat = await fs.stat(output);
  } catch (error) {
    if (error?.code === "ENOENT") {
      let candidate = path.dirname(output);
      for (;;) {
        try {
          const parentStat = await fs.stat(candidate);
          if (!parentStat.isDirectory()) {
            throw new CliError(`Report output path has a parent that is not a directory: ${candidate}`);
          }
          return;
        } catch (parentError) {
          if (parentError instanceof CliError) throw parentError;
          if (parentError?.code !== "ENOENT") {
            if (parentError?.code === "ENOTDIR") {
              throw new CliError(`Report output path has a parent that is not a directory: ${candidate}`);
            }
            const code = parentError?.code ? ` (${parentError.code})` : "";
            throw new CliError(`Report output path could not be inspected${code}: ${output}`, EXIT.failed);
          }
          const parent = path.dirname(candidate);
          if (parent === candidate) throw parentError;
          candidate = parent;
        }
      }
    }
    if (error?.code === "ENOTDIR") {
      throw new CliError(`Report output path has a parent that is not a directory: ${output}`);
    }
    const code = error?.code ? ` (${error.code})` : "";
    throw new CliError(`Report output path could not be inspected${code}: ${output}`, EXIT.failed);
  }
  if (!stat.isDirectory()) throw new CliError(`Report output path is not a directory: ${output}`);

  const entries = await fs.readdir(output, { withFileTypes: true });
  const unexpected = [];
  for (const entry of entries) {
    const nameKey = outputNameKey(entry.name);
    const isKnownReport = entry.isFile() && GENERATED_REPORT_NAMES.has(nameKey);
    const machineFormat = entry.isFile() ? MACHINE_REPORT_NAMES.get(nameKey) : null;
    const isAllowedFile = entry.isFile()
      && (isKnownReport
        || Boolean(machineFormat)
        || nameKey === ".gitkeep"
        || nameKey === outputNameKey(REPORT_LOCK_FILE)
        || nameKey === outputNameKey(MACHINE_REPORT_LOCK_FILE)
        || isGeneratedReportTemporaryFile(entry.name));
    if (!isAllowedFile) {
      unexpected.push(entry);
    } else if (isKnownReport || machineFormat) {
      const owned = isKnownReport
        ? await hasGeneratedReportMarker(path.join(output, entry.name))
        : await isOwnedMachineReport(path.join(output, entry.name), machineFormat);
      if (!owned) unexpected.push(entry);
    }
  }
  if (unexpected.length > 0) {
    unexpected.sort((left, right) => left.name === right.name ? 0 : left.name < right.name ? -1 : 1);
    const examples = unexpected.slice(0, 3).map((entry) => entry.name).join(", ");
    throw new CliError(
      `--output must be an empty/dedicated Modular report directory. Refusing to overwrite or exclude existing content found there: ${examples}.`,
    );
  }
}

export function isInside(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

export function isInsideOrEqual(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}
