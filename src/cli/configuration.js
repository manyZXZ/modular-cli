import { loadProjectConfiguration } from "../core/config.js";
import { CLI_SPECIFIED } from "./arguments.js";
import { CliError } from "./errors.js";
import { isInsideOrEqual } from "./paths.js";

function policyPathInsideOutput(options, value) {
  return value && isInsideOrEqual(options.output, value);
}

export async function applyProjectConfiguration(options, runtime) {
  const loader = runtime.loadProjectConfiguration ?? loadProjectConfiguration;
  let loaded;
  try {
    loaded = await loader({
      root: options.root,
      file: options.config,
      disabled: options.configDisabled,
    });
  } catch (error) {
    throw new CliError(error instanceof Error ? error.message : String(error));
  }
  const configured = loaded?.config ?? {};
  const specified = options[CLI_SPECIFIED] ?? new Set();
  if (!specified.has("failOn") && configured.failOn !== undefined) options.failOn = configured.failOn;
  if (!specified.has("failOnNew") && configured.failOnNew !== undefined) options.failOnNew = configured.failOnNew;
  if (!specified.has("failOnRegression") && configured.failOnRegression !== undefined) options.failOnRegression = configured.failOnRegression;
  if (!specified.has("failOnIncomplete") && configured.failOnIncomplete !== undefined) options.failOnIncomplete = configured.failOnIncomplete;
  if (!specified.has("maxFindingsPerRule") && configured.maxFindingsPerRule !== undefined) {
    options.maxFindingsPerRule = configured.maxFindingsPerRule;
  }
  if (!specified.has("baseline") && configured.baseline) options.baseline = configured.baseline;
  options.baselineFromConfig = !specified.has("baseline") && Boolean(configured.baseline);
  options.ignore = [...new Set([...(configured.ignore ?? []), ...options.ignore])];
  options.machineFormats = [...new Set([...(configured.outputFormats ?? []), ...options.machineFormats])].sort();
  options.suppressions = configured.suppressions ?? [];
  options.loadedConfig = loaded?.path ?? null;

  if (options.failOnNew !== "none" && !options.baseline) {
    throw new CliError("--fail-on-new requires --baseline or a baseline path in .modular.json.");
  }
  if (options.failOnRegression !== "none" && !options.baseline) {
    throw new CliError("--fail-on-regression requires --baseline or a baseline path in .modular.json.");
  }
  for (const [label, value] of [["baseline", options.baseline], ["write-baseline", options.writeBaseline]]) {
    if (policyPathInsideOutput(options, value)) {
      throw new CliError(`--${label} must stay outside the generated report directory.`);
    }
  }
  return options;
}
