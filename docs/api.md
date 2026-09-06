# JavaScript and TypeScript API

Use the API to embed Modular in a Node.js tool, inspect findings in memory, or control when reports are written. Use the CLI when you want the complete configuration, discovery, policy, runtime, and exit-code workflow without assembling it yourself.

[Documentation](./README.md) · [Getting started](./getting-started.md) · [Report format](./reports.md)

## Requirements and entry points

Modular is an ESM package and requires Node.js **22.12.0 or later**. The [getting started guide](./getting-started.md) covers running a checkout and installing a locally built package; an npm registry release is not assumed.

| Import | Purpose |
| --- | --- |
| `modular-check` | File discovery, scanners, finding models, policy, reports, and runtime helpers |
| `modular-check/cli` | `runCli`, argument parsing, usage text, and exit-code constants |
| `modular-check/runtime` | Browser audits, capability discovery, and the static preview server |
| `modular-check/package.json` | Package metadata |

These are the supported package entry points. Internal paths such as `modular-check/src/scanners/security.js` are not exported. TypeScript declarations are bundled; no separate types package is needed. The current API is version `0.1.0`, so review the [changelog](../CHANGELOG.md) when upgrading.

## A complete example from a checkout

Create `.release-output/api-example.mjs` in the Modular checkout and paste the following code. Run it from the checkout root with `node .release-output/api-example.mjs`. It scans the included demo and writes Markdown, JSON, and SARIF under `.release-output/api-report`.

```js
import path from "node:path";
import { readFile } from "node:fs/promises";
import {
  EXIT,
  applyFindingPolicy,
  collectFiles,
  detectWebProject,
  findingsAtOrAbove,
  runSecurityScan,
  runSiteScan,
  writeMachineReports,
  writeScanReports,
} from "../src/index.js";

const root = path.resolve("examples/basic-site");
const outputDirectory = path.resolve(".release-output/api-report");
const { version: toolVersion } = JSON.parse(
  await readFile(new URL("../package.json", import.meta.url), "utf8"),
);

const inventory = await collectFiles(root, {
  excludeDirectories: [outputDirectory, path.join(root, "Modular")],
});
if (inventory.skipped.limit || inventory.skipped.totalBytes) {
  throw new Error("Discovery reached a file-count or total-byte limit.");
}
console.log("Inventory exclusions:", inventory.skipped);

const detection = await detectWebProject({ root, files: inventory.files });
if (!detection.isWebsite) {
  throw new Error(`Website detection failed: ${detection.reasons.join(" ")}`);
}

const results = [];
const expectedModes = ["security", "mysite"];
for (const scan of [runSecurityScan, runSiteScan]) {
  const rawResult = await scan({
    root,
    files: inventory.files,
    skipped: inventory.skipped,
    options: { maxFindingsPerRule: 50 },
  });
  const result = applyFindingPolicy(rawResult);
  results.push(result);

  await writeScanReports(result, {
    outputDirectory,
    overviewResults: results,
    afterReportCommit: () => writeMachineReports(results, {
      outputDirectory,
      formats: ["json", "sarif"],
      toolVersion,
      complete: results.length === expectedModes.length,
      expectedModes,
    }),
  });
}

console.log(`Reports written to ${outputDirectory}`);
process.exitCode = results.some(
  (result) => findingsAtOrAbove(result, "high").length > 0,
) ? EXIT.threshold : EXIT.ok;
```

The demo intentionally contains findings, so this example exits with **3** after successfully writing its reports. Remove the final threshold assignment if your host application only needs results and should choose its exit code elsewhere. An exception aborts the example; reports from any completed phase remain available.

In an application that has installed the package, change the source import to `from "modular-check"` and choose your own `root`, `outputDirectory`, and version lookup. Keep generated reports out of the input inventory. The example excludes both its own output and the `Modular/` reports created by an earlier `npm run demo`.

## What the scanners do, and what you supply

`runSecurityScan(input)` and `runSiteScan(input)` return promises for `ScanResult<"security">` and `ScanResult<"mysite">`. They do not discover files: `files` defaults to an empty array. Call `collectFiles` first and pass both `files` and `skipped`, so exclusions remain visible in the result.

Both scanners independently verify that the supplied root and inventory describe a website. A failed check rejects with an error whose `code` is `NOT_A_WEBSITE` and whose `details` contain the detection result. Calling `detectWebProject` first lets an integration present those reasons earlier; it does not bypass the scanners' checks.

The direct scanner functions do not load `.modular.json`, apply suppressions or baselines, write reports, set your process exit code, or automatically run a browser audit. Those steps belong to the caller. `options.auditDependencies: true` explicitly enables dependency advisory lookup for the security scanner; it is not needed for the offline example above.

The collection defaults are 20,000 files, 1,500,000 bytes per file, and 128 MiB of total readable source. Configure `maxFiles`, `maxFileBytes`, and `maxTotalBytes` on `collectFiles` when needed. Inspect `skipped`, rule applicability, and result metadata before treating a scan as complete. The example rejects aggregate discovery limits but only prints other exclusions; it does not reproduce the CLI's `--fail-on-incomplete` gate.

`onProgress` accepts a synchronous or asynchronous callback receiving a `ScannerProgress` object, including `current`, `total`, and optional `stage` and `file` fields. Keep that callback inexpensive because the scanner awaits progress delivery.

## Policy and result handling

A `ScanResult` contains its mode, timing, inventory count, retained `findings`, severity/risk `summary`, and `metadata`. Findings include severity, confidence, evidence, a recommendation, source location when available, and a `manual` flag. A manual finding requires review; severity alone does not establish an exploitable vulnerability.

Use `applyFindingPolicy` to produce a result annotated with baseline states and accepted suppressions. For an existing baseline:

```js
import { applyFindingPolicy, loadBaseline } from "modular-check";

const baseline = await loadBaseline(baselinePath, { root });
const governed = applyFindingPolicy(rawResult, {
  baseline,
  suppressions: [{
    rule: "a11y-form-label",
    path: "src/legacy/**",
    reason: "Tracked migration of the legacy settings UI.",
    expires: "2027-01-31",
  }],
});
```

Here `baselinePath`, `root`, and `rawResult` come from your integration. Use a real, reviewed exception and an appropriate expiry date. Expired suppressions no longer suppress matching findings.

Policy annotations preserve findings and the original summary score. They affect active threshold checks, not the underlying evidence. Use these helpers instead of filtering only `result.findings`:

| Check | Call |
| --- | --- |
| Unsuppressed high or critical findings | `findingsAtOrAbove(result, "high")` |
| New high or critical findings against a loaded baseline | `findingsAtOrAbove(result, "high", { newOnly: true })` |
| New findings or severity increases at high or above | `findingsAtOrAbove(result, "high", { regressionsOnly: true })` |
| Create an in-memory baseline | `createBaselineDocument(results)` |
| Persist a baseline | `await writeBaseline(baselinePath, results, { root, toolVersion })` |

Built-in scanners keep a compact finding index when per-rule detail limits truncate the displayed findings. Policy and baseline helpers use that index, so a threshold match may have `detailOmitted: true` and lack a full evidence excerpt. See [reports](./reports.md) for counts, fingerprints, score interpretation, and completeness fields.

`loadProjectConfiguration` and `validateProjectConfiguration` are available for integrations that want to read the JSON policy themselves. Loading configuration does not apply it to a scanner: map discovery options to `collectFiles`, scanner options to the runner, and policy settings to the policy helpers. Use `runCli` when you want the existing merge and validation behavior.

## Reports and CLI embedding

`writeScanReports(result, options)` writes the built-in mode's detailed report, action plan, and shared overview; its return value is a promise for the written paths. Supply `overviewResults` when assembling multiple modes. The example's `afterReportCommit` callback coordinates machine output with each completed Markdown phase.

`createJsonReport(results, options)` and `createSarifReport(results, options)` return plain objects without writing files. `writeMachineReports` writes selected formats and returns their paths. For incremental runs, pass `complete: false` until every requested mode finishes and supply `expectedModes`; that flag describes the run's phases, not a guarantee of exhaustive source or runtime coverage.

For the complete CLI workflow inside a Node.js application:

```js
import { runCli } from "modular-check/cli";

const code = await runCli([
  "check", "all",
  "--root", projectRoot,
  "--output", reportDirectory,
  "--json",
  "--fail-on", "high",
], {
  stdout: process.stdout,
  stderr: process.stderr,
  setExitCode: () => {},
});
// The host decides how to use `code`; this call does not set its exit code.
```

`projectRoot` and `reportDirectory` are paths supplied by the host. Omitting `setExitCode` lets `runCli` set `process.exitCode`. Its second argument also accepts `signal: abortController.signal` for cancellation. See [getting started](./getting-started.md) for command usage.

## Runtime and module registry

`runRuntimeBrowserAudit` returns a separate `RuntimeAuditResult`. `startRuntimeStaticServer` returns a server handle with an asynchronous `close()` method; use `try/finally` to close it. These are explicit operations and can load browser dependencies and execute page JavaScript. Read the [runtime guide and trust boundary](./runtime.md) before enabling them. A standalone runtime result is not automatically merged into a site result; use the CLI when you want its combined reporting behavior.

`SCAN_MODULES` describes the two built-in modes. `getScanModule("security")` returns a descriptor whose asynchronous `load()` resolves to the scanner function. `createScanModuleRegistry` validates and freezes explicitly supplied definitions. It does **not** install modules, discover project plugins, or register new CLI commands. The built-in CLI, Markdown reports, and baselines use the built-in mode list; a custom registry alone does not extend those workflows.

## Types and contributing

Useful exported types include `FileCollection`, `ScannerInput`, `ScannerProgress`, `Finding`, `ScanResult`, `ProjectConfiguration`, `RuntimeAuditInput`, and `RuntimeAuditResult`. For example:

```ts
import { runSiteScan, type ScanResult, type Severity } from "modular-check";

const threshold: Severity = "high";
const result: ScanResult<"mysite"> = await runSiteScan(input);
```

`input` is a `ScannerInput` assembled as in the complete example. The declarations use a broad `Record<string, unknown>` for scanner `options` and extensible metadata; that does not imply arbitrary option names have an effect. The checked declarations are in [`src/index.d.ts`](../src/index.d.ts). The source checkout also includes `type-tests/public-api.ts` for development validation; test fixtures are not bundled in the installed package. See [contributing](../CONTRIBUTING.md) for development and validation commands.
