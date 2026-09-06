# CLI reference

[Documentation](./README.md) · [Getting started](./getting-started.md) · [Runtime audits](./runtime.md)

Modular requires Node.js **22.12.0 or later**. The examples below use the `modular` command provided by a local package installation or `npm link`; see [installation](./getting-started.md). From a Modular checkout, `node bin/modular.js` is the equivalent entry point.

## Choose a command

```sh
modular check all --root ./my-web-app --json --sarif
```

| Command | What it does |
| --- | --- |
| `check security` | Scans source and configuration for security signals, credentials, and supply chain risks. |
| `check mysite` | Scans site source for accessibility, SEO, performance, maintainability, and related review items. |
| `check all` | Runs both modules using one repository inventory and website detection step. |
| `doctor` | Checks local scan readiness without producing reports or running audits. |
| `--help`, `-h` | Prints usage and supported options. |
| `--version`, `-v` | Prints the installed Modular version. |

All three `check` commands require a detected website project, including `check security`. A repository that does not pass that gate exits with code `2`. In a monorepo, select a root that contains the intended frontend and any backend source you want included. Read [coverage](./coverage.md) before interpreting a clean result.

Static scanning is the default. Dependency advisory lookup and browser execution require their own CLI opt-ins. Project configuration cannot enable either operation.

## Repository and output options

Options take a separate value, such as `--root ./app`; `--root=./app` is not supported. Quote paths containing spaces.

| Option | Default | Behavior |
| --- | --- | --- |
| `--root <path>` | Current working directory | Repository to scan. A relative root is resolved from the working directory. |
| `--output <path>` | `<root>/Modular` | Dedicated directory for generated reports. Relative paths resolve from `--root`. |
| `--ignore <directory>` | Built-in exclusions | Adds an exact directory name at any depth; repeat to add more names. Paths and globs are rejected. |
| `--max-files <number>` | `20000` | Maximum inventoried files before discovery fails. |
| `--max-file-size <bytes>` | `1500000` | Maximum readable text size per file. Larger files remain inventoried but their content is skipped. |
| `--max-total-size <bytes>` | `134217728` | Total readable source budget. Exceeding it stops the scan. |
| `--max-findings-per-rule <number>` | `50` per module | Caps retained finding details per rule; complete finding identities still drive policy when the index is complete. |
| `--json` | Off | Adds `modular-results.json` in the report directory. |
| `--sarif` | Off | Adds `modular-results.sarif` in the report directory. |
| `--no-color` | Color enabled | Disables ANSI colors. |
| `--quiet` | Off | Prints failures only. Report writing still occurs. |

All numeric CLI limits must be positive safe integers. See [reports](./reports.md) for retained details, the finding index, and completion metadata; a detail cap does not mean only that many findings were detected.

Built-in directory exclusions include `.git`, `node_modules`, `vendor`, `dist`, `build`, framework caches, coverage directories, and browser test output. Modular does not use `.gitignore` as its exclusion policy. For example, an ignored local `.env` can still be scanned. The selected report directory is excluded from source discovery.

```sh
modular check all --root ./apps/store --output quality-reports --ignore generated --ignore fixtures --json
```

This writes into `./apps/store/quality-reports`, relative to the working directory from which the command is launched. It does **not** write into `./quality-reports`.

The output must be empty or contain only recognized Modular report files and allowed report bookkeeping. It cannot be the repository root. Modular refuses an output directory containing unrelated files. Relative output paths cannot escape `--root`; use an explicit absolute path if reports belong elsewhere.

## Configuration, baselines, and CI gates

| Option | Default | Behavior |
| --- | --- | --- |
| `--config <file>` | `<root>/.modular.json`, if present | Reads an explicit JSON policy file. |
| `--no-config` | Off | Disables project configuration discovery; incompatible with `--config`. |
| `--baseline <file>` | None | Compares findings against a saved Modular baseline. |
| `--write-baseline <file>` | None | Atomically creates or updates a baseline after scan completion checks. |
| `--fail-on <severity>` | `none` | Exits `3` for any unsuppressed finding at or above the threshold. |
| `--fail-on-new <severity>` | `none` | Exits `3` for unsuppressed baseline-new findings at or above the threshold. Requires a baseline. |
| `--fail-on-regression <severity>` | `none` | Exits `3` for new or severity-increased unsuppressed findings at or above the threshold. Requires a baseline. |
| `--fail-on-incomplete` | Off | Exits `1` if discovered source coverage is incomplete. |

Severity thresholds are `critical`, `high`, `medium`, `low`, `info`, or `none`. For example, `high` includes both high and critical findings. Gates act on reported severity, including findings marked for manual review; they do not independently confirm exploitability.

Relative CLI config and baseline paths resolve from `--root` and must stay inside it. Explicit absolute paths can point elsewhere. Baselines must stay outside the generated report directory. Configuration values and CLI overrides are described in [configuration](./configuration.md).

Create a baseline after reviewing the existing findings:

```sh
modular check all --root ./my-web-app --write-baseline .modular-baseline.json --json
```

Then compare a later scan against it:

```sh
modular check all --root ./my-web-app --baseline .modular-baseline.json --fail-on-regression high --fail-on-incomplete --json --sarif
```

Do not routinely add `--write-baseline` to the comparison command: it updates the baseline before severity gates run, so a command can both write a new baseline and exit `3`. Missing or invalid baselines are errors; Modular does not silently create one for comparison.

`--fail-on-incomplete` concerns discovered source coverage. Explicitly requested dependency and browser audits already exit `1` when incomplete, even without this flag. Deliberately ignored directories are outside the source scan's scope.

## Optional execution

| Option | Applies to | Behavior |
| --- | --- | --- |
| `--dependency-audit` | `security`, `all` | Enables a network advisory lookup using a supported npm/pnpm lockfile and an available compatible package manager. |
| `--no-dependency-audit` | `security`, `all` | Disables the advisory lookup; this is already the default. |
| `--runtime` | `mysite`, `all` | Enables browser auditing; requires exactly one of `--url` or `--runtime-static-dir`. |

```sh
modular check security --root ./my-web-app --dependency-audit --json
```

Dependency auditing uses a temporary sanitized manifest and lockfile. It does not load the repository's package manager configuration, plugins, or lifecycle scripts. Unsupported lockfiles, missing tools, timeouts, and lookup failures are reported as incomplete requested coverage; no completed lookup means no current advisory assurance. See [coverage](./coverage.md) for the supported scope.

The full runtime option reference and setup are in [runtime audits](./runtime.md). Runtime flags are rejected without `--runtime`, and `check security --runtime` is invalid.

## Doctor

```sh
modular doctor --root ./my-web-app --no-color
```

Doctor validates the Node.js version, repository accessibility, configuration and baseline structure, dedicated output target, nearest existing output parent's write access, discovery budgets, and website detection. It also reports source coverage limitations and expired suppressions. It does not create the output directory, write reports, run repository scripts, query dependency registries, or launch a browser.

Doctor accepts only these options:

```text
--root <path>             --output <path>
--ignore <directory>      --max-files <number>
--max-file-size <bytes>   --max-total-size <bytes>
--config <file>           --no-config
--baseline <file>         --no-color
```

Global help and version flags also work. Flags such as `--json`, `--quiet`, `--runtime`, `--dependency-audit`, and `--fail-on` are not doctor options. A successful doctor result means local static scanning is ready; it does not verify Playwright, Axe, browser binaries, network access, or the correctness of the website.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command completed and no enabled finding gate was reached, or doctor found no blocking readiness issue. Findings may still be present. |
| `1` | Execution failure, failed doctor readiness, incomplete requested dependency/browser audit, or incomplete source coverage when gated. |
| `2` | Invalid command, option, path, policy, baseline, output target, or a failed website gate during `check`. |
| `3` | A finding severity, baseline-new, or regression gate was reached. |
| `130` | Interrupted by `SIGINT`. |
| `143` | Interrupted by `SIGTERM`. |

Reports from completed phases are preserved when a later phase fails or a scan is interrupted. Incomplete requested coverage is evaluated before severity gates, so exit `1` takes precedence over `3`. Read the report's completion metadata before consuming findings from an unsuccessful command.

For errors and recovery steps, see [troubleshooting](./troubleshooting.md). Return to the [project README](../README.md).
