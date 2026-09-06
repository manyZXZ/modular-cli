# Troubleshooting

Start with the command, exit code and selected root. A failure before discovery may produce no reports; a failure after a completed phase can leave useful partial output. Check [report completion fields](./reports.md#json-and-sarif-completion) before consuming it.

```console
modular --version
node --version
modular doctor --root "path/to/website" --no-color
```

Doctor checks local static-scan readiness, not Playwright/Axe or the website's correctness.

## Modular is not recognized

Use the source entry point from the Modular checkout:

```console
node bin/modular.js --help
```

If this works, the problem is command resolution. Run `npm link` in the checkout or install a local archive, then reopen the terminal and check that your npm global executable directory is on `PATH`.

On Windows, if PowerShell refuses the generated `.ps1` shim, try `modular.cmd --help` or the direct Node entry point. This does not require changing the system execution policy. See [installation](./getting-started.md).

## The project is not recognized as a website

Check `--root`. It must point to a supported website source project or a monorepo containing one. Standalone backends, CLIs and native apps are outside the current product scope. A folder containing only a build artifact may lack the source structure needed for detection.

For an auxiliary-looking website folder, select it directly:

```console
modular doctor --root ./docs
modular check all --root ./docs
```

Use those paths only when `docs` is actually the website. Inspect detection reasons rather than adding dummy HTML or disabling limits to force acceptance. [Coverage](./coverage.md#supported-project-shapes) lists the supported shapes.

## The output directory is rejected

The selected output must be a dedicated empty directory or contain only verified Modular reports and an optional `.gitkeep`. The repository root, an application source folder, or a directory containing handwritten notes is not a valid target.

Choose a fresh path rather than deleting unrelated files:

```console
modular check all --root ./web --output review-output-2 --json
```

The path above is `web/review-output-2`. Relative output paths cannot escape `--root`; choose an explicit absolute path if you need output elsewhere. Do not manually edit Modular ownership markers to bypass the check.

## The scan completed but exited 3

An enabled severity/new/regression gate matched a finding. That is a policy result, not a scanner crash. Read the action plan and policy metadata. Manual-review findings still count unless suppressed, and an all-findings `failOn` gate remains active even when you also configure a baseline gate.

Review [configuration](./configuration.md) before changing thresholds. Do not repeatedly rewrite a baseline merely to make the job green.

## Baseline or configuration errors

Unknown JSON keys, missing baselines, malformed expiry dates and relative paths escaping the root fail with exit code `2`. Baseline comparison requires an existing Modular baseline outside the report directory. Create it only after reviewing a scan.

To compare against CLI defaults without editing the project file:

```console
modular check all --root ./web --no-config --json
```

`--no-config` and `--config` cannot be combined. Configured output formats/ignore names are additive with CLI entries; `--json` alone does not remove configured SARIF.

## Source coverage is incomplete

Read the omission counts for oversized, inaccessible, linked or subsequently changed files. Resolve permissions and source changes or select the intended real source directory. Raising a size limit can be reasonable after you inspect the file, but it will not fix a link or permission error.

```console
modular check all --root ./web --max-file-size 3000000 --fail-on-incomplete --json
```

File-count and total-source-byte budgets are separate. Intentionally ignored directories and unsupported formats are outside scope; adding an ignore solely to hide a coverage error reduces what the scan can establish.

## Playwright, Axe or a browser is unavailable

Install the optional tooling where runtime resolution can find it: normally the target website root. Installing Playwright's JavaScript package does not necessarily install its browser executable. Follow [runtime setup](./runtime.md#install-the-optional-tools).

If a compatible Playwright package is already available, an installed Chrome channel can be selected:

```console
modular check mysite --root ./web --runtime --runtime-static-dir dist --browser-channel chrome --json
```

Chrome must actually be installed. Firefox/WebKit may lack required performance observations, so a selectable browser is not a guarantee of complete LCP/CLS coverage. Missing Axe or other requested runtime coverage produces exit `1`, not a successful empty accessibility result.

## Runtime stays on Loading or reports session errors

A static build server has no API proxy, authentication service or backend. An older build can also differ from your current source. Reproduce against the normally running application and required services:

```console
modular check mysite --root ./web --runtime --url http://127.0.0.1:4173/ --json
```

Use your actual local URL. The runtime waits for a bounded DOM quiet period and recognized loading indicators to clear. A readiness timeout marks coverage partial. Increasing the total timeout is not a substitute for starting a missing backend, and the CLI does not expose every per-stage API deadline.

## Remote requests are blocked

Local-only runtime mode blocks non-loopback resources, including fonts, analytics and API hosts. The blocked requests can change the rendered page; the result is partial coverage. Enable `--allow-remote` only when that broader page traffic is intended. It permits remote resources, not just the initial target origin.

Routes still need the base URL's origin. The base route counts toward the limit; with the default five-route budget, specify at most four additional `--route` arguments.

## Dependency advisories are unavailable

An explicit advisory audit needs a supported, unambiguous npm/pnpm graph and a compatible installed package manager. Registry configuration, private/custom dependency sources or unsafe manager configuration may prevent the isolated lookup. Read the reported reason instead of removing required project configuration just to force the audit.

Use your organization's approved dependency-review process when isolation requirements cannot be met. See [advisory coverage](./coverage.md#dependency-advisories). A skipped or unavailable lookup says nothing about current CVEs.

## Report a reproducible scanner problem

Include the Modular version, operating system, Node.js version, sanitized command, exit code, expected result and smallest synthetic source example. For a missed finding, explain the source-to-sink or rendered behavior that should have been detected. For a false positive, include the guard or framework behavior that makes it safe.

Do not attach real keys, private source or unreviewed reports. Security-boundary problems use [the private reporting process](../SECURITY.md); other rule-quality issues follow [Contributing](../CONTRIBUTING.md).

[Documentation index](./README.md) · [CLI reference](./cli.md)
