# Getting started

This guide takes you from the source checkout to a report for your own website. Static scanning needs Node.js 22.12 or newer; npm is used for the demo shortcut and optional installation. Modular has no runtime dependencies for a static scan.

## 1. Try the included website

Clone or download the Modular repository. Open its root directory in a terminal:

```console
node --version
node bin/modular.js --help
npm run demo
```

The [demo project](../examples/README.md) intentionally contains missing page/form metadata and a source-only unsafe HTML sink. It has no real credentials and does not start a server. Open `examples/basic-site/Modular/00-overview.md`, then follow its report and action-plan links.

Findings are expected. The demo exits `0` when the scan completes because its command has no severity gate. No `npm install` is required to run it.

## 2. Choose the scan root

From the Modular checkout:

```console
node bin/modular.js check all --root "../my-website" --json --sarif
```

Replace `../my-website` with your project path. Choose a source directory containing a recognizable website: for example, static `index.html`, a Vite/React app, or a Next.js project. You can choose a monorepo root when it contains a supported web workspace; this also brings relevant server code into the scan. Choose the web workspace itself when you only want that scope.

The Modular source directory is a CLI project. Use the included demo root or your website as the target; running a default scan from the tool's own directory is not the intended workflow.

Build output such as `dist/` is excluded from ordinary source discovery. Scan the source project root; use [runtime mode](./runtime.md) when you want to inspect an already-built site.

### Windows paths

Quote paths containing spaces. Either slash style works on Windows:

```powershell
node .\bin\modular.js check all --root "D:\Projects\My Website" --json --sarif
```

Do not copy a placeholder path literally. `--root` resolves from your current terminal directory. Relative report/configuration/baseline paths resolve from the chosen root, as described in the [CLI reference](./cli.md).

## 3. Read and act on the report

By default, the command writes into `Modular/` under the website root. A combined scan creates five Markdown files; `--json` and `--sarif` add machine reports.

1. Read the overview's coverage notices.
2. Open an action plan and follow a finding to its source location.
3. Check severity, confidence and whether manual validation is required.
4. Fix the application source yourself, then rerun the same command.

An accessible-name finding may be verifiable directly from markup. An HTML sink marked for manual review needs input tracing before you call it an exploitable XSS issue. [Understanding reports](./reports.md) explains that distinction.

Add `Modular/` to your website's `.gitignore` unless your team deliberately stores reviewed reports. Redacted excerpts can still contain private project context.

### A custom report directory

```console
node bin/modular.js check all --root "../my-website" --output review-output --json
```

This writes to `../my-website/review-output`, not to the Modular checkout. The directory must be empty or contain only verified Modular reports (and optionally `.gitkeep`). Keep notes and application files elsewhere. An explicit absolute output directory outside the project is also supported.

## 4. Make the command available everywhere

From the Modular checkout:

```console
npm link
```

Then, from a website directory:

```console
modular check all --json --sarif
modular doctor
```

The linked command follows this checkout. If the shell cannot find it, see [command resolution troubleshooting](./troubleshooting.md#modular-is-not-recognized).

### Install a local archive

For an install that does not depend on a moving checkout:

```console
npm pack --ignore-scripts
npm install --global ./modular-check-0.1.0.tgz
modular --version
```

Use the filename printed by `npm pack` if the version differs. To install as a dependency in another project, run `npm install --save-dev /absolute/path/to/the-archive.tgz` there instead of the global command. The [API guide](./api.md) assumes that local dependency is resolvable.

Registry installation is an alternative only after a maintainer publishes a verified version. Source checkout and local archive instructions above work without assuming that `modular-check` already exists in your registry.

## Next steps

- [Set a project policy](./configuration.md) for consistent local and CI behavior.
- [Run a browser audit](./runtime.md) for rendered evidence.
- [Add CI](./ci.md) after reviewing the initial findings.

[Documentation index](./README.md) · [CLI reference](./cli.md)
