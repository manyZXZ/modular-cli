<div align="center">
  <img src="./assets/modular-logo.png" width="144" alt="Modular" />
  <h1>Modular</h1>
  <p><strong>Security and website quality, reviewed from your repository.</strong></p>
  <p>Node.js 22.12+ · MIT · No runtime dependencies</p>
</div>

Modular is a local CLI for reviewing web applications before a release. It scans source code for security risks and website quality issues, then produces reports with evidence, source locations and suggested fixes. Add a browser run when you need evidence from the rendered page.

[Get started](#quick-start) · [Documentation](./docs/README.md) · [Türkçe](./docs/README.tr.md) · [Contribute](./CONTRIBUTING.md)

## What you can review

| Module | Areas covered |
|---|---|
| **Security** | Credential patterns, browser injection sinks, bounded server data flows, JWT configuration, transport, CI and selected container/infrastructure settings |
| **Website quality** | Accessible names and semantics, metadata, crawlability, structured data, responsive layout signals and asset delivery |
| **Optional browser audit** | Rendered DOM, Axe checks, console/network errors, response headers and laboratory LCP/CLS |

Static scans run without an AI model, API key or network service. Source code is read as data and is never modified by a scan. Dependency advisories and browser execution are separate opt-ins.

Modular accepts supported **website projects**, including monorepos with a web application and backend. A standalone CLI, backend-only service or native app does not pass the website gate. Detection supports static HTML and common JavaScript frameworks; see [coverage and limitations](./docs/coverage.md) for the boundaries.

## Quick start

Clone or download this repository and open a terminal in its root. You need Node.js **22.12 or newer**, with npm. These commands use the source checkout and do not depend on a registry release.

```console
node bin/modular.js --version
npm run demo
```

The [demo](./examples/README.md) scans a small, deliberately incomplete website. Open `examples/basic-site/Modular/00-overview.md` to see its results. No dependency installation is needed for this static scan.

Now scan your own project:

```console
node bin/modular.js check all --root "path/to/your/website" --json --sarif
```

Replace the path with your website directory. Reports go into `Modular/` inside that directory. To use the shorter `modular` command from any folder, run `npm link` in this checkout.

[Installation, Windows paths and local archives →](./docs/getting-started.md)

## From a finding to a fix

The demo's email field produces this finding:

```text
a11y-form-label · high · index.html:14
Form control has no programmatic label
```

The detailed report explains the evidence and recommends associating a visible label with the control. Review the evidence, fix the relevant source, then rerun the same command. Modular does not apply fixes automatically.

Each run writes an overview and the selected module's report/action plan. A combined scan produces:

```text
Modular/
├── 00-overview.md
├── 01-security-report.md
├── 02-security-action-plan.md
├── 03-site-report.md
├── 04-site-action-plan.md
├── modular-results.json       # with --json
└── modular-results.sarif      # with --sarif
```

Findings carry severity, confidence and a manual-review flag. A completed scan means the requested work finished; it does not certify that the site is secure or accessible. The score helps prioritize review, and is not a measured accuracy percentage. [Learn how to read the results.](./docs/reports.md)

## Use it in your workflow

After linking or installing the local package:

```console
modular check security --root "path/to/site"
modular check mysite --root "path/to/site"
modular check all --root "path/to/site" --fail-on high --json --sarif
modular doctor --root "path/to/site"
```

Scans are advisory by default. `--fail-on high` returns exit code `3` when an unsuppressed high or critical finding is present. A reviewed baseline lets you gate only new findings or severity regressions. [Configure a project policy](./docs/configuration.md) or [add a CI job](./docs/ci.md).

For an existing build and a trusted Playwright installation:

```console
modular check mysite --root "path/to/site" --runtime --runtime-static-dir dist --runtime-spa-fallback
```

Runtime setup, browser selection and the difference between a static preview and a deployed application are covered in the [browser audit guide](./docs/runtime.md).

## Documentation

- [Getting started](./docs/getting-started.md) — installation and your first real scan.
- [CLI reference](./docs/cli.md) — commands, options, defaults and exit codes.
- [Configuration](./docs/configuration.md) — project policy, baselines and suppressions.
- [Reports](./docs/reports.md) — evidence, scores, coverage and machine output.
- [Coverage](./docs/coverage.md) — supported inputs, privacy and analysis limits.
- [Browser audits](./docs/runtime.md), [CI](./docs/ci.md), [troubleshooting](./docs/troubleshooting.md) and [JavaScript API](./docs/api.md).

## Development

```console
npm ci --ignore-scripts
npm run release:check
```

The release gate checks the public file set, tests, TypeScript API, CLI, archive contents and an offline installation. Real Chromium/Axe integration runs separately in CI; see [Contributing](./CONTRIBUTING.md) for the local command.

Found a scanner error? Include a small, synthetic reproduction. Report confidential security issues through the process in [SECURITY.md](./SECURITY.md).

[Changelog](./CHANGELOG.md) · [Release process](./RELEASING.md) · [Code of conduct](./CODE_OF_CONDUCT.md) · [MIT license](./LICENSE)
