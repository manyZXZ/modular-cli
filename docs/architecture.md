# Source architecture

This guide is for contributors changing Modular's implementation. Package consumers should use the supported entry points in the [API guide](./api.md).

## Entry points and orchestration

`bin/modular.js` handles process signals and invokes `src/cli.js`. The CLI coordinates discovery, website detection, scanner dispatch, optional browser auditing, finding policy, report publication and exit codes. The public exports remain in `src/index.js`, `src/cli.js` and `src/runtime/index.js`; the adjacent TypeScript declarations describe those contracts.

Built-in module IDs, capabilities, lazy scanner loaders and Markdown filenames are defined once in `src/core/modules.js`. Both scanners validate the website boundary when called directly through the JavaScript API.

## Where to make a change

| Area | Source | Responsibility |
|---|---|---|
| Command line | `src/cli.js`, `src/cli/` | Orchestration, argument validation and help, configuration precedence, output preflight, doctor, runtime integration, interrupts and exit codes |
| Repository input | `src/core/files.js`, `src/core/project.js`, `src/core/syntax.js` | Confined file discovery and reads, website detection, bounded shared syntax helpers |
| Security | `src/scanners/security.js`, `src/scanners/security/`, `src/scanners/security-dataflow.js`, `src/scanners/security-catalog.js` | Security rules, optional dependency-audit orchestration, isolated processes, dependency privacy checks, advisory parsing and standards metadata |
| Website quality | `src/scanners/mysite.js`, `src/scanners/mysite/` | Site scope and orchestration, rule catalog, markup parsing, document and Markdown audits, styles and asset budgets |
| Browser auditing | `src/runtime/browser-audit.js`, `src/runtime/browser-probes.js`, `src/runtime/snapshot.js`, `src/runtime/audit-findings.js`, `src/runtime/url-policy.js` | Browser lifecycle, page-context probes, metric normalization, finding construction and network policy |
| Static build server | `src/runtime/static-server.js` | Opt-in, confined serving of an existing build |
| Findings and policy | `src/core/model.js`, `src/core/policy.js`, `src/core/config.js`, `src/core/sanitize.js` | Finding normalization, scoring, baselines, suppressions, strict configuration and redaction |
| Markdown reports | `src/core/reporter.js`, `src/core/reports/` | Report coordination, rendering, ownership checks, locking and transactional publication |
| Machine reports | `src/core/machine-reporter.js` | JSON/SARIF serialization and atomic publication |

## Module boundaries

Internal modules import their dependencies explicitly. Keep shared helpers below the orchestrators so they do not need to import back from the public entry point. Internal exports are implementation details; adding one does not add a supported package API.

CLI errors and exit handling share one definition in `src/cli/errors.js`. The parser's explicit-option symbol is shared with configuration loading so a command-line setting continues to take precedence over project defaults. Keep package-relative resource resolution at its original boundary when moving code that uses `import.meta.url`.

Functions in `src/runtime/browser-probes.js` execute in the page context after Playwright serializes them. Their bodies must be self-contained: imported helpers and Node.js variables are not available inside the browser. Snapshot normalization and finding construction execute in Node.js.

Report storage owns the in-process queue, cross-process locks, identity checks and rollback sequence. Renderers prepare Markdown; the public writer keeps Markdown and optional machine-report publication inside the same report lock. Markdown commits before the machine-report callback, and each writer owns its transaction. Moving a helper must not create a second lock registry or change callback ordering.

Scanner helpers preserve source offsets, finding identity, ordering, evidence redaction and declared coverage. Prefer a focused module with explicit inputs when separating another rule area. Keep optional network and browser execution controlled by the existing opt-in paths.

## Verification

Use the relevant existing regression suites while changing an area. Before handing off the complete change, run `npm run release:check`; it verifies repository contents, tests, public types, help, package contents and installation of the actual archive offline.

For runtime changes, also run `npm run test:browser` with an available Playwright browser. The script supports an installed Chrome/Edge channel through `MODULAR_TEST_BROWSER_CHANNEL`. For security-rule changes, run `npm run test:accuracy`. See [Contributing](../CONTRIBUTING.md) for setup and test expectations.

[Back to documentation](./README.md)
