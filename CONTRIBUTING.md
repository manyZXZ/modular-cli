# Contributing to Modular

Thank you for helping make Modular more accurate and useful. Small, focused changes with evidence and regression tests are easiest to review.

## Before you start

- Search existing issues and pull requests before opening a duplicate.
- Use a private security advisory for security-boundary problems or sensitive reproductions; see [SECURITY.md](./SECURITY.md).
- Discuss large behavior changes in an issue before investing in an implementation.
- Never include private repositories, production credentials or generated reports containing sensitive evidence in a public contribution.

## Development setup

Modular requires Node.js 22.12 or newer and npm. It has no runtime dependencies.

```console
# Clone or download this repository and open its root directory.
npm ci --ignore-scripts
npm test
npm run test:types
npm run smoke
```

Run the source CLI against a disposable website fixture or a repository you are authorized to inspect:

```console
node ./bin/modular.js check all --root "path/to/site" --output Modular
```

The output path resolves inside the selected website root. Use an empty directory or a previous Modular report directory. See the [documentation index](./docs/README.md) for usage and the [API guide](./docs/api.md) for programmatic integration.

Do not use runtime mode with an untrusted installed dependency tree or built site: runtime capability discovery imports project-local Playwright/Axe packages, and audited page code executes in the browser context. Do not point development builds at an untrusted live target with `--allow-remote`.

## Making a change

1. Keep the change scoped and preserve existing public APIs unless the issue explicitly calls for a breaking change.
2. For behavior changes, add tests for expected behavior and relevant failure cases.
3. Run `npm run release:check` (public Git file set, unit/integration tests, public type contract, CLI smoke, package inventory and a real offline archive installation).
4. Update the relevant guide and CHANGELOG when user-visible behavior changes. Keep README focused on the first scan; put detailed options in the CLI reference. Verify documented commands against the current CLI and run `npm run package:check` to check that local documentation links resolve in the published archive.
5. Open a pull request using the repository template.

For scanner rules, include both a true-positive and a realistic counterexample. A finding must have a stable rule ID, category, severity, confidence, actionable explanation, sanitized evidence, recommendation and source location where available. Update the check ledger when a rule family is added or removed. Avoid rules that merely count keywords without context.

Add labeled accuracy cases to `test/fixtures/security-accuracy.json` and run `npm run test:accuracy`. Mark regression and validation partitions accurately; generated identifier/line-offset transformations exercise invariance. Report corpus results separately from claims about unseen projects. Shared syntax helpers are bounded lexical analysis, so unsupported syntax must not silently establish a safety guarantee.

For runtime changes, also run `npx --no-install playwright install chromium` and `npm run test:browser`. The latter runs real Playwright/Axe on local fixture pages and fails if browser support is missing. An installed Chrome/Edge channel can be selected with `MODULAR_TEST_BROWSER_CHANNEL=chrome` or `msedge`. Dependencies are installed with `npm ci`; network/browser installation is separate from test execution. CI runs this integration in its browser job.

Keep built-in module identity, version, capabilities, lazy runner and report filenames in `src/core/modules.js`. Registry creation must validate without executing module code. Preserve CLI/report/policy consistency when adding a module, and update public TypeScript declarations alongside exported APIs.

See the [source architecture guide](./docs/architecture.md) for module responsibilities, browser callback boundaries and report transaction ownership.

For filesystem, output, dependency-audit or runtime changes, include tests for hostile paths, links, interrupted operations and fail-closed behavior as applicable. Tests must not depend on public network access.

## Pull request expectations

- Explain the problem, the chosen behavior and the evidence used to validate it.
- Keep formatting-only changes separate from behavioral changes when practical.
- Do not commit `audit/`, environment files, `node_modules`, coverage output, packed archives or generated `Modular/` reports. `npm run repo:check` rejects them even if a private file was already tracked.
- Do not edit generated terminal-logo data by hand; use the documented generator and approved asset.
- Ensure all tests pass on Windows and Linux.

By contributing, you agree that your contribution is licensed under the repository's [MIT License](./LICENSE).
