# Modular documentation

Start with a local static scan. Add policy, CI or a browser audit as your workflow needs them. Examples assume the current CLI and a supported website project; they do not require an existing npm registry release.

## Learn the workflow

| Guide | What you will do |
|---|---|
| [Getting started](./getting-started.md) | Run the demo, choose a project root and inspect your first report |
| [Understanding reports](./reports.md) | Separate findings, review items and coverage gaps; interpret scores and machine output |
| [Coverage and limitations](./coverage.md) | Check supported project shapes and understand what each scan can establish |
| [Troubleshooting](./troubleshooting.md) | Resolve detection, output, policy and runtime setup failures |

## Set up a repeatable audit

| Guide | What you will configure |
|---|---|
| [CLI reference](./cli.md) | Commands, options, defaults and exit codes |
| [Project configuration](./configuration.md) | Severity gates, baselines and reasoned suppressions |
| [Browser audits](./runtime.md) | Playwright/Axe, routes, viewports and an existing build or server |
| [Continuous integration](./ci.md) | A source-based GitHub Actions job and retained machine reports |
| [JavaScript API](./api.md) | Use the scanner and report APIs from your own tooling |

## Contribute or maintain

[Contributing](../CONTRIBUTING.md) explains the development loop and rule-quality requirements. [GitHub setup](./GITHUB.md) covers the first source push. [Releasing](../RELEASING.md) covers package publication. These maintainer tasks are separate from scanning a website.

[Source architecture](./architecture.md) maps implementation responsibilities and the boundaries to preserve when refactoring.

For private vulnerability reports, use [the security policy](../SECURITY.md). For a Turkish introduction, read [Türkçe başlangıç rehberi](./README.tr.md).

[Back to the product README](../README.md)
