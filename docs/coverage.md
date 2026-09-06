# Coverage, privacy and limitations

Modular is a bounded repository review tool. It provides evidence for triage and optional browser observations; it does not establish that every vulnerability, accessibility failure or product problem has been found.

## Supported project shapes

The website gate uses source structure, manifests and framework indicators. A package name or dependency alone is not a guarantee that an entire framework application will be understood.

| Project | Current scope |
|---|---|
| Static HTML website | Supported source detection and HTML/site checks |
| React, Vue, Svelte or Vite web application | Recognized project shapes and source checks |
| Next.js, Nuxt, Astro, Gatsby, Remix, SvelteKit, Angular | Recognized framework structures, including common web workspaces |
| Monorepo containing a supported web app and backend | Supported; select the root that matches your intended source scope |
| Website under a folder such as `docs/` | Select that folder as `--root` if outer-project detection treats it as auxiliary |
| Backend-only, generic Node CLI, browser-extension-only, Electron/Tauri-only or native-only app | Rejected by the website gate |
| PHP/Twig/Liquid/Nunjucks and other server template ecosystems | No claim of first-class template semantics or complete framework coverage |

A JavaScript library's synthetic test HTML does not necessarily make it a website project. If detection fails, use its reported reasons and the intended production web root. Do not add a fake `index.html` merely to force an unsupported application through the gate.

## What the modules inspect

### Security

The security module checks credential signatures and contextual assignments, browser HTML/code sinks, selected URL/messaging/storage patterns, JWT verification options and short server-side source-to-sink flows for SSRF, path traversal, command injection and SQL injection. It also checks selected lockfile, GitHub Actions, Docker and Terraform settings.

Server flow analysis is lexical and bounded within a file. It is not a complete JavaScript/TypeScript program model, call graph or framework authorization analysis. Recognized guards can reduce noise; unsupported syntax and application-specific wrappers can produce missed findings or unresolved signals. A sink finding does not by itself prove that an attacker controls its input.

Test fixtures and non-production artifacts are treated differently for many rules. Secret checks retain relevant coverage of test/configuration files, with context affecting severity and manual review. Review the reported file scope rather than assuming every collected file receives every rule.

### Website quality

Source checks cover document metadata, crawlability, structured data syntax, accessible labels and semantics, selected heading/dialog/table patterns, responsive CSS, likely delivered assets and maintainability signals. They do not render arbitrary component trees or execute framework metadata functions during a static scan.

Some rules are deliberate review prompts: large components, conversion measurement, browser policy, visual UX and user flows need project context. GEO/AEO/AIO wording refers to source and discoverability heuristics. Modular does not query an AI search engine or measure answer-engine ranking, traffic or conversion performance.

### Optional runtime

Playwright and Axe add evidence from chosen routes: rendered DOM, accessibility, console/network events, allowlisted response headers and laboratory LCP/CLS. There is no automatic crawling, login, interaction script, authenticated storage-state option or full user journey replay. [Runtime setup and boundaries](./runtime.md) describe what executes and what traffic is permitted.

## Input boundaries

Default discovery excludes generated/vendor directories such as `node_modules`, `.git`, `dist`, `build`, `.next`, coverage and browser-test output. Use exact directory names with `--ignore` to add exclusions. Ordinary discovery is not a Git-tracked-files-only scan and does not use `.gitignore` as a general file selection policy. The secret hygiene rule separately interprets applicable `.gitignore` coverage.

Readable source is bounded to 20,000 inventoried files, 1,500,000 bytes per text file and 128 MiB of total readable source by default. Aggregate file/byte limits stop discovery. Oversized, inaccessible, linked or changed sources can leave explicit coverage gaps; `--fail-on-incomplete` makes in-scope source gaps fail the command.

Images, fonts, media and WebAssembly can remain as metadata-only descriptors for identity/size checks. Their binary content is not decoded during the static scan. Other unrelated binary formats are skipped. Collected files are checked for root confinement and mutation before reads; filesystem links are not a route to reading outside the selected repository.

Choose `--root` and exclusions carefully. Deliberately excluded files are outside the scan scope, and no strict-coverage flag restores that omitted scope.

## Context changes the meaning of a signal

| Observation | What must still be established |
|---|---|
| Credential-shaped value in a local `.env` | Whether it is real, tracked, logged, deployed or exposed; presence alone is not a leak |
| Provider key embedded in shipped source | Exposure path, validity and affected systems; the scanner does not test the key |
| HTTP URL in container configuration | Whether it is an internal connection or an unprotected public boundary |
| MD5/SHA1 use | Whether it protects a security property or is only a cache/content fingerprint |
| Missing HTML image dimensions | Whether CSS already reserves space and whether rendered layout actually shifts |
| `noindex` directive | Whether the page is intentionally private or intended to be discoverable |
| An outer form group label | Whether each individual control receives an accessible name |

Local CSS imports in a recognized bundling pipeline and backend-only asset references do not automatically establish browser delivery problems. A recognized direct-child FormField convention can satisfy a source label check; arbitrary wrapper behavior is not fully inferred. Use real rendered evidence where source semantics are ambiguous.

## Dependency advisories

Advisory lookup is off by default. Use `--dependency-audit` with `check security` or `check all` to request it. Supported npm/pnpm flows use a temporary directory containing a sanitized manifest and selected lockfile, and an available compatible package manager.

A declared package manager chooses its matching graph. Unsupported declarations, ambiguous/conflicting lockfiles, custom dependency sources or incompatible manager setup can make the requested audit unavailable. Yarn and Bun network audits are currently unavailable because the required plugin/preload isolation is not guaranteed.

The scanner refuses network auditing when repository registry/auth configuration, linked/unreadable manager configuration or non-public lockfile hosts prevent safe isolation. It does not copy repository scripts/plugins or execute lifecycle scripts. The package registry receives dependency metadata needed for advisory matching; it does not receive repository source through this feature.

An unavailable, partial or inapplicable requested audit preserves reports and exits `1`. Skipping the feature produces no current-CVE assurance. A completed lookup is still a registry advisory match, not proof that every vulnerable package is reachable or exploitable.

## Data handling

Default static scanning reads local files as data and writes the selected reports. It does not upload source, invoke an AI service, run application scripts, inspect Git history or validate real credentials against providers.

Runtime mode imports trusted installed Playwright/Axe packages and executes the audited page's JavaScript. `--allow-remote` broadens browser traffic beyond loopback to page resources as well as the target. Review [the runtime trust boundary](./runtime.md#network-boundaries) before using it on unfamiliar code or dependencies.

Known secret patterns are redacted, but generated reports can still expose private paths, business context or imperfectly recognized secrets. Redaction is a safeguard, not permission to post an unreviewed report publicly.

## Accuracy claims

The repository includes labeled synthetic security cases, transformations, calibration regressions and a separate real Chromium/Axe integration. `npm run test:accuracy` measures the included corpus. Its precision/recall values do not estimate accuracy on all real-world projects, and should not be advertised as such.

For a false positive or missed issue, provide the smallest synthetic reproduction, the Modular version, command, expected result and observed result. Include a realistic counterexample when possible. Use the private route in [SECURITY.md](../SECURITY.md) if the reproduction includes a security-boundary failure or confidential data.

[Documentation index](./README.md) · [Reports](./reports.md) · [Contributing](../CONTRIBUTING.md)
