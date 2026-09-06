# Changelog

All notable user-facing changes to Modular are recorded here. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and the structure of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Topic-based guides for installation, CLI usage, configuration, report interpretation, coverage, browser audits, CI, troubleshooting and the JavaScript/TypeScript API, with a Turkish introduction and runnable examples.
- Source-first quick start, Turkish guide, GitHub setup guide and a safe synthetic demo with Markdown/JSON/SARIF output.
- Public repository-content gate excluding private audits, generated reports, credentials and non-portable paths, including already tracked files.
- Offline tarball-install verification covering the generated CLI shim, package API, real scans and policy exit codes on the CI operating-system matrix.
- Archive-level documentation-link verification and exact demo file allowlisting so generated reports cannot enter the package.
- Shared immutable built-in module registry for scanner dispatch, capabilities and report mappings.
- Optional `--fail-on-regression` and `--fail-on-incomplete` CI policies, with configuration, machine-report and TypeScript support.
- A labeled scanner-accuracy corpus with per-rule measurements and semantics-preserving transformations, plus explicit real Chromium/Axe CI integration.
- Open-source governance, security-reporting, contribution and release documentation.
- Cross-platform CI and package-contract verification for supported Node.js releases.
- Website checks for canonical/social metadata integrity, JSON-LD syntax, robots/sitemap URL validity, restricted zoom, named dialogs and SVGs, nested interactions, form groups, data tables, and render-blocking CSS imports.
- Repository-confined metadata verification and conservative size-budget findings for likely delivered images, fonts, audio/video and WebAssembly assets.
- CWE and OWASP Top 10:2025 mappings with authoritative references on security findings.
- Bounded one-file server data-flow checks for SSRF, path traversal, shell command injection and SQL injection.
- GitHub Actions trust-boundary, lockfile transport/integrity, JWT verification-option and additional provider-secret checks.
- High-signal Docker/container privilege, remote-build execution and Terraform public-exposure checks.
- Deterministic JSON and SARIF 2.1.0 artifacts with portable paths, source locations, rule metadata and stable fingerprints.
- Strict `.modular.json` project policy, process-safe reviewed baseline updates, new-finding CI gates and reasoned expiring suppressions.
- Mobile-first and desktop runtime viewport presets.
- A read-only `modular doctor` readiness command for runtime, policy, baseline, output and website-gate diagnostics.
- Maintained TypeScript declarations for the root library, CLI and runtime public entry points.

### Changed

- Failed Markdown and JSON/SARIF rollback preserves recovery backups and reports their paths instead of deleting the last copy of earlier results.
- Security source masking preserves UTF-16 positions; URL guard inference rejects stale values and conditionally executed validation.
- Dependency privacy checks accept valid integrity hashes containing Base64 slashes, and Windows dependency audits recognize standard npm-generated package-manager shims.
- Website scans include Markdown content under detected monorepo roots, recognize JSX language literals, and preserve visible inline-code heading text.
- Runtime form checks exclude CSS-hidden controls and CSP findings follow the effective script policy rather than overridden fallback directives.
- Split CLI coordination, scanner helpers, browser probes and Markdown report internals into focused modules while preserving public entry points, findings, command behavior and report formats.
- Real-project calibration distinguishes local credentials from demonstrated source exposure, deduplicates long provider signatures, and excludes narrowly recognized public-only environment configuration from secret-file hygiene findings.
- Complete filename-component rejection plus a mandatory anchored filename prefix can establish a bounded path-traversal guard, including Windows drive-relative protection.
- Site checks distinguish bundled local CSS imports and backend-only image references from browser delivery; remote imports remain checked even after a bundled import. FormField label inference requires exactly one direct child.
- Runtime measurement waits for visible loading indicators to clear and a bounded DOM quiet period; readiness timeouts explicitly mark incomplete coverage. Nested runtime standards retain valid reference URLs.
- Detail limits now preserve all finding identities for baseline, suppression and CI decisions; scan observations remain explicitly bounded.
- SSRF analysis distinguishes URL bases from fixed destinations and follows local reassignment. Filename and URL rejection guards require executable, unconditional exits; permissive filename patterns remain unsafe.
- JWT verification analysis uses actual call/options tokens, ignores text in comments and strings, and checks every literal algorithm entry.
- Runtime CSP analysis precedes report truncation; CLS uses session windows and performance reporting distinguishes API support from measured entries.
- Runtime form-name checks resolve ARIA references and native input names; SVG, MathML and inert-content titles no longer satisfy HTML document title checks.
- Incomplete requested audits produce unsuccessful SARIF execution and incomplete JSON run status. Static directory routes redirect to preserve relative asset resolution.
- Scanner inputs are now deterministically ordered and confined to the declared repository root, including programmatic API calls.
- Website detection covers root Next.js App Router surfaces and cannot be bypassed with caller-supplied detection metadata.
- Environment hygiene follows applicable nested `.gitignore` rules and negations.
- CLI interruption, closed-pipe, narrow-terminal, invalid-output and `--ignore` behavior now fail cleanly with documented exit codes.
- File reads reject linked ancestors and files changed after discovery; a bounded SHA-256 snapshot also catches same-size mutations when filesystem timestamps are too coarse.
- Capitalized framework components are no longer interpreted as native HTML controls by native-element accessibility rules, and Remix-style route metadata is recognized explicitly.
- JWT-shaped secret detection now validates decoded header/payload structure, and provider signatures are deduplicated against contextual assignment findings.
- Server data-flow guards now require a terminating rejection path, ignore comments and unrelated string literals, preserve lexical shadowing, and keep privileged workflow correlation inside one CI job.

### Initial source command set (0.1.0; registry publication not asserted)

- `modular check security`, `modular check mysite` and combined `modular check all` commands.
- Deterministic website-project detection with a fail-closed non-website gate.
- Static frontend security, accessibility, SEO, GEO/AEO/AIO, UX, responsive and performance-readiness checks.
- Explicit opt-in dependency advisory and disposable runtime browser audits.
- Atomic, bounded Markdown report generation with severity-aware summaries and action plans.
- CI threshold exit codes, machine-safe plain output and detailed coverage metadata.
- Official-logo-derived terminal rendering and live scan progress.
