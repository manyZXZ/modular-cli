# Runtime browser audits

[Documentation](./README.md) · [CLI reference](./cli.md) · [Reports](./reports.md)

Runtime auditing adds observations from a real headless browser to the static `mysite` scan: rendered document structure, accessible names, metadata, layout, browser errors, resource requests, lab performance, and Axe accessibility results. It is explicitly enabled with `--runtime`; a normal static scan does not start a browser.

Runtime evidence is merged into the site reports and optional JSON/SARIF outputs. This is a bounded visit to selected routes, not an interactive end-to-end test or a production performance benchmark.

## Install the optional tools

Modular's installed package does not bundle Playwright, browser binaries, or Axe. From the website repository selected by `--root`, install the browser tooling you want Modular to use:

```sh
npm install --save-dev playwright @axe-core/playwright
npx playwright install chromium
```

These are setup commands you run separately. Modular never installs packages or downloads browsers during a scan. If you already have compatible tooling, reuse it. The versions used in Modular's development checks are pinned in its [package.json](../package.json).

The capability resolver searches from the target repository first, then from Modular's own installation, using normal Node.js package resolution. It checks `playwright`, `@playwright/test`, and `playwright-core` in that order, and `@axe-core/playwright` followed by `axe-core`. It imports those packages when runtime auditing is requested. A compatible JavaScript package and an available selected browser executable are separate requirements.

This permits a linked Modular checkout to use its own installed development tools, while an installed package can use the target application's tools. A package installed globally in an unrelated location is not automatically discoverable. `modular doctor` checks static scan readiness; it does not test these runtime dependencies.

## Audit an already-running application

Start your application and any required backend using your normal development workflow. Then run, for example:

```sh
modular check mysite --root ./my-web-app --runtime --url http://127.0.0.1:4173/ --route /pricing --route /docs --json
```

The base URL is always visited, followed by the supplied routes. Each route gets a fresh browser context with no inherited login session or saved storage. Modular does not click through flows, submit forms, log in, inject credentials, or reuse your normal browser profile. Site JavaScript runs in the page and may make its usual requests.

`--root` remains the source repository being scanned; `--url` chooses the browser target. Runtime mode still requires the local website detection gate. The CLI does not verify that a remote URL was deployed from the selected source revision.

Requested routes must use the base URL's origin. A leading slash is unambiguous: `/pricing` resolves from the origin root, while `pricing` follows normal URL resolution from the base URL's path. Fragment identifiers are removed for navigation. There is no automatic crawling, route discovery, or separate report per route.

## Audit an existing static build

Build the site yourself, then select its output directory:

```sh
modular check mysite --root ./my-web-app --runtime --runtime-static-dir dist --runtime-spa-fallback --route /pricing --route /docs --json
```

Modular serves those existing files on `127.0.0.1` using a temporary port. It does not run a build or a development server. For a monorepo scanned from its outer root, use a path such as `--runtime-static-dir web/dist`.

The static directory must be a real, non-root subdirectory inside `--root`. Paths outside the repository, symbolic links, and junctions are rejected. Linked assets, hidden paths, and parent traversal paths are not served. The server supports `GET` and `HEAD`, has no directory listing, and limits an individual served file to 64 MiB.

Use `--runtime-spa-fallback` only for a client-routed application that should serve `index.html` for missing paths. Without it, a route with no corresponding built file returns a normal error response. With it, missing assets can also receive the fallback HTML, so check network findings rather than assuming every `200` response is a working asset.

This server supplies static files only: it has no API backend, proxy configuration, server rendering, or authentication service. An API-dependent page may remain on a loading screen, show session errors, or render an error state. Confirm those observations against the running application before calling them production defects. The audit observes the build as it exists on disk, which may be older than the source scan.

Runtime security header checks are skipped for the isolated static server because its headers do not represent the application's deployment. Use `--url` against the intended response layer to review headers.

## Network boundaries

By default, the browser accepts only loopback HTTP(S) and WebSocket destinations, such as `localhost`, `127.0.0.1`, and `[::1]`. Other ports and loopback services are still reachable; this is not an origin-only network sandbox. LAN addresses and ordinary hostnames that happen to resolve to a local machine require `--allow-remote`.

Remote scripts, fonts, images, APIs, and analytics requests are blocked in local-only mode. Service workers are blocked. Worker creation and direct transports such as WebRTC and WebTransport are disabled in local-only mode; attempted use is recorded as a coverage limitation. A Playwright version without the required WebSocket interception API cannot complete that mode.

If a route needs remote resources and you intend to allow its network traffic, opt in explicitly:

```sh
modular check mysite --root ./my-web-app --runtime --url https://staging.example.com/ --allow-remote --route /pricing --json
```

Replace the staging URL with a site you are authorized to audit. `--allow-remote` permits remote page resources as well as the target itself; it is not a per-host allowlist. Explicitly supplied routes must still be same-origin, but the network flag is broader than those route entries. Embedded username/password credentials in URLs are rejected. Reported URLs strip queries and fragments.

Blocked requests can change what the page renders. Modular records that run as partial coverage instead of presenting it as a complete observation of the normal application.

## Runtime options

Use these with `check mysite` or `check all`. Every runtime option requires `--runtime`, and exactly one target must be provided.

| Option | Default | Meaning |
| --- | --- | --- |
| `--runtime` | Off | Enables the browser audit. |
| `--url <http-url>` | None | Visits an already-running HTTP(S) site. |
| `--runtime-static-dir <directory>` | None | Serves a pre-existing static build; relative to `--root`. |
| `--runtime-spa-fallback` | Off | Enables `index.html` fallback; requires `--runtime-static-dir`. |
| `--route <path>` | Base URL only | Adds an explicit same-origin route; repeatable. |
| `--runtime-max-routes <n>` | `5` | Maximum routes including the base URL; range `1`–`25`. |
| `--runtime-timeout <ms>` | `60000` | Total browser audit work budget; range `1`–`600000`. |
| `--browser <name>` | `chromium` | Selects `chromium`, `firefox`, or `webkit`. |
| `--browser-channel <name>` | Playwright browser | Selects an installed Chrome or Edge channel; requires `chromium`. |
| `--runtime-viewport <name>` | `mobile` | `mobile` is 390 × 844; `desktop` is 1280 × 720. |
| `--allow-remote` | Off | Permits remote targets and page resources. |

The CLI counts the base URL plus every `--route` argument against the limit before the runtime layer deduplicates normalized routes. With the default limit, provide at most four additional route arguments. Listing `/` again is unnecessary when it is already the base route.

Supported installed browser channels are `chrome`, `chrome-beta`, `chrome-dev`, `chrome-canary`, `msedge`, `msedge-beta`, `msedge-dev`, and `msedge-canary`. For example:

```sh
modular check mysite --root ./my-web-app --runtime --url http://127.0.0.1:4173/ --browser chromium --browser-channel chrome --runtime-viewport desktop --json
```

The channel must already be installed. The viewport presets change viewport dimensions; they do not emulate a named device or enable network/CPU throttling. Use separate runs and dedicated output directories to compare viewports or browsers.

## Readiness and time budgets

Routes are visited sequentially. Navigation waits for `DOMContentLoaded`, then attempts to reach the page `load` state. Before measurement, Modular waits for at least 500 ms without DOM child/text mutations and checks visible loading indicators such as `aria-busy`, progress bars, and loading status text. This catches common delayed rendering, but it cannot prove that every application-specific fetch or hydration task is complete.

The current per-stage defaults are:

| Stage | Budget |
| --- | --- |
| Browser launch | 15 seconds |
| Navigation, per route | 15 seconds |
| Waiting for `load`, per route | 2 seconds |
| Render readiness, per route | 5 seconds |
| DOM/performance measurement, per route | 5 seconds |
| Axe, per route | 10 seconds |
| Resource cleanup | 5 seconds per close operation |

The total browser deadline bounds the work remaining for those stages. `--runtime-timeout` changes that total; it does not change individual stage limits. There is no CLI selector to wait for an application-specific ready element. A readiness timeout becomes an explicit incomplete-readiness finding, and any measurements collected afterward belong to partial coverage.

The browser deadline does not include the earlier static scan, report writing, or all cleanup work. Modular closes each route context, the browser, and its own temporary static server on completion or handled interruption. Cleanup is bounded separately and cleanup failures are reported. It does not stop a server that you started and supplied through `--url`.

## Interpret results

An explicitly requested runtime audit exits `1` if coverage is unavailable or partial, even when `--fail-on` is `none`. Examples include missing Playwright or Axe, unavailable browser binaries, blocked resources, a navigation or readiness timeout, incomplete instrumentation, missing LCP/CLS measurement support, and cleanup failure. Reports retain completed observations with route and stage status.

Chromium is the default for the widest current measurement coverage. Firefox and WebKit can provide useful rendering and accessibility observations, but unsupported performance observer entries remain unavailable and can make the overall result partial. Modular does not substitute zero for an unsupported metric.

A completed Axe run can still contain checks marked `incomplete` that need human review. Those are distinct from Axe failing to execute. Zero automated violations does not establish complete accessibility conformance.

LCP, CLS, TTFB, resource transfer, and long-task observations describe this browser visit. The audit does not measure field Core Web Vitals or interaction INP, exercise authenticated journeys, assess every responsive state, or certify visual quality. Short observation windows can miss later shifts or failures. Static-preview API errors and local timings need context before prioritizing a production change.

See [reports](./reports.md) for result fields, [coverage](./coverage.md) for the scanner's broader limits, and [troubleshooting](./troubleshooting.md) for setup failures. Return to the [project README](../README.md).
