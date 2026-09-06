# Continuous integration

Choose a policy after reviewing a first local scan. The default CLI is advisory; a CI gate is an explicit choice about severity and coverage. Examples below scan source, so no application build, browser or registry advisory lookup is required.

## Select a gate

| Policy | Command from the website root |
|---|---|
| Collect reports without a finding gate | `modular check all --json --sarif` |
| Fail on all high/critical findings | `modular check all --fail-on high --fail-on-incomplete --json --sarif` |
| Fail only on reviewed-baseline regressions | `modular check all --baseline .modular-baseline.json --fail-on-regression high --fail-on-incomplete --json --sarif` |

Exit `3` means the finding gate was reached. Exit `1` means an execution or requested-coverage failure; do not treat it as a clean report. Invalid configuration/usage exits `2`. Manual findings still count toward thresholds unless accepted by policy.

Commit a reviewed `.modular.json` and baseline only when your team's handling of those files is appropriate. Do not regenerate the baseline in every audit job. See [configuration](./configuration.md) for suppressions, expiry and cumulative gates.

## GitHub Actions using Modular source

This workflow belongs in the **website repository**, as `.github/workflows/modular.yml`. It checks out Modular separately, so it does not depend on an npm package being published. Before using it, replace `YOUR_ACCOUNT/YOUR_REPOSITORY` and `YOUR_REVIEWED_COMMIT_SHA` with the actual Modular repository and a reviewed full commit SHA. The example assumes that repository is readable by the job.

```yaml
name: Modular website review

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Check out website
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Check out reviewed Modular version
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: YOUR_ACCOUNT/YOUR_REPOSITORY
          ref: YOUR_REVIEWED_COMMIT_SHA
          path: .tools/modular
          persist-credentials: false

      - name: Set up Node.js
        uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: 24

      - name: Audit website source
        run: node .tools/modular/bin/modular.js check all --ignore .tools --fail-on high --fail-on-incomplete --json --sarif --no-color
```

The first checkout is the scan root. `--ignore .tools` keeps Modular's own source/demo out of your website's inventory. Static sites without `package.json` or a lockfile can use this workflow; no npm cache or dependency installation is required. Keep the scan rooted at the repository checkout when using the SARIF upload below, including for a monorepo whose web application lives in a subdirectory.

If the project already has a policy file, remove duplicate CLI thresholds or choose the explicit overrides you want. For baseline-only adoption, replace the all-findings gate with the baseline/regression options above.

### Upload SARIF after the scan

If GitHub Code Scanning is enabled for the website repository, give the `audit` job the following permissions and append the upload step below. Keep `contents: read` explicitly: a job-level permissions block replaces the inherited block.

```yaml
permissions:
  contents: read
  security-events: write
  # Also add actions: read for private repositories.
```

```yaml
- name: Upload Modular SARIF
  if: always() && hashFiles('Modular/modular-results.sarif') != ''
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: Modular/modular-results.sarif
```

The file-existence guard prevents an upload failure when discovery stops before reports are produced. `always()` permits the upload after a finding gate fails; the failed scan step still keeps the job unsuccessful. Pin the upload action to a reviewed full commit SHA before adopting the snippet as a production policy, just as the checkout/setup steps are pinned.

If you use `--output`, update the upload path to match it. Modular records SARIF source locations relative to its scan root. A workspace-only scan such as `--root web` is useful for local reports, but uploading it requires rebasing those locations to the Git repository root; changing only `sarif_file` does not add the missing `web/` prefix. The workflow above avoids that additional transformation.

Code Scanning availability and pull-request token permissions depend on repository settings; consult GitHub's [third-party SARIF upload guide](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github). Review report contents before uploading them.

Without Code Scanning, retain the dedicated report directory using your CI platform's artifact mechanism. Preserve the scan exit code and inspect `run.complete` in JSON instead of treating the presence of an artifact as success.

## After an npm release exists

A published and verified version can replace the source checkout with a pinned package invocation:

```console
npx --yes modular-check@0.1.0 check all --fail-on high --fail-on-incomplete --json --sarif --no-color
```

This command contacts the configured package registry if installation is needed. Do not use it until that version is actually available in your intended registry. For an offline runner, install a reviewed local archive beforehand, as described in [getting started](./getting-started.md#install-a-local-archive).

## Add browser evidence deliberately

A browser CI job needs trusted installed Playwright/Axe packages, a browser executable and either an existing build or an application you started yourself. It may also need a backend and permitted remote resources. Runtime incompleteness exits `1` independently of the finding threshold.

Keep static preview observations separate from claims about production headers, authentication and backend latency. See [runtime audits](./runtime.md) for setup and route limits.

## CI for Modular itself

Modular's own workflow tests its implementation rather than auditing this CLI repository as a website. It runs core tests on Windows, Linux and macOS, checks the public package API, installs the archive offline and tests the demo scan and threshold behavior. A separate job runs real Chromium/Axe and the labeled accuracy corpus.

The Chromium job keeps the browser sandbox enabled. On its disposable GitHub-hosted Ubuntu runner, a CI-only AppArmor profile permits user namespaces for the exact installed Playwright Chromium and headless-shell executables. The profile is removed after the job's tests; it does not disable Ubuntu's system-wide restriction or modify users' computers. The profile generator refuses local and self-hosted execution. Other browser CI environments need their own reviewed, sandbox-capable setup.

To run the local release gate, follow [Contributing](../CONTRIBUTING.md). To publish the source repository or an npm release, use [GitHub setup](./GITHUB.md) and [Releasing](../RELEASING.md).

[Documentation index](./README.md) · [CLI reference](./cli.md)
