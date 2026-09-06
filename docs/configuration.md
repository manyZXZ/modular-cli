# Project configuration and CI policy

Put a `.modular.json` file in the website root to reuse settings across local runs and CI. Modular loads it automatically. Configuration is strict: unknown keys and invalid values fail with exit code `2`.

Examples below use `modular` after [linking or installing](./getting-started.md) the CLI. Run them from the website root.

## Start with a severity gate

```json
{
  "failOn": "high",
  "failOnIncomplete": true,
  "maxFindingsPerRule": 100,
  "outputFormats": ["json", "sarif"]
}
```

```console
modular check all
```

This writes both machine formats and returns `3` if any unsuppressed high or critical finding is present. `failOnIncomplete` returns `1` if in-scope source could not be fully read. These are different failure conditions; a severity gate alone does not require complete source coverage.

Manual-review findings still participate in severity gates. Review and fix them, or use a narrow, justified suppression when the risk is accepted. A manual flag is not an automatic exemption.

## Available settings

| Key | Purpose |
|---|---|
| `failOn` | Gate all unsuppressed findings at or above a severity; default `none` |
| `failOnNew` | Gate new finding identities compared with a required baseline |
| `failOnRegression` | Gate new identities and severity increases compared with a required baseline |
| `failOnIncomplete` | Fail on incomplete in-scope source coverage; default `false` |
| `baseline` | Path to a Modular baseline inside the selected repository |
| `outputFormats` | Additional formats: `json`, `sarif`; Markdown is always written |
| `maxFindingsPerRule` | Positive integer limiting displayed evidence examples per rule |
| `ignore` | Exact directory names to exclude wherever they occur, such as `storybook-static` |
| `suppressions` | Accepted findings, matched by rule and optionally file path |
| `$schema` | Optional editor schema hint; no runtime schema download is performed |

Severity values are `critical`, `high`, `medium`, `low`, `info`, or `none`. `high` includes `critical`; `medium` includes both. `none` disables that gate.

The packaged [JSON schema](../modular.schema.json) describes the complete configuration. If Modular is a local dependency, an editor can use `"$schema": "./node_modules/modular-check/modular.schema.json"`. The [copyable example](../examples/modular.config.json) is another starting point.

### Precedence and paths

Explicit CLI thresholds and limits override their configured equivalents. `ignore` names and output formats are additive: `--json` does not remove configured SARIF output. A configured baseline resolves from the website root, even when an alternate configuration file lives in a subdirectory.

```console
modular check all --config policies/modular.json --fail-on critical
modular check all --no-config --fail-on none
```

`--config` and `--no-config` cannot be combined. Relative CLI paths for configuration and baseline files must stay within `--root`; explicit absolute CLI paths can target elsewhere. The configuration's `baseline` field must stay inside the project.

`ignore` accepts directory names, not globs or paths. Use `"storybook-static"`, not `"web/storybook-static"` or `"**/generated/**"`. Intentionally ignored directories are outside coverage, not reported as unreadable source.

Configuration cannot enable a browser run, a remote target or dependency advisory access. Those permissions require their CLI flags.

## Adopt a reviewed baseline

A baseline records finding identities, not a certificate that the code is safe. First scan and review the current findings:

```console
modular check all --json --sarif
```

Once that state has been reviewed, create its snapshot:

```console
modular check all --write-baseline .modular-baseline.json
```

Now use a regression policy:

```json
{
  "baseline": ".modular-baseline.json",
  "failOnRegression": "high",
  "failOnIncomplete": true,
  "outputFormats": ["json", "sarif"]
}
```

`modular check all` now gates new high/critical findings and existing findings whose severity increases to that threshold. To gate only newly observed identities, use `failOnNew` instead.

Do not also retain `failOn: "high"` if the intention is to tolerate reviewed existing high findings: the all-findings gate remains active and can still fail. Multiple configured gates are cumulative.

Findings are fingerprinted from mode, rule, repository-relative file and redacted evidence. Moving a finding to another line normally preserves its identity; changing the file or evidence can create a new identity. Severity increases keep their fingerprint and expose `baselineChange: "severity-increased"` and `previousSeverity` in machine output.

Baselines are created only with `--write-baseline`. Existing non-Modular files are refused. Updating one mode preserves the other mode's entries. Do not rewrite the baseline on every CI run, because that would continually accept the state you intended to compare.

## Suppress an accepted finding with a reason

Use the actual rule ID from the finding. For example, a deliberate demo sink can be reviewed and accepted for that file:

```json
{
  "suppressions": [
    {
      "rule": "security.dom-xss",
      "path": "examples/basic-site/legacy-widget.js",
      "reason": "Synthetic demonstration source; this module is never loaded by the example page."
    }
  ]
}
```

The path is relative to the website root. If you scan `examples/basic-site` itself, the matching path is `legacy-widget.js`. Do not copy the example path into an unrelated project without reviewing the matching source.

Both `rule` and optional `path` support glob matching; use an exact ID and narrow file path when possible. `reason` is required and must contain 8–1000 characters. An optional `expires` value uses `YYYY-MM-DD`; the suppression is valid through that UTC date and stops applying after it.

Accepted findings remain visible in detailed Markdown, JSON and SARIF. They are omitted from the actionable checklist and CI threshold decisions. Reports also identify expired suppressions. Suppressing a finding does not remove the underlying source risk or make an incomplete scan complete.

## Detail limits do not weaken the gate

`maxFindingsPerRule` limits full evidence shown in reports. Modular keeps a compact index of all observed identities for baseline, suppression and CI decisions. Raising the limit reveals more evidence; lowering it does not hide a new finding from policy.

See [reports and coverage](./reports.md) for retained counts versus complete observations, and [CI](./ci.md) for workflow examples.

[Documentation index](./README.md) · [CLI reference](./cli.md)
