# Understanding reports

Read coverage first, then findings. A successful command can report problems, and an incomplete command can still leave useful reports from completed work. Neither the exit code nor the score is a certificate of security or accessibility.

## Where the files go

The default directory is `Modular/` inside `--root`. `--output` selects a different dedicated directory.

| File | Use it for |
|---|---|
| `00-overview.md` | Compare the selected modules and read coverage notices |
| `01-security-report.md` | Review security evidence and source locations |
| `02-security-action-plan.md` | Triage actionable security work |
| `03-site-report.md` | Review accessibility, metadata, layout and other site signals |
| `04-site-action-plan.md` | Triage actionable site work |
| `modular-results.json` | Consume the scan model, policy and coverage in your tooling; requires `--json` |
| `modular-results.sarif` | Import retained findings into compatible code-scanning tooling; requires `--sarif` |

A single module writes the overview and its two Markdown files. `check all` writes both pairs. Running the other module later adds its pair and refreshes the overview. Check the overview's refreshed/preserved sections and timestamps when comparing runs; separate invocations are not one shared snapshot.

The output directory must be empty or owned by Modular's report markers. A matching filename alone is not proof of ownership. An optional `.gitkeep` is allowed; your notes and unrelated JSON files are not. Writes are atomic per file, but the entire report set is not a single filesystem transaction. After an interruption, inspect completion metadata before consuming the set.

If publication fails and an earlier report cannot be restored, Modular retains any remaining recovery backup and includes its path in the error. Markdown backups end in `.bak`; JSON/SARIF backups end in `.backup`. Preserve those files, compare them with the canonical reports, and resolve the filesystem problem before restoring or rerunning. The CLI refuses output directories containing recovery backups so a later scan cannot silently discard them.

## Read a finding

This is an abridged JSON finding from the included demo, not the complete JSON report:

```json
{
  "id": "a11y-form-label",
  "title": "Form control has no programmatic label",
  "severity": "high",
  "confidence": "high",
  "manual": false,
  "file": "index.html",
  "line": 14
}
```

| Field | Meaning |
|---|---|
| `id` | Rule identifier used in policy matching and reports |
| `severity` | Priority/possible impact: critical, high, medium, low or info |
| `confidence` | How strongly the observed evidence supports the signal |
| `manual` | Whether this signal explicitly requires manual validation |
| `file`, `line` | Repository-relative source location when available; runtime findings may have no source line |
| `evidence` | A short, redacted excerpt or observation |
| `recommendation`, `suggestedFiles` | Guidance for investigation and changes |
| `fingerprint` | Stable identity used in baseline comparisons |
| `standards`, `references` | Rule mappings and supporting references where available |

Severity and confidence answer different questions. The demo's `security.dom-xss` finding is high severity, medium confidence and manual: an HTML sink exists, but you still need to trace whether untrusted data reaches it. An automated finding also needs context before you make an exploitability or conformance claim.

CWE, OWASP and WCAG references describe the rule's subject. They do not mean that every requirement in that standard was evaluated.

## How to triage

1. Check whether the source and optional audits were available and complete.
2. Review high-priority findings in the relevant action plan.
3. Follow the evidence to source or the rendered page.
4. Classify it as a verified issue, an accepted risk, a false positive, or an unresolved review item.
5. Fix the source or record a narrow, justified suppression; rerun the same scope.

Do not treat each occurrence as a separate attack or every information-level checklist entry as a defect. A local `.env` value is not proof of a leak, and an intentional `noindex` page may be correct for private content. [Coverage](./coverage.md) gives more context-dependent examples.

Accepted suppressions remain visible in detailed and machine reports, but are removed from the actionable checklist and enabled thresholds. A baseline comparison labels current identities as new or unchanged and records severity increases separately. It does not emit resolved findings or establish that unchanged findings are safe. See [configuration](./configuration.md).

## What the score means

Modular calculates a review score from the strongest retained signal in each score/rule family. Repeated occurrences in the same family do not each add another full risk contribution. Confidence scales the weight, and manual-review signals receive half weight.

For the current `rule-family-confidence-v2` model:

```text
risk = min(99, floor(100 × rawPoints / (rawPoints + 60)))
review score = 100 − risk
```

`rawPoints` is the sum of the selected family contributions. The JSON summary includes the model, weights and contributions. A score of 100 means no scored signal was retained in that result; it does not mean 100% coverage or proven safety. Scores should be compared with the same version, scope, options and coverage.

Suppressions annotate the policy result; they do not erase evidence or recalculate the original summary score. A policy can pass while the report still shows accepted high findings. Static-only and combined runtime reviews are labeled separately.

## Coverage and counts

The reported number of checks refers to configured **rule families**, not the number of browser visits, independent security tools or successfully verified requirements. The rule ledger distinguishes completed, inapplicable, skipped, unknown-applicability and manual-review work. A completed family with no observed findings is still a bounded negative observation.

The default detail cap is 50 findings per rule. Retained counts describe displayed findings, so they may be lower than the complete observation count. Omitted counts and severity mixes are reported; `metadata.findingIndex` preserves compact identities for all observed findings. CI and baseline helpers use that index rather than silently dropping omitted occurrences.

```console
modular check all --max-findings-per-rule 200 --json --sarif
```

Raise the cap when you need every retained evidence location for a large rule family. It does not make the scanner search more source or perform deeper analysis. More than 250,000 distinct policy observations causes a bounded failure rather than silent truncation of the identity index.

## JSON and SARIF completion

The JSON envelope contains `schemaVersion`, `tool`, `run` and `results`. Each result has `mode`, `findings`, `summary` and `metadata`, plus timing and inventory counts. Use `mode` to select a result; do not rely on array position.

| Completion field | What it tells you |
|---|---|
| JSON `run.modesComplete` | All expected scan modes produced results |
| JSON `run.complete` | The mode set completed and no requested runtime, advisory or strict source-coverage check is incomplete |
| SARIF `properties.modularRun` | Equivalent combined-run status |
| SARIF invocation `executionSuccessful` | Whether the result's requested audits completed successfully |

Default scans can have skipped optional advisory/browser work and source exclusions. Inspect metadata even when `run.complete` is true. Use `--fail-on-incomplete` to require in-scope source readability; explicitly requested runtime/advisory work already affects completion when unavailable or partial.

SARIF 2.1.0 includes retained rule details, locations, stable fingerprints and suppression/baseline annotations. If your downstream workflow needs every occurrence, raise the detail cap or consume the compact JSON index as appropriate. Do not gate CI by counting only the retained SARIF results.

## Browser observations

Runtime results include requested routes, HTTP status, stages, viewport, accessibility outcomes and measured performance. A completed Axe run can still produce `incomplete` checks that need a person to decide them. Zero Axe violations is not a full accessibility evaluation.

LCP/CLS values are local laboratory samples, without named-device emulation or automatic field-data collection. A static preview has no application backend and its headers are not production headers. See [runtime audits](./runtime.md) before interpreting session errors, local TTFB or a loading state as a deployed-site defect.

## Sharing reports

Known credentials are redacted before report generation, but source paths and surrounding project context may still be private. Review reports before uploading them to issues, artifacts or code scanning. The normal secret scan covers the collected working tree, not Git history. Keep confidential findings out of public issue templates.

[Documentation index](./README.md) · [Configuration](./configuration.md) · [CI](./ci.md)
