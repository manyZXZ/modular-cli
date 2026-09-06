# Security Policy

## Supported versions

Security fixes are made on the latest published minor line. Pre-release builds and older minor lines may be asked to upgrade before a fix is backported.

| Version | Supported |
|---|---|
| `0.1.x` | Yes |
| `< 0.1` | No |

The supported Node.js baseline is `>=22.12.0`. Running Modular on an end-of-life Node.js release is not supported.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, leaked credential, private report, or exploit.

1. Open the repository's **Security** tab and choose **Report a vulnerability** to start a private GitHub security advisory.
2. Include the affected Modular version, operating system and Node.js version.
3. Provide a minimal reproduction, impact assessment and any known workarounds. Remove real credentials and private source code.

If private vulnerability reporting is not available, contact a repository maintainer privately through a contact method on their GitHub profile. Maintainers must enable GitHub private vulnerability reporting before the first public release.

We aim to acknowledge a report within three business days, provide an initial triage within seven business days and send an update at least every fourteen days until resolution. Timelines may change with severity and reproduction complexity.

Please allow maintainers reasonable time to investigate and release a fix before public disclosure. We will credit reporters who want attribution.

## Scope

Security reports about Modular itself include, for example:

- reading files outside the selected repository or following unsafe links;
- overwriting files outside the dedicated report directory;
- leaking source, credentials or registry configuration;
- executing repository code without an explicit, documented opt-in;
- bypassing the runtime network boundary;
- command injection, unsafe temporary files or package-install behavior.

A finding produced while Modular scans another project is normally a finding about that project, not a vulnerability in Modular. False positives, false negatives and rule-quality problems can be filed as ordinary bugs unless the report contains private data or demonstrates a security-boundary failure.

## Execution trust boundary

The default static scanner treats repository content as data and does not import repository modules or run repository scripts. The isolated dependency advisory workflow also refuses repository package-manager configuration, plugins and lifecycle scripts.

`--runtime` is different. When explicitly selected, Modular imports an allowlisted Playwright package and optional Axe package resolved from the scanned project's installed dependency tree. Package module-initialization code therefore runs in Modular's Node.js process, and the audited site's JavaScript runs in a disposable browser context. Only use runtime mode for a dependency tree and built site you trust. A way to trigger other project code without this explicit boundary is in security scope.

## Secret handling

Never attach real secrets. Revoke any credential accidentally exposed in an issue, report or log; deleting a message is not sufficient. Modular redacts known credential patterns, but generated reports should still be treated as potentially sensitive until reviewed.
