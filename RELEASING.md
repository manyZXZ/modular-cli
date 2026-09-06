# Releasing Modular

Publishing is a maintainer-only operation. These steps prepare and verify a release; they do not grant registry access or publish automatically.

## One-time repository setup

Before the first public release:

1. Choose the canonical GitHub repository and confirm ownership of the `modular-check` npm package name.
2. Add real `repository`, `homepage` and `bugs` URLs to `package.json`; never publish placeholder URLs.
3. Add release and comparison links to `CHANGELOG.md` after the canonical repository URL exists.
4. Verify the copyright holder in `LICENSE`.
5. Enable GitHub private vulnerability reporting and branch protection with required CI checks.
6. Require npm two-factor authentication or configure npm Trusted Publishing with provenance.

The source tree intentionally omits identity URLs until the canonical repository is known.

For a first source push, use [the GitHub setup guide](./docs/GITHUB.md). Registry publication is not required to use the CLI from a clone or a local `.tgz`.

## Release checklist

1. Start from a clean, protected default branch and review every change since the last tag.
2. Choose a Semantic Versioning number, update `package.json` and `package-lock.json` together, and move relevant changelog entries out of **Unreleased**.
3. Install exactly from the lockfile and run the release gate:

   ```console
   npm ci --ignore-scripts
   npm run release:check
   ```

4. Inspect the machine-readable archive inventory. Only the intended public demo files should be included; private or test fixtures, generated reports, caches and credentials must be absent:

   ```console
   npm pack --dry-run --json --ignore-scripts
   npm pack --ignore-scripts
   ```

5. Run `npm run package:smoke` to create an archive, install it offline in a disposable directory, verify its npm CLI shim and public API, and run both scanners with JSON/SARIF and an enforced severity gate. This is also included in `release:check`.
6. Commit the version and changelog, create a signed `v<version>` tag, and let required CI finish.
7. Publish from a protected environment using provenance:

   ```console
   npm publish --access public --provenance
   ```

8. Verify the public package contents and CLI on a clean supported Node.js installation, then create release notes from the changelog.

Never publish from a dirty working tree, with `--ignore-scripts` applied to `npm publish`, or after a failed/partial test. Deprecate a broken release instead of silently replacing it; npm versions are immutable.
