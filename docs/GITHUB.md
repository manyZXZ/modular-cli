# Prepare and push the repository

The checkout is a source product, with a synthetic demo, Markdown/JSON/SARIF output, a tested npm archive and GitHub CI. Creating a GitHub repository, pushing commits and publishing to npm are separate maintainer actions. No remote URL or registry ownership is assumed.

## Verify the public file set

```console
npm ci --ignore-scripts
npm run release:check
npm run test:accuracy
git status --short
```

`repo:check`, included in the release gate, examines both tracked files and untracked candidates. It rejects private audit folders, generated scan reports, environment files, key files, unexpected root entries, unsafe paths and machine-local home paths. A tracked file cannot evade the check merely by being added to `.gitignore`. This is a repository-content contract, not a complete secret-history scanner.

Keep `audit/`, generated `Modular/` directories, caches, `node_modules/`, `.env*` and local credentials on your machine. Do not force-add them. The public tests and examples use synthetic data. The package has an explicit file allowlist, checked independently of Git.

## First push

Create an empty repository in the intended GitHub account without an automatically generated README or license. Replace `YOUR_ACCOUNT/YOUR_REPOSITORY` below with the actual repository, then review the staged files before committing:

```console
git add .
git diff --cached --stat
git diff --cached --check
git commit -m "Prepare Modular public source release"
git branch -M main
git remote add origin https://github.com/YOUR_ACCOUNT/YOUR_REPOSITORY.git
git push -u origin main
```

If the repository already has a remote or commits, use its existing branch/remote convention; do not overwrite history. Configure your own Git author identity if Git requests it. Never use `--force` to resolve an unrelated-history error.

## Configure GitHub

- Enable Actions, private vulnerability reporting and secret scanning/push protection where available for the repository.
- Protect the default branch and require the test, package and browser jobs to pass.
- CI uses full-SHA action references and read-only repository permissions. Dependabot maintains dependencies and action pins.
- Core tests run on Windows, Linux and macOS. The package matrix installs the archive offline and checks its CLI, public import, both scanners, JSON/SARIF reports and exit-code policy. A separate Linux job uses real Chromium and Axe.

See GitHub's [branch protection documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches) and [private reporting setup](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository).

## Before an npm release

Set `repository`, `homepage` and `bugs` in `package.json` to the real GitHub URL. Confirm npm ownership of `modular-check`, the license holder and the security contact route. Do not substitute invented identity URLs or treat an available source checkout as a published registry release. Follow [RELEASING.md](../RELEASING.md) for versioning, final checks and provenance.

[Documentation index](./README.md) · [Contributing](../CONTRIBUTING.md) · [Website CI guide](./ci.md)
