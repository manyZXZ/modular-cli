## Summary

Explain the problem and the behavior this pull request changes.

## Validation

List the exact commands and fixtures used to verify the change.

## Checklist

- [ ] I kept the change focused and added regression coverage.
- [ ] I tested both expected matches and realistic counterexamples for scanner-rule changes.
- [ ] `npm test` passes.
- [ ] `npm run smoke` passes.
- [ ] `npm run package:check` passes when package contents changed.
- [ ] `npm run repo:check` and `npm run package:smoke` pass.
- [ ] I updated user-facing documentation and `CHANGELOG.md` where needed.
- [ ] I did not include secrets, private source, generated `Modular/` reports or unrelated changes.
- [ ] This change does not silently broaden filesystem, network or code-execution permissions.
