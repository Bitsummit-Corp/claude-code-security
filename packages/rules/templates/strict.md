# CLAUDE.md Hardening Rules - Strict

> Includes all baseline rules. Layer the snippets below on top of the
> baseline file (or copy this whole template to a strict-profile project).

## Secrets, destructive operations, sensitive paths

See `baseline.md`. All baseline rules apply.

## Bash structural risks

- Avoid command substitution (`$(...)`, backticks) and process substitution
  (`<(...)`, `>(...)`) when a direct invocation works. Strict profile blocks
  unexpected substitution shapes.
- Do not pipe network output into a shell (`curl ... | sh`, `wget ... | bash`).
  Download to a file, inspect, then run.

## Branch and history protection

- Do not push directly to `main`, `master`, `release/*`, `develop`, `prod`, or
  `production`. Use a feature branch + PR.
- Do not run `git push --force` against shared branches.
- Do not run `git filter-branch`, `git filter-repo`, or `bfg --strip-blobs`
  without an out-of-band approval; these rewrite shared history.
- Do not run `git commit --no-verify` to skip pre-commit hooks. If a hook
  fails, fix the underlying issue.
