# Snippet: never force-push or skip pre-commit hooks

Drop this into a CLAUDE.md to lock down git behaviour on shared branches.

- Do not run `git push --force` or `git push -f` against shared branches.
  If you need to update a feature branch, use `--force-with-lease`.
- Do not skip pre-commit or pre-push hooks (`--no-verify`,
  `--no-gpg-sign`). If a hook fails, investigate and fix the underlying
  issue rather than bypassing.
- Do not run `git reset --hard` against any branch tip without an explicit
  user instruction. Local resets that discard work are user decisions.
- Do not delete protected branches with `git branch -D` (`main`, `master`,
  `release/*`, `develop`, `prod`, `production`).

The `git-destructive-guard` and `branch-protection-guard` hooks enforce
these on baseline (warn), strict, and regulated (block).
