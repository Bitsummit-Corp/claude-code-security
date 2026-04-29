# CLAUDE.md Hardening Rules - Baseline

> Drop these rules into the project or user CLAUDE.md to make Claude Code's
> default behaviour more conservative under the baseline profile. Rules are
> phrased as positive instructions; the runtime hooks enforce the boundary.

## Secrets

- Never echo, log, or print API keys, tokens, or passwords. Use boolean checks
  (`[ -n "$VAR" ] && echo set`) instead of value retrieval.
- Never invoke `security find-generic-password` with `-w` or `-g`.
- Never run bare `env` or `printenv` to inspect the environment.

## Destructive operations

- Do not run `rm -rf` against `$HOME`, `/`, or any path containing user data
  without explicit user confirmation.
- Do not modify shell rc files (`.zshrc`, `.bashrc`, `.profile`) without user
  confirmation. Persistence changes are user decisions.

## Sensitive paths

- Do not Read or cat files inside `~/.ssh/`, `~/.aws/`, `~/.gnupg/`,
  `~/.kube/`, `~/.docker/`, `/etc/sudoers`, or `/etc/shadow`.
