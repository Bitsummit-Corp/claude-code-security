# archive/hooks-rc2

Retired hook implementations from the `v0.9.0-rc.x` line. Preserved as reference TypeScript for the patterns the project intends to validate against the real Claude Code harness contract.

## Status

These hooks were moved here from `packages/hooks/src/` as part of the v0.1.0 scope reset (2026-05-04). They are not currently wired into a build, not exercised by any test that talks to the real Claude Code harness, and not protecting any machine. The four delivery-layer defects documented in the [README "Current state" section](../../README.md#current-state-delivery-layer-is-broken) explain why.

## Why this directory exists

The retired implementations are the working notes for what the M1+ rebuild will validate one capability at a time. Each `<hook-name>/index.ts` declares a manifest, a `run(ctx)` function, and a colocated `<hook-name>.test.ts` against the in-process runner. The manifests are the right shape for the original (broken) compiler contract, not the real Claude Code harness contract. Treat them as design intent, not specifications to copy verbatim.

## What the M1+ rebuild will look like

Read the [README "Scope reset" section](../../README.md#scope-reset-may-2026) for the M1-M4 cadence. Briefly:

- M1 picks one hook, ports it to the real harness contract, and ships an integration test that writes a real `~/.claude/settings.json` and spawns the harness.
- M2 documents how operators calibrate their own regex tables.
- M3 ports the M1 hook to one Linux distro.
- M4 picks a second hook category.

The ordering matters: the calibration model precedes more hooks, because more hooks calibrated to nobody's actual secrets is more theater, not less.

## How to use this directory

For reference reading. Open any subdirectory and read `index.ts`. The manifests show the rc.x hook contract (event, matchers, threat ID, severity, profiles, timeout). The `<name>.test.ts` files show the test shape that was being asserted against the in-process runner. Neither file is currently part of a working pipeline.

For external links into this directory: the prior pattern was `packages/hooks/src/<name>/index.ts`. After the move, the canonical reference is `archive/hooks-rc2/<name>/index.ts`. If you arrived here from a stale link, that move is intentional.

## Index of retired hooks

26 hooks across the categories the rc.x line intended to cover:

- **Secrets:** `secret-guard`, `secret-leak-detector`, `keychain-guard`, `mcp-secret-guard`
- **Destructive filesystem:** `destructive-fs-guard`, `git-destructive-guard`, `sensitive-paths-guard`, `dotfile-guard`
- **Bash structure:** `bash-structural-guard`, `pipe-to-shell-guard`
- **Branch / git:** `branch-protection-guard`, `commit-amend-pushed-guard`, `submodule-injection-guard`, `git-history-rewrite-guard`
- **Egress:** `webfetch-egress-guard`, `bash-egress-guard`
- **Audit:** `audit-tamper-detector`, `audit-session-summary`
- **Behavioral / prompt-injection:** `behavioral-rule-enforcer`, `claude-md-validator`, `untrusted-content-tagger`
- **MDM bypass:** `disable-all-hooks-detector`, `local-settings-precedence-checker`
- **Subagent / agent gating:** `subagent-spawn-guard`, `task-tool-input-guard`, `agent-allowlist-enforcer`

For the threat-to-hook coverage these were intended to provide (with the same caveat that the runtime did not enforce them), see [`docs/coverage-matrix.md`](../../docs/coverage-matrix.md) and [`docs/threat-model.md`](../../docs/threat-model.md).
