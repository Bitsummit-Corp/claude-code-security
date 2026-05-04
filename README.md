# claude-code-governance

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)](./CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-reference%20%E2%80%94%20under%20reconstruction-lightgrey)](#scope-reset-may-2026)

> **v0.1.0 is a reset, not a release of new functionality.** This repo was inherited under a `v0.9.0-rc.x` line that read like a working hardening kit one release away from `v1.0.0`. Independent review confirmed the delivery layer is broken end to end (see "Current state" below). Rather than wave through another rc, the architecture is being narrowed to one capability at a time. The retired `rc.x` line is preserved as reference material under `archive/`. Installation is paused; there is no working binary to ship right now. If you arrived expecting a download, see [Scope reset](#scope-reset-may-2026) for what is actually being built.

This repository is reference material for hardening Anthropic's Claude Code via hooks, settings overlays, and behavioral CLAUDE.md rules. It is not a turnkey kit. The 26 hooks under `archive/hooks-rc2/` are TypeScript implementations of patterns that were never validated against the real Claude Code harness contract; the v0.1.0 work is to validate one of those patterns end to end before doing anything else.

## Current state: delivery layer is broken

Four functional defects were identified in live testing on Ubuntu 24.04 with Claude Code 2.1.123. They are root causes, not edge cases. Each was independently confirmed against the source. Status will not change until the rebuild milestones below ship.

1. **Hooks do not fire.** The compiler emits hook entries as `{"name": "<hook-name>"}`. The Claude Code harness requires `{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}` and silently drops entries it cannot parse. Source: [`packages/cli/src/compiler.ts:16`](./packages/cli/src/compiler.ts) plus [`packages/cli/src/commands/apply.ts`](./packages/cli/src/commands/apply.ts).

2. **Audit log is not written from production sessions.** The CLI registers no `run-hook` subcommand, so the harness has no entry point to invoke after applying settings. The runner that calls `AuditLogger.write()` is reachable only from in-process tests. Source: [`packages/cli/src/index.ts`](./packages/cli/src/index.ts), [`packages/cli/src/commands/`](./packages/cli/src/commands/).

3. **All `permissions.deny` entries are dropped on session load.** The compiler emits deny rules as `{pattern, threat}` objects; the harness requires plain strings and removes object entries with `Non-string value in deny array was removed`. Coverage of T-001 through T-018 at the deny layer is currently 0/18. Source: [`packages/cli/src/compiler.ts:15`](./packages/cli/src/compiler.ts) (deny shape declared), [`packages/cli/src/compiler.ts:111-113`](./packages/cli/src/compiler.ts) (`stripThreatField` still emits objects), [`packages/cli/src/commands/apply.ts:42`](./packages/cli/src/commands/apply.ts) (`apply` channel passes `stripThreatField: false`).

4. **WebFetch deny patterns are skipped.** Patterns shipped as `WebFetch(*pastebin.com*)` use a glob form the harness rejects with `WebFetch permissions must use 'domain:' prefix`. The four egress-target hosts the project most directly defends against (T-005) are unenforced. Source: [`packages/settings/overlays/network-egress.json:4-7`](./packages/settings/overlays/network-egress.json).

Net runtime effect today: hook-layer enforcement is 0/26 (defect 1), deny-layer enforcement is 0/18 (defect 3), and the audit log is empty (defect 2). The retired hook source, settings overlays, and threat model remain useful as reference material; the runtime is not enforcing them.

### Why the inherited test suite did not catch this

The 313-test suite passes because every test layer exercises the producer side in isolation. Unit tests assert on the compiler's own output shape. Snapshot tests compare a checked-in compiled artifact to itself. Integration tests preload hook modules into an in-process `runHooks()` call instead of writing a real `~/.claude/settings.json` and spawning a Claude Code session. No test exists in the repository today that asks the question that matters: will Claude Code accept this file and invoke these hooks?

Closing this gap requires adding a harness-contract test layer, not just adding more unit tests. That is the central work item for M1.

## Scope reset (May 2026)

The inherited `rc.3 → pilot → v1.0.0` roadmap assumed one wave of fixes would land a production-ready release: four critical defects, a harness-contract test layer, pilot validation, and signing infrastructure all in one milestone. That is not realistic. The project is being narrowed to one capability at a time, with each milestone deliberately small enough to ship without a roadmap.

- **M1 — One hook, one platform, one secret pattern.** A single `PreToolUse` hook on macOS that blocks one regex-detectable secret pattern (e.g., GitHub PAT `ghp_[a-zA-Z0-9]{36}`), with an integration test that writes a real `~/.claude/settings.json` and spawns the Claude Code harness. The test asserts the hook fired and the audit log gained a record.
- **M2 — Calibration documentation.** A guide that tells the operator how to add their own regex patterns and validate them against the same harness-contract test the M1 hook ships with. The repo will not ship a curated secret list — see [Why this repo is non-composable, on purpose](#why-this-repo-is-non-composable-on-purpose).
- **M3 — Port to one Linux distro.** Same hook, same test, on Ubuntu 24.04. Confirms the contract holds across BSD vs GNU tooling.
- **M4 — Second hook category.** Only after M1–M3 are green.

No dates. No rc tags. No `v1.0.0`.

## What is actually protected today

Today, nothing in this repo is protecting your machine. The 26 hooks under `archive/hooks-rc2/` are reference TypeScript implementations of patterns we intend to validate against the Claude Code harness contract — they are not currently wired up correctly. Treat the manifest as a wishlist, not a feature list.

For documented detection gaps in the rc.x design (heredoc bodies, hardlink aliasing, alias-wrapped git, pipe-to-interpreter, cross-process audit-log writes) see [`docs/known-bypasses.md`](./docs/known-bypasses.md). Those gaps remain even when the delivery layer eventually works.

## Install

Installation is paused until M1 ships. The 26 hooks from rc.2 have been moved to `archive/hooks-rc2/` and are kept as reference TypeScript implementations of the patterns we intend to validate against the real Claude Code harness contract. Do not run `ccsec apply` against a real `~/.claude/settings.json` — the compiled output is not currently a valid Claude Code settings file.

If you want to read the retired hook source, start at [`archive/hooks-rc2/`](./archive/hooks-rc2/). If you want a working binary, watch the [release feed](https://github.com/jwtor7/claude-code-governance/releases) — there will be no release until M1 lands a real harness-contract test.

## Why this repo is non-composable, on purpose

Hooks are deterministic regex matchers calibrated to the secrets, paths, and tools their operator actually uses. A hook that detects "all possible AWS keys" without knowing your tenant prefix is theater. A hook that detects `AKIA[0-9A-Z]{16}` against an audit log of your last 90 days of commits is operational security. Calibration is the work; the regex table is the artifact.

Therefore, this repo is reference material, not a turnkey kit. Forking, deleting hooks you do not need, and replacing the regex tables with patterns drawn from your own secret inventory is the expected workflow — not the exception. The M2 milestone exists to document that workflow. Until then, "drop in this profile and you are protected" is not a claim this repo makes.

## Documentation tracks

Two tracks are useful as-is. The rest were aspirational under the rc.x line and are deferred to the M1+ rebuild.

### Project entry point
- This README.
- [`SECURITY.md`](./SECURITY.md): vulnerability disclosure.
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md): community norms.
- [`LICENSE`](./LICENSE): MIT.
- [`CHANGELOG.md`](./CHANGELOG.md): per-release notes; v0.1.0 entry summarizes the reset.

### Reference (threat-driven, retired but readable)
- [`docs/threat-model.md`](./docs/threat-model.md): threat register (T-001 through T-018) from the rc.x line. Useful for thinking about vectors; not currently mitigated.
- [`docs/known-bypasses.md`](./docs/known-bypasses.md): documented detection gaps with vector / detection status / recommended response.
- [`archive/hooks-rc2/`](./archive/hooks-rc2/): retired hook implementations, indexed in their own README.

`docs/coverage-matrix.md` and `docs/hooks/<name>.md` are auto-generated artifacts from the rc.x flow. They are accurate descriptions of what the rc.x source intended to do, not of what runs today.

## Acknowledgement

The four defects above were identified by an external technical reviewer running `v0.9.0-rc.2` in a real Claude Code session against a real workload. The report and proposed fixes were filed as a clean issue with passing tests. That is the discovery shape this project needs more of, and it is the reason the architecture is being reset rather than papered over with another rc. Public acknowledgement (with permission) will accompany M1 when it ships.

## License

MIT. See [LICENSE](./LICENSE).

## Security

Report vulnerabilities to `security@bitsummit.com`. See [SECURITY.md](./SECURITY.md).
