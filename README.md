# claude-code-governance

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.9.0--rc.2%20(defects%20pending%20fix)-red)](./CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-DO%20NOT%20DEPLOY%20rc.2-red)](#known-defects-in-v090-rc2)
[![Hooks](https://img.shields.io/badge/hooks-26%20(delivery%20layer%20broken)-yellow)](./docs/coverage-matrix.md)
[![Threat coverage](https://img.shields.io/badge/threat%20coverage-14%2F18%20mapped-yellow)](./docs/coverage-matrix.md)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF%20Scorecard-pending%20v1.0.0-lightgrey)](./docs/superpowers/plans/)

> **Status disclosure - read before installing.** Tag `v0.9.0-rc.2` ships with four critical defects in the bridge between this project's compiler and the Claude Code harness. As tagged, the hook layer does not fire, the audit log is not written from production sessions, the `permissions.deny` array is dropped wholesale by the harness on session load, and the WebFetch deny patterns use a syntax the harness rejects. The 313-test suite passes in this state because no test layer exercises the contract between the emitted `~/.claude/settings.json` and the Claude Code harness that consumes it. **Do not deploy `v0.9.0-rc.2` to production.** Fixes are in progress and will land in `v0.9.0-rc.3` together with a harness-contract test gate in CI. See [Known defects](#known-defects-in-v090-rc2) below for the technical details and the remediation plan.

Open-source hardening reference for Anthropic's Claude Code. Intended to ship hooks, layered settings templates, behavioral CLAUDE.md rules, and OS-specific installers so individual developers can harden their own installs and IT admins can deploy a vetted policy via MDM. The hook modules, settings overlays, threat model, and macOS installer artifacts are all in the repository today; the runtime contract that wires them into Claude Code is currently broken (see disclosure above).

## Known defects in v0.9.0-rc.2

Four functional defects were identified in live testing on Ubuntu 24.04 with Claude Code 2.1.123. They are root causes, not edge cases. Each was independently confirmed against the source.

1. **Hooks do not fire.** The compiler emits hook entries as `{"name": "<hook-name>"}`. The Claude Code harness requires `{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}` and silently drops entries it cannot parse. Source: [`packages/cli/src/compiler.ts:16`](./packages/cli/src/compiler.ts) plus [`packages/cli/src/commands/apply.ts`](./packages/cli/src/commands/apply.ts).

2. **Audit log is not written from production sessions.** The CLI registers no `run-hook` subcommand, so the harness has no entry point to invoke after applying settings. The runner that calls `AuditLogger.write()` is reachable only from in-process tests. Source: [`packages/cli/src/index.ts`](./packages/cli/src/index.ts), [`packages/cli/src/commands/`](./packages/cli/src/commands/).

3. **All `permissions.deny` entries are dropped on session load.** The compiler emits deny rules as `{pattern, threat}` objects; the harness requires plain strings and removes object entries with `Non-string value in deny array was removed`. Coverage of T-001 through T-018 at the deny layer is currently 0/18. Source: [`packages/cli/src/compiler.ts:15`](./packages/cli/src/compiler.ts) (deny shape declared), [`packages/cli/src/compiler.ts:111-113`](./packages/cli/src/compiler.ts) (`stripThreatField` still emits objects), [`packages/cli/src/commands/apply.ts:42`](./packages/cli/src/commands/apply.ts) (`apply` channel passes `stripThreatField: false`).

4. **WebFetch deny patterns are skipped.** Patterns shipped as `WebFetch(*pastebin.com*)` use a glob form the harness rejects with `WebFetch permissions must use 'domain:' prefix`. The four egress-target hosts the project most directly defends against (T-005) are unenforced. Source: [`packages/settings/overlays/network-egress.json:4-7`](./packages/settings/overlays/network-egress.json).

Net runtime effect on rc.2: hook-layer enforcement is 0/26 (defect 1), deny-layer enforcement is 0/18 (defect 3), and the audit log is empty (defect 2). The shipped hook source, settings overlays, and threat model remain useful as reference material; the runtime is not enforcing them on rc.2.

### Why the test suite did not catch this

The 313-test suite passes because every test layer exercises the producer side in isolation. Unit tests assert on the compiler's own output shape. Snapshot tests compare a checked-in compiled artifact to itself. Integration tests preload hook modules into an in-process `runHooks()` call instead of writing a real `~/.claude/settings.json` and spawning a Claude Code session. No test exists in the repository today that asks the question that matters: will Claude Code accept this file and invoke these hooks? That gap is the structural cause of all four defects above. Closing it requires adding a harness-contract test layer, not adding more unit tests.

### What is being done

- Fixes for all four defects are staged for `v0.9.0-rc.3` together with regression tests at the harness boundary, not the unit boundary.
- A harness-contract test layer is being added in CI: every compiled profile will be validated against the Claude Code settings schema, and an end-to-end smoke test will boot Claude Code against the compiled `regulated` profile and assert the four bug fixtures are blocked plus the audit log gains a record per fixture.
- The README badges have been corrected. Threat coverage moved from `18/18` to `14/18 mapped` to match the auto-generated [`docs/coverage-matrix.md`](./docs/coverage-matrix.md). T-007, T-009, T-014, and T-016 are listed in the threat model but have no hook row in the matrix.
- The previous "Plans 1-9 shipped, feature-complete and infrastructure-complete" framing has been retired until rc.3 ships and the harness-contract gate is green.
- The companion-document set (per-hook reference docs at `docs/hooks/*.md`) currently consists of auto-generated manifest tables with TODO placeholders in the Behavior and Notes sections; populating those sections is part of the rc.3 work.

### How to evaluate the project today

If you want to read the threat model, the deployment runbooks, the macOS installer scripts, the hook source, and the engagement template, all of that is shipped and useful as reference material. If you want to install the hooks against a live Claude Code session, wait for `v0.9.0-rc.3`. Watch the [release feed](https://github.com/jwtor7/claude-code-governance/releases) for the rc.3 announcement.

### Acknowledgement

The four defects above were identified by an external technical reviewer running rc.2 in a real Claude Code session against a real workload. The report and proposed fixes were filed as a clean issue with passing tests. That signal is exactly the discovery shape this project's pilot-validation runbook is designed to surface, and it is being treated as the most valuable input the project has received to date. Public acknowledgement of the reviewer (with permission) will accompany the rc.3 release notes.

## v1.0.0 path

`v1.0.0` is now gated on three items, in this order:

1. **`v0.9.0-rc.3`** ships the four [Known defects](#known-defects-in-v090-rc2) fixed at the source plus a harness-contract test gate in CI. This is the immediate next step.
2. **Pilot validation** with a real regulated adopter - see [docs/pilot-validation.md](./docs/pilot-validation.md) for the six-week runbook. Pilot acceptance criteria require a successful end-to-end harness validation against rc.3, not against rc.2.
3. **Release-signing secrets provisioned** (PGP, npm token, Apple Developer ID, optional Windows EV) - see [docs/v1.0.0-readiness.md](./docs/v1.0.0-readiness.md) for the full checklist.

Adopters that need extended security governance beyond the open-source defaults (custom-profile compilation, SIEM integration, compliance-regime mapping, training) can engage BITSUMMIT directly - see [docs/bitsummit-security-engagement.md](./docs/bitsummit-security-engagement.md).

The full plan sequence is at [`docs/superpowers/plans/`](./docs/superpowers/plans/).

## Table of Contents

- [Known defects in v0.9.0-rc.2](#known-defects-in-v090-rc2)
- [v1.0.0 path](#v100-path)
- [What's protected / What's not](#whats-protected--whats-not)
- [Install](#install)
- [Profile Chooser](#profile-chooser)
- [Documentation tracks](#documentation-tracks)
- [License](#license)
- [Security](#security)

## What's protected / What's not

> **Caveat for v0.9.0-rc.2.** The "Protected" list below describes the design intent of the shipped hook modules and settings overlays. As of rc.2, the harness-contract bugs in [Known defects](#known-defects-in-v090-rc2) prevent these protections from running on a live Claude Code session. The list will be accurate again when rc.3 ships with the harness-contract gate green; until then, treat it as a description of what the project is designed to do, not what running rc.2 actually does.

We publish detection gaps openly. The signal-to-noise ratio of this repo depends on operators trusting the documented coverage; "we catch everything" claims train operators to stop thinking.

**Designed to be protected** (covered by hooks + settings + behavioral rules in source; see caveat above):

- Secret leak via Bash, MCP input, tool output, env-dump, keychain CLI.
- Destructive filesystem ops (`rm -rf /`, `mkfs`, `dd`, dotfile rewrites).
- Credential file reads (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`).
- Branch sabotage (force push, hard reset, `--no-verify`, amend on pushed commits, history rewrite).
- Network exfil via WebFetch and Bash (`curl`, `wget`, `fetch`) with deny-by-default allowlist.
- Pipe-to-shell remote execution (`curl | bash` and shape-equivalents).
- Prompt injection from tool output (CLAUDE.md validation, untrusted-content tagging, behavioral rules).
- Subagent escape (allowlist + spawn guard + Task tool input scan).
- MDM bypass via `disableAllHooks` (passive detection per ADR-0003).
- Audit log tampering (sha256 hash chain).
- Supply chain via submodule injection.

**Not fully protected** (documented gaps; see [docs/known-bypasses.md](./docs/known-bypasses.md)):

- Heredoc bodies are not parsed; semicolons and command substitution inside heredocs are not flagged at the structural layer.
- Pipe-to-interpreter (`| python -c`, `| node -e`, `| perl -e`) is out of scope for `pipe-to-shell-guard`; rely on `bash-egress-guard` for the curl half.
- Obfuscated git via shell aliases or function wrappers is not detected; the hook matches the literal `git` CLI.
- Filesystem hardlinks and bind mounts that alias credential dirs to benign paths are not detected; rely on TCC / AppArmor / DAC at the OS layer.
- Cross-process audit log writes can produce false-positive tamper alerts; per-PID audit files are deferred to a post-v1.0 plan.

For the full list with vector / detection status / recommended response, see [`docs/known-bypasses.md`](./docs/known-bypasses.md).

## Install

> **Do not install rc.2 onto a production developer or fleet machine.** The install steps below produce a `~/.claude/settings.json` that the Claude Code harness silently rejects in part (deny rules dropped, hook entries ignored). Wait for `v0.9.0-rc.3`.

### Channel 1: Claude Code Plugin (recommended for individual devs) - Not Published Yet (ETA: May 29, 2026)

```
/plugin install bitsummit/hardening
/ccsec apply baseline
```

### Channel 2: npm (for CI use, non-plugin contexts)

The npm package name still uses the project's original name `claude-code-security`; rename to `claude-code-governance` is pending `v1.0.0`. Both names refer to the same project.

```
npm i -g @bitsummit/claude-code-security
ccsec apply --profile baseline
```

### Channel 3: Raw repo (for MDM admins)

```
git clone https://github.com/jwtor7/claude-code-governance.git
cd claude-code-governance
./installers/macos/install.sh --profile baseline
```

For Jamf-managed fleets, use the Configuration Profile template at `installers/macos/jamf/com.bitsummit.claude-code-security.mobileconfig.xml` together with `installers/macos/install-managed.sh` (sudo, root-owned, immutable) and `installers/macos/verify-managed.sh` (tamper detection). See [docs/deployment/mdm-jamf.md](./docs/deployment/mdm-jamf.md) for the full IT-admin workflow.

For Windows (Intune) and Linux (Ansible / `.deb` / `.rpm`) deployment guides, see [installers/windows/README.md](./installers/windows/README.md) and [installers/linux/README.md](./installers/linux/README.md). Both ship as substantive guides today; the script artifacts they reference are templates pending v1.1 / v1.2.

## Profile Chooser

| Profile | When to use |
| --- | --- |
| `baseline` | Solo dev. Mostly warns. Doesn't break flow. |
| `strict` | Team / shared infra. Tighter egress. Blocks dotfile + git-destructive ops. |
| `regulated` | Regulated environment (healthcare, legal, public sector). Tightest egress + MDM bypass detector + agent allowlist. |

Run `ccsec apply --profile <profile>` to install. Run `ccsec doctor` to verify file integrity (settings file present, JSON valid, lockfile hash match). Note that `doctor` does not yet validate the harness contract; harness-acceptance validation arrives with rc.3 and the new test gate. See [`docs/settings-reference.md`](./docs/settings-reference.md) for the full schema of every key.

## Documentation tracks

Five documentation tracks, with completion status noted per track:

### Track 1 - Project entry point
- This README.
- [`SECURITY.md`](./SECURITY.md): vulnerability disclosure.
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md): community norms.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md): how to set up, what kinds of contributions are welcomed, PR workflow, hook-adding procedure.
- [`OWNERS.md`](./OWNERS.md): current maintainers, decision rights, response-time expectations.
- [`LICENSE`](./LICENSE): MIT.
- [`CHANGELOG.md`](./CHANGELOG.md): per-release notes.

### Track 2 - Deployment
- [`docs/deployment/mdm-jamf.md`](./docs/deployment/mdm-jamf.md): macOS Jamf workflow (the working reference).
- [`installers/macos/README.md`](./installers/macos/README.md): per-user and fleet-managed install paths for macOS.
- [`installers/macos/`](./installers/macos/): `install.sh`, `install-managed.sh`, `verify-managed.sh`, Jamf Configuration Profile template.
- [`installers/windows/README.md`](./installers/windows/README.md): Intune deployment guide (templates pending v1.1).
- [`installers/linux/README.md`](./installers/linux/README.md): Ansible / `.deb` / `.rpm` deployment guide (templates pending v1.2).

### Track 3 - Operator reference (threat-driven)
- [`docs/threat-model.md`](./docs/threat-model.md): full threat register (T-001 through T-018).
- [`docs/coverage-matrix.md`](./docs/coverage-matrix.md): auto-generated threat-to-hook map. Regenerate with `pnpm gen:coverage-matrix`.
- [`docs/hooks/<name>.md`](./docs/hooks/): one auto-generated page per hook (manifest tables only as of rc.2; the Behavior and Notes sections are TODO placeholders pending rc.3). Regenerate with `pnpm gen:hook-docs`.
- [`docs/known-bypasses.md`](./docs/known-bypasses.md): documented detection gaps with vector / detection status / recommended response.

### Track 4 - Configuration reference
- [`docs/settings-reference.md`](./docs/settings-reference.md): every settings.json key the project uses.
- Profile chooser table (above).
- Per-profile templates at `packages/settings/profiles/`.

### Track 5 - Project meta (decisions + history)
- [`docs/adr/0001-node-implementation.md`](./docs/adr/0001-node-implementation.md): why Node TypeScript over Go.
- [`docs/adr/0002-monorepo-layout.md`](./docs/adr/0002-monorepo-layout.md): pnpm workspaces structure.
- [`docs/adr/0003-passive-only-posture.md`](./docs/adr/0003-passive-only-posture.md): no daemon, no auto-remediation.
- [`docs/adr/0004-hook-contract-bumps-plan2.md`](./docs/adr/0004-hook-contract-bumps-plan2.md): hook manifest schema evolution.
- [`docs/adr/0005-rules-package-decision.md`](./docs/adr/0005-rules-package-decision.md): markdown templates over executable rules.
- [`docs/adr/0006-mdm-deployment-decision.md`](./docs/adr/0006-mdm-deployment-decision.md): Configuration Profile + per-OS path templates.
- [`docs/superpowers/plans/`](./docs/superpowers/plans/): per-plan implementation sequence (Plan 1 through Plan 10).

## License

MIT. See [LICENSE](./LICENSE).

## Security

Report vulnerabilities to `security@bitsummit.com`. See [SECURITY.md](./SECURITY.md).
