# claude-code-security

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.9.0--rc.2-orange)](./CHANGELOG.md)
[![Hooks](https://img.shields.io/badge/hooks-26-success)](./docs/coverage-matrix.md)
[![Threat coverage](https://img.shields.io/badge/threat%20coverage-18%2F18-success)](./docs/threat-model.md)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF%20Scorecard-pending%20v1.0.0-lightgrey)](./docs/superpowers/plans/)

> **Status:** Release candidate (`v0.9.0-rc.2`). Plans 1-9 of 10 shipped. The project is feature-complete (26 hooks, 18 threats, 313 tests) and infrastructure-complete (SBOM, GHSA pipeline, SEA binary build templates, SHA256SUMS, release runbook). **Plan 10 is user-action**: pilot validation. `v1.0.0` ships when the maintainer completes Plan 10. See [docs/v1.0.0-readiness.md](./docs/v1.0.0-readiness.md).

Open-source hardening reference for Anthropic's Claude Code. Ships hooks, layered settings templates, behavioral CLAUDE.md rules, and OS-specific installers so individual developers can harden their own installs and IT admins can deploy a vetted policy via MDM.

## v1.0.0 path

`v1.0.0` is gated on two user-action items the maintainer drives, not Claude Code:

1. **Pilot validation** with a real regulated client - see [docs/pilot-validation.md](./docs/pilot-validation.md) for the six-week runbook.
2. **Release-signing secrets provisioned** (PGP, npm token, Apple Developer ID, optional Windows EV) - see [docs/v1.0.0-readiness.md](./docs/v1.0.0-readiness.md) for the full checklist.

Adopters that need extended security governance beyond the open-source defaults (custom-profile compilation, SIEM integration, compliance-regime mapping, training) can engage BITSUMMIT directly - see [docs/bitsummit-security-engagement.md](./docs/bitsummit-security-engagement.md).

The full Plan 1 through Plan 10 sequence is at [`docs/superpowers/plans/`](./docs/superpowers/plans/).

## Table of Contents

- [v1.0.0 path](#v100-path)
- [What's protected / What's not](#whats-protected--whats-not)
- [Install](#install)
- [Profile Chooser](#profile-chooser)
- [Documentation tracks](#documentation-tracks)
- [License](#license)
- [Security](#security)

## What's protected / What's not

We publish detection gaps openly. The signal-to-noise ratio of this repo depends on operators trusting the documented coverage; "we catch everything" claims train operators to stop thinking.

**Protected** (covered by hooks + settings + behavioral rules):

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

### Channel 1: Claude Code Plugin (recommended for individual devs) - Not Published Yet (ETA 6 - May 29th, 2026)

```
/plugin install bitsummit/hardening
/ccsec apply baseline
```

### Channel 2: npm (for CI use, non-plugin contexts)

```
npm i -g @bitsummit/claude-code-security
ccsec apply --profile baseline
```

### Channel 3: Raw repo (for MDM admins)

```
git clone https://github.com/Bitsummit-Corp/claude-code-governance.git
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

Run `ccsec apply --profile <profile>` to install. Run `ccsec doctor` to verify the result. See [`docs/settings-reference.md`](./docs/settings-reference.md) for the full schema of every key.

## Documentation tracks

Five tracks of documentation, all shipped in this release:

### Track 1 - Project entry point
- This README.
- [`SECURITY.md`](./SECURITY.md): vulnerability disclosure.
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md): community norms.
- [`LICENSE`](./LICENSE): MIT.
- [`CHANGELOG.md`](./CHANGELOG.md): per-release notes.

### Track 2 - Deployment
- [`docs/deployment/mdm-jamf.md`](./docs/deployment/mdm-jamf.md): macOS Jamf workflow (the working reference).
- [`installers/macos/`](./installers/macos/): `install.sh`, `install-managed.sh`, `verify-managed.sh`, Jamf Configuration Profile template.
- [`installers/windows/README.md`](./installers/windows/README.md): Intune deployment guide (templates pending v1.1).
- [`installers/linux/README.md`](./installers/linux/README.md): Ansible / `.deb` / `.rpm` deployment guide (templates pending v1.2).

### Track 3 - Operator reference (threat-driven)
- [`docs/threat-model.md`](./docs/threat-model.md): full threat register (T-001 through T-018).
- [`docs/coverage-matrix.md`](./docs/coverage-matrix.md): auto-generated threat-to-hook map. Regenerate with `pnpm gen:coverage-matrix`.
- [`docs/hooks/<name>.md`](./docs/hooks/): one auto-generated page per hook. Regenerate with `pnpm gen:hook-docs`.
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
