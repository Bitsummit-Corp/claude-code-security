# Changelog

All notable changes to this project will be documented here. Format follows [Keep a Changelog](https://keepachangelog.com/), versioning follows [SemVer](https://semver.org/) with a security-tightening carve-out (see SECURITY.md).

## [Unreleased]

## [0.4.0-alpha.0] - 2026-04-29

### Added
- 4 new hooks: `webfetch-egress-guard`, `bash-egress-guard`, `audit-tamper-detector`, `audit-session-summary`.
- New overlays: `overlays/network-egress.json` and `overlays/audit.json`.
- Integration transcripts: webfetch-exfil-attempt, bash-egress-attempt, audit-tamper-attempt.
- Threat model entries: T-005 fully covered, T-014 Tool Spoofing via MCP (partial), T-015 Audit Log Tampering, T-016 Hook DoS, T-017 Repudiation of Risky Action.

### Changed
- `AuditLogger.write()` serializes concurrent in-process writes via internal promise queue; closes the race noted in Plan 1 review.
- `AuditLogger.verify()` returns `{ ok: true, records: 0 }` on missing file (was throwing) and `{ ok: false, brokenAt: i }` on JSON-parse failure (was throwing).
- All 3 profiles extend the network-egress and audit overlays.

### Notes
- Cross-process audit log safety still tracked for a future plan (per-PID files or flock).
- Strict / regulated profile differentiation still tracked for Plan 5.
- Plugin / npm distribution still tracked for Plan 6.

## [0.3.0-alpha.0] - 2026-04-29

### Added
- 6 new hooks: `bash-structural-guard`, `pipe-to-shell-guard`, `branch-protection-guard`, `commit-amend-pushed-guard`, `submodule-injection-guard`, `git-history-rewrite-guard`.
- New overlays: `overlays/bash-structural.json` and `overlays/branch-guards.json`.
- `fast-check` property-based fuzz test for `bash-parser`.
- Integration transcripts: bash-structural-attempt, branch-sabotage-attempt, history-rewrite-attempt.
- Threat model entries: T-005 Supply Chain via Submodule, T-006 Pipe-to-Shell Remote Execution, T-007 Command Chaining Bypass, T-008 Git History Rewrite, T-009 Arbitrary Code via eval/command substitution.

### Changed
- Bash parser detects fullwidth pipe (U+FF5C) and fullwidth dollar (U+FF04) as unicode lookalikes.
- Bash parser detects `&` (background operator) as a new structural risk kind.
- T-004 marked fully covered (was partial in Plan 2).
- All 3 profiles extend the new overlays.

### Notes
- Audit-logger concurrency hardening still tracked for Plan 4.
- Egress / WebFetch allowlist still tracked for Plan 4.
- Strict / regulated profile differentiation still tracked for Plan 5.

## [0.2.0-alpha.0] - 2026-04-29

### Added
- 7 new hooks: `secret-leak-detector` (PostToolUse), `keychain-guard`, `mcp-secret-guard`, `destructive-fs-guard`, `git-destructive-guard`, `sensitive-paths-guard`, `dotfile-guard`.
- `packages/settings/overlays/destructive.json` and `packages/settings/overlays/sensitive-paths.json`.
- `packages/settings/profiles/strict.json` and `packages/settings/profiles/regulated.json` (shells; Plan 5 differentiates).
- Compiled snapshots for strict and regulated profiles.
- 4 new integration transcripts: secret-leak-postonly, destructive-attempt, sensitive-paths-attempt, attack-chain.
- Threat model entries for T-002, T-003, T-004; T-001 expanded with PostToolUse + MCP + keychain coverage.
- `docs/coverage-matrix.md` mapping every hook to threats and profiles.
- ADR-0004 documenting hook contract bumps.

### Changed
- `HookManifest.severity` accepts `HookSeverity` scalar OR `Record<HookProfile, HookSeverity>` per-profile record (additive, backward compatible).
- `HookManifest.matchers` accepts `*` (any tool) and `<prefix>*` patterns.
- `HookContext` gains optional `response` field for PostToolUse hooks.
- Runner resolves per-profile severity and modulates hook decisions accordingly.
- `baseline` profile now extends three overlays (was one in Plan 1).

### Notes
- Audit-logger concurrency hardening still tracked for Plan 4.
- Egress / WebFetch allowlist still tracked for Plan 4 (attack-chain transcript flags step 2 as partial-block).
- Strict / regulated profile differentiation still tracked for Plan 5.

## [0.1.0-alpha.0] - 2026-04-29

### Added
- pnpm-workspace monorepo with TypeScript, vitest, ESLint, Prettier baseline.
- `packages/core/` runtime: hook contract types, manifest validator (zod), path-token resolver (HOME/SSH/AWS/TMP/KEYS), secret pattern library (AWS/GitHub/Stripe/PEM/Slack/Google), structural-bash parser (chaining/substitution/pipe-to-shell/unicode-lookalikes), JSONL audit logger with sha256 hash chain, hook runner with profile/matcher gating and timeout enforcement.
- `packages/hooks/secret-guard` canary hook (PreToolUse, severity=block) blocking secret literals and env-dump patterns.
- `packages/settings/` with base config, secrets overlay, baseline profile, compiled snapshot.
- `packages/cli/` with `ccsec compile | apply | doctor` commands and Commander entry point.
- `installers/macos/` with `install.sh`, `verify.sh`, and bats integration tests.
- `installers/windows/` and `installers/linux/` placeholder READMEs (planned for v1.1 / v1.2).
- Initial threat model documenting T-001 (Secret Leak via Tool Output).
- Three architecture decision records: ADR-0001 Node.js hooks, ADR-0002 monorepo layout, ADR-0003 passive-only enforcement posture.
- `SECURITY.md` disclosure policy.
- `tests/integration/` with synthetic transcript replay through runner+secret-guard.
- GitHub Actions CI workflow on `macos-14` running lint, typecheck, build, vitest with coverage gates, and bats.

### Fixed
- `secret-guard` regex now blocks bare `env` and `printenv` (full environment dump); earlier draft required trailing arguments.
- CLI `--settings-root` Commander option now applies the default value correctly (third-arg signature was previously the description).
- Root `build:settings` script now invokes `bin/ccsec.js` (the entry that calls `main()`) instead of `dist/index.js` (which only exports `main`).

### Notes
- Audit-logger walking-skeleton has no in-process write serialization or cross-process locking. Concurrent writers may fork the chain. Hardening tracked for Plan 4 (audit overlay).
