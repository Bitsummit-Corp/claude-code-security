# Changelog

All notable changes to this project will be documented here. Format follows [Keep a Changelog](https://keepachangelog.com/), versioning follows [SemVer](https://semver.org/) with a security-tightening carve-out (see SECURITY.md).

## [Unreleased]

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
