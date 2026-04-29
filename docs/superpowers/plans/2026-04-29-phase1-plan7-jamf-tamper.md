# Phase 1 / Plan 7: Jamf MDM Deployment + Tamper Detection

> **For agentic workers:** this plan is admin-tooling only; no new hooks.

**Goal:** Ship the Jamf-side admin tooling, the managed-settings installer with tamper detection (manifest hashing + `chflags uchg`), the verification script, and the deployment guide. Tag `v0.7.0-beta.0`.

**Predecessor commit:** `3b1a62e` (Plan 6 CHANGELOG; v0.6.0-beta.0 tagged).

---

## In Scope

See `docs/superpowers/specs/2026-04-29-plan7-jamf-tamper.md`.

## Tasks

### Task 1: Spec + plan docs

Both are this file and its sibling spec. Brief is fine.

Commit: `docs: Plan 7 spec + plan (Jamf + tamper detection)`

### Task 2: Jamf Configuration Profile template

- `installers/macos/jamf/com.bitsummit.claude-code-security.mobileconfig.xml`
  Custom Settings payload that writes to `/Library/Application Support/ClaudeCode/managed-settings.json`.
- `installers/macos/jamf/README.md`
  Import + scope + payload-population + verification.

Commit: `feat(installers): Jamf config profile template + admin docs`

### Task 3: Managed install + verify scripts

- `installers/macos/install-managed.sh`: sudo, compiles profile, writes settings, chowns `root:wheel`, chmods `0644`, `chflags uchg`, writes `.ccsec-manifest` with sha256.
- `installers/macos/verify-managed.sh`: re-hash, compare, warn on missing immutable flag.
- Both `chmod +x`. Note in spec: not exercised by bats (sudo + system path).

Commit: `feat(installers): managed-settings deployment with manifest hashing and immutable flag`

### Task 4: Deployment guide

`docs/deployment/mdm-jamf.md` covering compile, profile import, scoping, verification, scheduling, and tamper response. ~150 lines.

Commit: `docs: MDM Jamf deployment guide`

### Task 5: CHANGELOG + README

- `[0.7.0-beta.0] - 2026-04-29` entry in CHANGELOG.
- README: link to the deployment guide; note the Jamf profile template.

Commit: `docs: changelog v0.7.0-beta.0`

### Task 6: Final checks + tag + push + release

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm build
pnpm test
bats installers/macos/tests/install.bats
git tag -a v0.7.0-beta.0 -m "v0.7.0-beta.0: Jamf MDM + tamper detection"
git push origin main
git push origin v0.7.0-beta.0
gh release create v0.7.0-beta.0 ...
```

## Self-Review

- Spec + plan committed first.
- All admin tooling (install-managed, verify-managed) clearly scoped as sudo-only.
- bats remains green; per-user installer untouched.
- README mentions Plan 7 outputs.
- 313 tests still pass; no new tests required (admin scripts are not unit-tested in this plan).
