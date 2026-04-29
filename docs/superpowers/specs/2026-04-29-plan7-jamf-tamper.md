# Spec: Plan 7 - Jamf MDM Deployment + Tamper Detection

**Status:** Locked
**Date:** 2026-04-29
**Plan target tag:** `v0.7.0-beta.0`
**Predecessor:** Plan 6 (`v0.6.0-beta.0`; plugin + npm + raw distribution channels live).

---

## 1. Purpose

Plan 6 covered the **per-user** install paths (plugin, npm, raw repo). Plan 7 covers the **fleet-managed** install path: an IT admin pushes a vetted Claude Code policy to a fleet of Macs via Jamf, and a tamper-detection layer flags any post-deployment drift.

This plan ships the admin tooling, not new hooks. The hook surface is feature-complete as of Plan 5.

## 2. In Scope

- A Jamf Configuration Profile (`.mobileconfig`) template that writes the compiled `managed-settings.json` to `/Library/Application Support/ClaudeCode/managed-settings.json`.
- `installers/macos/install-managed.sh`: a sudo-only installer that compiles the chosen profile, writes managed-settings.json with `root:wheel` ownership, mode `0644`, and the macOS `uchg` immutable flag, plus a `.ccsec-manifest` JSON file recording sha256 of the deployed config.
- `installers/macos/verify-managed.sh`: a verifier that re-hashes the deployed file and compares against the manifest. Exit code 2 on tamper. Warns if the file is missing the `uchg` flag.
- An admin README at `installers/macos/jamf/README.md` covering: importing the .mobileconfig, scoping to a smart group, embedding the compiled payload, and verification steps.
- A deployment guide at `docs/deployment/mdm-jamf.md` for IT admins.

## 3. Out of Scope

- Intune / Workspace ONE / Kandji equivalents (future plan).
- Linux / Windows MDM equivalents (future plan).
- Signed releases / SBOM (Plan 9).
- New hooks. The hook surface is frozen at 26.
- bats coverage of `install-managed.sh` and `verify-managed.sh`. Both require sudo and write to `/Library/Application Support/ClaudeCode/`. The bats suite continues to test the per-user install path only. Admins can sanity check locally with a temp directory.

## 4. Success Criteria

- Admin can run `sudo installers/macos/install-managed.sh --profile regulated` and end up with an immutable, root-owned `managed-settings.json`.
- `verify-managed.sh` returns exit 0 OK, exit 2 on hash mismatch, with a `WARN` line if `uchg` is missing.
- The `.mobileconfig` template imports cleanly into Jamf Pro and the README walks the admin from import to verification in <30 minutes.
- All 313 existing tests still pass; new release ships as `v0.7.0-beta.0`.
