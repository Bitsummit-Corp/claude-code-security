# Changelog

All notable changes to this project will be documented here. Format follows [Keep a Changelog](https://keepachangelog.com/), versioning follows [SemVer](https://semver.org/) with a security-tightening carve-out (see SECURITY.md).

## [v0.1.0] — 2026-05-04

Scope reset. The inherited `v0.9.0-rc.x` line was retired and the project restarted at `v0.1.0`. This is not a feature release; it is an honest reset of the repo's claims to match what the code actually does (nothing, at runtime).

### Removed
- `v0.9.0-rc.x` as the active release line. The `rc.3 → pilot → v1.0.0` roadmap was not viable in one wave (four critical defects + harness-contract test gate + pilot validation + signing infrastructure in one milestone). It has been replaced by an `M1 → M2 → M3 → M4` cadence with one capability per milestone (see README "Scope reset (May 2026)"). No dates, no rc tags, no `v1.0.0` reference in the active roadmap.
- The "Plans 1-9 shipped, feature-complete and infrastructure-complete" framing, residual mentions of which had been retained through rc.2.
- Cross-platform installer claims that were never validated (Windows Intune templates, Linux Ansible / `.deb` / `.rpm` templates). These were template-only under the rc.x line and are deferred until at least one platform passes a real harness-contract test.
- "26 hooks across 3 profiles" framing. Hook count is the wrong unit; calibrated detections validated against the real harness are the unit.

### Changed
- `packages/hooks/src/` moved to `archive/hooks-rc2/`. The 26 retired hook implementations are preserved as reference material; `packages/hooks/src/` no longer exists. The visual signal of the move is intentional. See `archive/hooks-rc2/README.md`.
- Version bumped to `0.1.0` across all ten surfaces: root `package.json`, the seven workspace `package.json` files, `packages/plugin/.claude-plugin/plugin.json`, the `PKG_VERSION` constant in `packages/cli/src/index.ts`, the `VERSION` constant in `packages/cli/src/commands/apply.ts`, and the `ccsec_version` field in `packages/settings/base.json`. The three compiled artifacts under `packages/settings/compiled/` and the vitest snapshot at `packages/settings/__snapshots__/snapshot.test.ts.snap` were regenerated to match.
- `README.md` rewritten. New top-level sections: "Current state: delivery layer is broken" (the four rc.2 defects preserved verbatim, reframed as ground truth for the reset), "Scope reset (May 2026)" (M1-M4 milestones), "What is actually protected today" (today, nothing), "Install" (paused), "Why this repo is non-composable, on purpose" (calibration is the work; regex tables are the artifact).
- `CONTRIBUTING.md` and `CLAUDE.md` carry a v0.1.0 scope-reset banner. Path references to `packages/hooks/src/` updated to `archive/hooks-rc2/`. The hook-authoring body of `CONTRIBUTING.md` is preserved as historical reference for the rc.x flow; the M1+ authoring flow will be documented when it ships.
- `scripts/gen-hook-docs.mjs` and `scripts/gen-coverage-matrix.mjs` `SRC_DIR` updated to `archive/hooks-rc2/`. The generators are not part of the v0.1.0 build flow; they are kept executable so the historical pages can be regenerated against the retired source if needed.
- `docs/v1.0.0-readiness.md` carries a deprecation banner pointing back to the README scope reset section. Body preserved as history.

### Notes
- Build, typecheck, and tests will not pass end to end after this commit. `packages/hooks/` no longer has source; `tests/integration/_all-hooks.ts` imports from `@bitsummit/ccsec-hooks/dist/...` which is gitignored and will not regenerate without source. This is expected: the README explicitly states the runtime is broken and installation is paused. M1 will rebuild the relevant slice with a real harness-contract test rather than restoring the inherited test surface.
- No tag was retired. `v0.9.0-rc.2` was never published to the GitHub remote (no `git tag`, no GitHub Release). The mitigation step in the reset plan (archive the rc.2 release notes before deleting the tag) was a no-op for this repo.
- The four defects from rc.2 are preserved verbatim in `README.md` "Current state: delivery layer is broken." They are the ground truth for "the delivery layer is broken" and will only be retired when the M1 hook proves the harness contract works on at least one path.

## Pre-reset history (retired)

The entries below describe the retired `v0.9.0-rc.x` release line. They are preserved for lineage and incident reconstruction. None of the milestones, dates, or roadmap claims in these entries are active under v0.1.0; see the v0.1.0 entry above for the current state.

## [Unreleased]

### Changed
- **2026-05-04 00:43** Sharpened the "Why the test suite did not catch this" punchline: split the closing sentence into its own paragraph, and tightened "Closing it requires adding a harness-contract test layer, not adding more unit tests" to "Closing this gap requires adding a harness-contract test layer, not just adding more unit tests". Affected: `README.md`.

### Added
- **2026-05-04 00:38** `CLAUDE.md` repo-level guide for AI assistants (Claude Code and similar). Documents project shape, the v0.9.0-rc.2 known-defects status, the compile / hook-contract / threat-model / test-layer architecture, build-and-test commands (with the CI ordering rationale), the compiled-artifact placeholder-home convention, and the ten-place version surface. Composes via `@CONTRIBUTING.md` and `@OWNERS.md` imports rather than duplicating their content. Affected: `CLAUDE.md` (new).

### Fixed
- **2026-05-04 01:03** Addressed four follow-up review findings on the public-facing docs. Removed an unsupported `${KUBE}` token from the path-token list in `CLAUDE.md` (only `${HOME}`, `${SSH}`, `${AWS}`, `${TMP}`, `${KEYS}` are expanded by `packages/core/src/path-tokens.ts`). Corrected the hook-manifest field name in `CLAUDE.md` from `timeout` to `timeout_ms` to match `packages/core/src/types.ts`. Added a docs-verification gate to `.github/workflows/ci.yml` that runs `pnpm gen:docs` and fails on a dirty worktree, backing the existing CONTRIBUTING.md and CLAUDE.md claim that "CI fails on stale generated docs" with an actual gate. Caveated the README's Channel 2 npm-install path as not yet functional in rc.2 (the published `@bitsummit/claude-code-security` umbrella ships only `package.json` and `README.md`, omitting the `ccsec` binary; the packaging fix lands in rc.3). Affected: `CLAUDE.md`, `README.md`, `.github/workflows/ci.yml`.
- **2026-05-03 23:58** Aligned project version across the workspace. The README, `packages/meta/package.json`, `packages/plugin/package.json`, and `packages/plugin/.claude-plugin/plugin.json` already reported `0.9.0-rc.2`, but seven other surfaces still reported `0.1.0-alpha.0`: `package.json` (root), `packages/core/package.json`, `packages/hooks/package.json`, `packages/cli/package.json`, `packages/settings/package.json`, `packages/rules/package.json`, and the two compiled-in CLI constants `PKG_VERSION` (`packages/cli/src/index.ts`) and `VERSION` (`packages/cli/src/commands/apply.ts`), plus the `ccsec_version` field in `packages/settings/base.json`. The user-visible consequence was that `node packages/cli/bin/ccsec.js --version` printed `0.1.0-alpha.0` and the `ccsec_version` field written into `~/.claude/settings.json` and `.ccsec-lock.json` was wrong by eight minor versions. Bumped all ten surfaces to `0.9.0-rc.2`. Regenerated `packages/settings/compiled/{baseline,strict,regulated}.json` and the vitest snapshot at `packages/settings/__snapshots__/snapshot.test.ts.snap` to reflect the corrected `ccsec_version`. 313/313 tests pass. Affected: `package.json`, `packages/cli/package.json`, `packages/cli/src/commands/apply.ts`, `packages/cli/src/index.ts`, `packages/core/package.json`, `packages/hooks/package.json`, `packages/rules/package.json`, `packages/settings/__snapshots__/snapshot.test.ts.snap`, `packages/settings/base.json`, `packages/settings/compiled/baseline.json`, `packages/settings/compiled/regulated.json`, `packages/settings/compiled/strict.json`, `packages/settings/package.json`.

### Security
- **2026-05-03** README disclosure for `v0.9.0-rc.2`. Added a top-of-file "Status disclosure" callout and a new `## Known defects in v0.9.0-rc.2` section enumerating four functional defects identified in live testing on Ubuntu 24.04 with Claude Code 2.1.123: (1) hooks do not fire because the compiler emits `{name}` shape and the harness requires `{matcher, hooks:[{type, command}]}`; (2) audit log is not written from production sessions because the CLI registers no `run-hook` subcommand; (3) all `permissions.deny` entries are dropped on session load because the compiler emits objects and the harness requires plain strings (deny-layer coverage of T-001 through T-018 is 0/18); (4) WebFetch deny patterns are skipped because the harness rejects glob form and requires `domain:` prefix. Each defect is sourced to specific files and line numbers (`compiler.ts:15` and `:111-113`, `apply.ts:42`, `index.ts`, `network-egress.json:4-7`). Added a net-runtime-effect statement: hook-layer enforcement is 0/26, deny-layer enforcement is 0/18, audit log is empty. Added subsections explaining why the 313-test suite did not catch the defects (no test layer exercises the contract between the emitted `~/.claude/settings.json` and the Claude Code harness that consumes it), the remediation plan (rc.3 fixes plus a harness-contract test gate in CI), how to evaluate the project today (reference material yes, runtime install no), and an acknowledgement of the external reviewer who reported the defects (named in the rc.3 release notes with permission). Updated badges: threat coverage `18/18` corrected to `14/18 mapped` to match `docs/coverage-matrix.md` ground truth; added `DO NOT DEPLOY rc.2` status badge; version badge marked `defects pending fix`; hooks badge marked `delivery layer broken`. Retired the prior "Plans 1-9 shipped, feature-complete and infrastructure-complete" framing until rc.3 ships green. Added an install-time warning, a "What's protected" caveat clarifying the list describes design intent rather than rc.2 runtime behavior, and a note that `docs/hooks/*.md` Behavior and Notes sections are TODO placeholders pending rc.3. Updated v1.0.0 path to gate on rc.3 first. Disclosed that the npm package name `@bitsummit/claude-code-security` predates the project rename and is pending alignment for `v1.0.0`. Softened the Profile Chooser claim that `ccsec doctor` "verifies the result" to clarify that `doctor` checks file integrity, not Claude Code harness acceptance. Cleaned an `ETA 6 -` token-truncation typo in the Channel 1 plugin install heading. Affected: `README.md`.

### Changed
- **2026-04-29 14:42** Redacted real prospect / client names from all public docs. Replaced specific organization names with anonymized candidate profiles (regulated municipal / law-enforcement Windows-heavy; regulated forensics / public-safety mixed-fleet; federally-regulated Mac-heavy research org). Specific candidate names are now tracked privately by the maintainer. Affected: `docs/pilot-validation.md`, `docs/v1.0.0-readiness.md`, `docs/external-security-review-rfp.md`, `docs/superpowers/plans/2026-04-29-phase1-plan10-pilot-validation.md`, `docs/superpowers/specs/2026-04-29-plan10-pilot-validation.md`, `docs/superpowers/specs/2026-04-29-claude-code-security-repo-design.md`, and the prior `[0.9.0-rc.2]` Added entry.
- **2026-04-30 10:08** OSS-framing pass: pilot runbook, pilot agreement template, pilot final-report signature line, RFP intro and submission line, and v1.0.0-readiness pilot definition rephrased so external adopters can run them, not only BITSUMMIT-led pilots. Added `docs/superpowers/README.md` marking that directory as the maintainer's build journal (kept for transparency, not load-bearing for adoption). Affected: `docs/pilot-validation.md`, `docs/v1.0.0-readiness.md`, `docs/pilot-templates/agreement.md`, `docs/pilot-templates/final-report.md`, `docs/external-security-review-rfp.md`, `docs/superpowers/README.md` (new).
- **2026-04-30 10:21** Repo-rename followups: replaced four lingering `cd claude-code-security` lines with `cd claude-code-governance` to match the renamed GitHub repo. Genericized `docs/superpowers/` planning artifacts to remove BITSUMMIT-internal voice and personal home-directory paths; technical/architectural content preserved. Remaining BITSUMMIT mentions in that directory are limited to locked branding (plugin name, publisher, LICENSE copyright). Affected: `README.md`, `docs/deployment/mdm-jamf.md`, `installers/linux/README.md`, `installers/windows/README.md`, and 13 files under `docs/superpowers/plans/` and `docs/superpowers/specs/`.
- **2026-04-30 14:07** Fixed CI failure that had been firing on every push since at least 2026-04-29. Two issues: (1) `package.json` `build` script used `pnpm -r --parallel build`, which ignores the workspace dependency graph - `packages/cli` and `packages/hooks` build in parallel with `packages/core` and cannot resolve `@bitsummit/ccsec-core`'s `dist/index.d.ts`. Removed `--parallel`. (2) `.github/workflows/ci.yml` ran `pnpm typecheck` before `pnpm build`, but typecheck depends on the cross-package `dist/*.d.ts` files. Swapped order to `lint -> build -> typecheck -> test`. Verified locally with a clean state: 313 tests pass, typecheck clean, lint clean, all four bats tests pass.
- **2026-04-30 14:01** Filled five structural OSS-doc gaps surfaced by the post-reframe audit. Added `CONTRIBUTING.md` (PR workflow, dev setup, em-dash rule, no-Claude-footer rule, hook-adding procedure, threat-adding procedure). Added `OWNERS.md` (current maintainer, contact channels, decision rights, response-time expectations, path to maintainer status). Added per-package `README.md` for `packages/core`, `packages/hooks`, `packages/cli`, `packages/rules`, `packages/settings` (matching the pattern from `packages/meta/README.md`). Added `installers/macos/README.md` documenting per-user and fleet-managed install paths, mirroring the structure of `installers/windows/README.md` and `installers/linux/README.md`. Extended `scripts/gen-coverage-matrix.mjs` to emit a "Threat to test map" section in `docs/coverage-matrix.md` (each hook now linked to its companion `<name>.test.ts` with rough test-case count); regenerated. Updated `README.md` "Documentation tracks" Track 1 to surface CONTRIBUTING.md and OWNERS.md, and Track 2 to surface the new macOS installer README.
- **2026-04-30 13:36** Three follow-up fixes from the post-reframe audit: (1) dropped "and external security review" from the README status banner on line 9, the last place still naming the removed v1.0.0 gate; (2) bumped `packages/plugin/.claude-plugin/plugin.json` from `0.6.0-beta.0` to `0.9.0-rc.2` (was three minor versions stale); (3) bumped `packages/plugin/package.json` and `packages/meta/package.json` from `0.9.0-rc.1` to `0.9.0-rc.2` to match the README badge and the most-recent tag.
- **2026-04-30 12:53** Reframed the security review document and dropped the v1.0.0 third-party-audit gate. Renamed `docs/external-security-review-rfp.md` to `docs/bitsummit-security-engagement.md` and rewrote it as a paid services engagement template adopters use to engage BITSUMMIT for extended security governance (custom-profile compilation, SIEM integration, compliance-regime mapping, training). Removed the named firm list (Trail of Bits, NCC Group, etc.) and the third-party-audit Q&A. Dropped the "External security review" item from `docs/v1.0.0-readiness.md`'s required-for-v1.0.0 list (renumbered remaining items 2-6) and from the matching v1.0.0-path section in `README.md`. Updated `docs/pilot-validation.md` to remove the external-review checklist item and reframe the external-review section as extended security governance. Updated `docs/superpowers/specs/2026-04-29-plan10-pilot-validation.md`, `docs/superpowers/plans/2026-04-29-phase1-plan10-pilot-validation.md`, and `docs/superpowers/README.md` to point at the new engagement template. Adopters who want an independent third-party audit commission one through their own procurement; BITSUMMIT does not bundle one into the project's `v1.0.0` release.

## [0.9.0-rc.2] - 2026-04-29

This is a **release candidate**. Plans 1-9 of 10 are shipped; Plan 10 (pilot validation) is user-action and gates `v1.0.0`.

### Added
- `docs/pilot-validation.md`: canonical pilot runbook covering candidate-client profiles (specific names tracked privately by the maintainer), pilot criteria, four-phase rollout (kickoff / rollout / hardening / signoff), v1.0.0 readiness checklist, friction-log template inline, and internal incident drill template inline.
- `docs/external-security-review-rfp.md`: Request-for-Proposal template the maintainer sends to outside security firms. Includes scope (in / out), deliverables, timeline, budget guidance, and a 10-question engagement Q&A template. (Replaced in `[Unreleased]` with `docs/bitsummit-security-engagement.md`.)
- `docs/pilot-templates/agreement.md`: pilot agreement template with explicit `[FILL]` markers and counsel-disclaimer.
- `docs/pilot-templates/friction-log.md`: running friction-log template with severity definitions (P0 / P1 / P2), status values, weekly check-in summaries, and v1.0.0 aggregate gating logic.
- `docs/pilot-templates/incident-drill.md`: five-drill simulated bypass-attempt template (T-001 secret leak, T-005 destructive FS, T-007 egress, T-008 pipe-to-shell, T-014 MDM bypass) with pass criteria and post-drill checklist.
- `docs/pilot-templates/final-report.md`: pilot signoff template with phase completion table, friction summary, drill results, audit log integrity attestation, recommendations to maintainer, and signature block.
- `docs/v1.0.0-readiness.md`: single-page summary of remaining user-action items before `v1.0.0`. Lists required items (pilot signoff, security review, PGP key, npm token, Apple cert, CHANGELOG entry, plugin marketplace listing) and optional items (Windows EV cert, OpenSSF Scorecard, public case study). (The "security review" required item was dropped in `[Unreleased]`; only the pilot, signing secrets, CHANGELOG, and plugin marketplace items remain v1.0.0 gates.)
- `docs/superpowers/specs/2026-04-29-plan10-pilot-validation.md` and `docs/superpowers/plans/2026-04-29-phase1-plan10-pilot-validation.md`.

### Changed
- `README.md`: status banner updated to reflect Plans 1-9 shipped and Plan 10 as user-action; added "v1.0.0 path" section near the top linking the three pilot / review / readiness docs; version badge bumped to `0.9.0-rc.2`; OpenSSF Scorecard placeholder updated to "pending v1.0.0". (In `[Unreleased]` the "v1.0.0 path" section was reduced from three items to two: review was dropped and the engagement template was added as a separate adopter pointer.)

### Notes
- 313 tests passing (unchanged from `v0.9.0-rc.1`; Plan 10 ships docs only, not code).
- `v1.0.0` is **not** tagged in this release. `v1.0.0` is the maintainer's call after pilot signoff and external security review report are filed. (The external security review requirement was dropped in `[Unreleased]`; `v1.0.0` now ships on pilot signoff plus signing-secret provisioning. Adopters who want extended security governance engage BITSUMMIT separately via `docs/bitsummit-security-engagement.md`.)
- Plan 10 is the final plan in Phase 1 of the project. All Plan 1-9 deliverables are shipped; the project is feature-complete and infrastructure-complete.

## [0.9.0-rc.1] - 2026-04-29

This is a **release candidate**. Only Plan 10 (pilot validation) remains before `v1.0.0`.

This release ships the release-engineering substrate: SBOM, GHSA pipeline scaffolding, Node SEA binary build templates, provenance, and the canonical release runbook. Actual signature production (PGP, Apple Developer ID, Authenticode) is gated on maintainer-provisioned secrets and is wired as drop-in steps in `docs/release-engineering.md`.

### Added
- `.github/workflows/release.yml` job `publish` now runs `npx @cyclonedx/cyclonedx-npm@2` after the npm publish step and attaches `sbom.cyclonedx.json` as a release asset.
- `.github/workflows/release.yml` job `sea-build`: matrix build (`macos-14`, `macos-13`, `ubuntu-latest`, `windows-latest`) producing Node Single-Executable Application binaries `ccsec-{macos-arm64, macos-x64, linux-x64, windows-x64}` via `scripts/build-sea.sh` (esbuild bundle, SEA blob, postject inject).
- `.github/workflows/release.yml` job `release-manifest`: downloads SEA artifacts, generates `SHA256SUMS`, attaches binaries + manifest to the GitHub release. PGP-signing the manifest is wired as a documented future step in `docs/release-engineering.md` and a TODO comment in the workflow.
- `scripts/build-sea.sh`: cross-platform SEA build script (macOS arm64/x64, Linux x64, Windows x64) using `esbuild@0.20` for bundling and `postject@1` for blob injection. Auto-detects target if not supplied; handles macOS codesign-removal pre-postject.
- `docs/release-engineering.md`: canonical release runbook covering pre-release gates, version + tag, the three CI jobs, signing slots (PGP, Apple Developer ID + notarize, Windows Authenticode), the secrets the maintainer must provision, post-release verification, the security-advisory pipeline (GHSA private fork -> coordinated disclosure -> publish), and backports across `release/v1.x`.
- `.github/security-advisory-template.md`: template for new GitHub Security Advisories. Reporter sections + maintainer sections clearly delineated; includes CVSS 4.0 placeholder, threat ID linkage to `docs/threat-model.md`, and disclosure-timeline grid.
- `.github/SECURITY.yml`: minimal GHSA configuration pointing at `SECURITY.md` and the advisory template, with `bit-haseebminhas` as default reviewer.
- `docs/superpowers/specs/2026-04-29-plan9-release-engineering.md` and `docs/superpowers/plans/2026-04-29-phase1-plan9-release-engineering.md`.

### Changed
- `SECURITY.md`: added explicit Disclosure Timeline section (ack 72h, fix-or-roadmap HIGH 14d / MEDIUM 30d, default 90-day disclosure window, CRITICAL collapse-to-fastest); added GHSA URL as preferred reporting channel; added Hall of Thanks placeholder section; added PGP Key placeholder section pointing at the runbook for generation procedure; expanded scope statement to enumerate shipped binaries; clarified the SemVer security carve-out.
- `.github/workflows/release.yml` `permissions.contents` raised from `read` to `write` so `softprops/action-gh-release@v2` can attach assets.

### Notes
- 313 tests passing; coverage above 90 percent. No new tests (Plan 9 ships CI infrastructure, not new hook code).
- Actual signature production requires maintainer-provisioned secrets: `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `APPLE_CERT_P12`, `APPLE_CERT_PASSWORD`, `APPLE_TEAM_ID`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `WINDOWS_CERT_PFX`, `WINDOWS_CERT_PASSWORD`. The runbook documents how to provision each.
- `npm publish --provenance` was already wired in Plan 6 (`v0.6.0-beta.0`); SLSA Level 3 attestation is automatic when `id-token: write` is set, which it is.
- Plan 10 (pilot validation) is the final step before `v1.0.0`.

## [0.8.0-rc.0] - 2026-04-29

This is a **release candidate**. Only Plan 9 (release engineering: signed releases, SBOM, GHSA workflow, OpenSSF Scorecard) and Plan 10 (pilot validation) remain before `v1.0.0`.

### Added
- `scripts/gen-hook-docs.mjs` and `scripts/gen-coverage-matrix.mjs`: Node ESM auto-generators that walk `packages/hooks/src/*/index.ts`, dynamically import each compiled hook from `dist/`, read its manifest, and emit `docs/hooks/<name>.md` (one page per hook, 26 total) and `docs/coverage-matrix.md` (threat-to-hook map plus per-event tables and summary stats).
- `pnpm gen:hook-docs`, `pnpm gen:coverage-matrix`, `pnpm gen:docs` workspace scripts.
- `docs/hooks/<name>.md` for all 26 hooks: manifest table (event, matchers, threat, profiles, severity, timeout), threat link to `docs/threat-model.md`, behavior + notes blocks (sourced from `// DOC:` and `// NOTES:` comment blocks in the hook source or left as TODO for hand-curation).
- `docs/known-bypasses.md`: documented detection gaps with vector / detection status / recommended response. Eight bypasses covered: `disableAllHooks` (issue #26637), cross-process audit log fork, bash escape-handling in `maskQuotedRegions`, heredoc bodies, pipe-to-interpreter, obfuscated git via aliases, filesystem hardlinks / bind mounts, and `bash <<<$(curl)` combo.
- `docs/adr/0005-rules-package-decision.md`: why `@bitsummit/ccsec-rules` ships markdown templates rather than executable rule code.
- `docs/adr/0006-mdm-deployment-decision.md`: why we chose Jamf Configuration Profile + companion script for `managed-settings.json` deployment, and why we ship per-OS path templates rather than auto-detecting.
- `docs/settings-reference.md`: schema-of-record for every settings.json key the project uses, including `schema`, `ccsec_version`, `audit.log_path`, `audit.egress_allowlist`, `audit.verify_on_session_start`, `permissions.deny[].pattern`, `permissions.deny[].threat`, `permissions.allow[]`, `hooks.<event>[].name`, plus the path-token table per OS.
- `installers/windows/README.md`: substantive Intune deployment guide (~150 lines) covering Win32 app packaging, the v1.1 `install-managed.ps1` / `verify-managed.ps1` templates, NTFS ACL hardening, sha256 manifest, and Intune Compliance scheduling. Templates pending v1.1.
- `installers/linux/README.md`: substantive Linux deployment guide (~150 lines) covering shell installer template, Ansible role template, `.deb` / `.rpm` packaging, `chattr +i` immutability, sha256 manifest, and systemd timer / cron scheduling. Templates pending v1.2.

### Changed
- `README.md`: moved from "Plan 7 of 10" to "Plan 8 of 10"; added release-candidate banner; added badges (MIT license, version, hook count, threat coverage, OpenSSF Scorecard placeholder); added Table of Contents linking Track 1-5 sections; added "What's protected / What's not" honesty box.
- `docs/coverage-matrix.md`: replaced the hand-maintained Plan 1-5 version with the auto-generated artifact from `gen-coverage-matrix.mjs`. The new matrix groups by threat ID, includes per-event tables, and emits summary stats (26 hooks, 14 distinct threats, 4 events).
- Stub READMEs at `installers/windows/README.md` and `installers/linux/README.md` replaced with full deployment guides.

### Notes
- 313 tests passing; coverage above 90 percent.
- The `// DOC:` / `// NOTES:` source-comment convention is established but not yet populated; per-hook hand-curation is a follow-up. Each generated page falls back to a TODO line when the comments are absent, and the auto-generator's footer makes the regeneration command discoverable.
- Plan 9 (release engineering) will add CI gates that fail on doc drift, sign release artifacts, emit SBOM, and stand up the GHSA + OpenSSF Scorecard workflow.
- Plan 10 (pilot validation) is the final step before `v1.0.0`.

## [0.7.0-beta.0] - 2026-04-29

### Added
- `installers/macos/jamf/com.bitsummit.claude-code-security.mobileconfig.xml`: Jamf Configuration Profile template (Custom Settings payload) for fleet deployment of `managed-settings.json`.
- `installers/macos/jamf/README.md`: admin workflow for importing the profile, scoping a smart group, populating the base64 payload, and running verification.
- `installers/macos/install-managed.sh`: sudo-only installer that compiles the chosen profile and writes `/Library/Application Support/ClaudeCode/managed-settings.json` as `root:wheel`, mode `0644`, with `chflags uchg` immutability and a `.ccsec-manifest` recording sha256.
- `installers/macos/verify-managed.sh`: tamper-detection verifier. Re-hashes the deployed file, compares against the manifest, warns if the immutable flag is missing. Exit code 2 on mismatch.
- `docs/deployment/mdm-jamf.md`: end-to-end IT-admin deployment guide covering compile, profile import, scoping, verification, periodic compliance checks, and tamper response.

### Changed
- README install section now references the Jamf profile template + deployment guide as the path for MDM admins.

### Notes
- `install-managed.sh` and `verify-managed.sh` require sudo and the `/Library/Application Support` system path; they are intentionally NOT exercised by the bats suite (which runs unprivileged). The bats suite continues to cover the per-user installer (`install.sh` + `verify.sh`).
- Intune / Workspace ONE / Kandji equivalents are out of scope; tracked for a future plan.
- Signed releases / SBOM / GHSA workflow still tracked for Plan 9.

## [0.6.0-beta.0] - 2026-04-29

### Added
- `packages/plugin/` Claude Code plugin manifest with `/ccsec` slash command (marketplace listing: BITSUMMIT Hardening).
- `packages/meta/` umbrella package `@bitsummit/claude-code-security` aggregating all sub-packages.
- `.github/workflows/release.yml` publishing all packages to npm on tag push (skipped if NPM_TOKEN absent).
- README install instructions for all 3 distribution channels + profile chooser table.

### Changed
- `ccsec apply` gains `--force` flag (override user-modification guard).
- `ccsec apply` gains `--rules` flag (install CLAUDE.md template from `@bitsummit/ccsec-rules` for the chosen profile if no CLAUDE.md exists).
- `ccsec apply` gains `--no-rules` flag (explicit opt-out, since some users may have pre-existing CLAUDE.md they want to preserve unchanged).

### Notes
- Actual npm publish requires NPM_TOKEN repository secret; the workflow tolerates absence and the user provisions on their schedule.
- Plugin marketplace listing submission is an Anthropic-side action, not in scope for this plan.
- Jamf / managed-settings.json deployment still tracked for Plan 7.

## [0.5.0-beta.0] - 2026-04-29

### Added
- 8 new hooks: `behavioral-rule-enforcer`, `claude-md-validator`, `untrusted-content-tagger`, `disable-all-hooks-detector`, `local-settings-precedence-checker`, `subagent-spawn-guard`, `task-tool-input-guard`, `agent-allowlist-enforcer`. Hook surface complete (26 hooks total).
- New `@bitsummit/ccsec-rules` package with CLAUDE.md hardening templates per profile (baseline, strict, regulated) plus reusable snippets (no-eval, no-curl-pipe-shell, no-force-push).
- New overlays: `overlays/behavioral.json`, `overlays/mdm-bypass.json`, `overlays/agent-gating.json`.
- Integration transcripts: behavioral-bypass-attempt, mdm-bypass-attempt, subagent-escape-attempt, regulated-profile-end-to-end.
- Threat model entries: T-010 Prompt Injection from Tool Output, T-011 Subagent Escape, T-012 MDM Bypass via disableAllHooks (passive per ADR-0003), T-013 Local Settings Overriding Managed.

### Changed
- **Strict and regulated profiles now differentiated for real** (Plans 1-4 shipped them as identical-content shells). Strict adds tighter egress allowlist (4 hosts) plus the agent-gating overlay; regulated adds the tightest egress (2 hosts) plus the mdm-bypass overlay.
- Settings compiler deep-merges top-level objects from extends fragments and applies sub-key overrides from `profile.overrides`. This lets `audit.log_path` (base) and `audit.egress_allowlist` (network-egress overlay) and `audit.verify_on_session_start` (audit overlay) coexist, while strict/regulated tighten only `egress_allowlist`.
- Threat ID cleanup: `submodule-injection-guard` renamed to `T-018-supply-chain-submodule` (was `T-005` in Plan 3, then `T-013` in Plan 4). T-013 is now reserved for local settings precedence.
- Project version moves from `alpha` to `beta`. Hook surface is feature-complete; remaining plans are distribution (Plan 6), Jamf integration (Plan 7), full docs (Plan 8), release engineering (Plan 9), pilot validation (Plan 10).

### Notes
- Plugin / npm distribution still tracked for Plan 6.
- Jamf / managed-settings.json deployment still tracked for Plan 7.
- Signed releases / SBOM / GHSA workflow still tracked for Plan 9 (T-018 distribution-side coverage).

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
