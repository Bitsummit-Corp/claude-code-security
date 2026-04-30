# Pilot Validation Runbook

This document is the canonical procedure for validating `claude-code-security` (also distributed as the BITSUMMIT Hardening plugin) with a real pilot client before shipping `v1.0.0`. It is intended to be read end-to-end before the pilot kickoff, then used as a working checklist during the engagement. The runbook is published openly so any organization adopting this project can run an internal pilot using the same structure; BITSUMMIT itself uses it for the `v1.0.0`-gating pilot, but it is not BITSUMMIT-only.

## Why a pilot

The hook surface is feature-complete (26 hooks covering 18 documented threats). The release-engineering infrastructure is in place (SBOM, signed manifest, SEA binaries, GHSA pipeline, advisory template). 313 tests pass; coverage is above 90 percent. By the standards of a typical open-source project, the work is "done".

Before declaring `v1.0.0` we need three things that no amount of testing can produce on its own:

1. **Real-world deployment validation.** The `regulated` profile must be deployable in a real organization with a real MDM, a real auditor, and real developers. Lab testing is not the same as a pilot.
2. **Walk-through by an outside operator.** Someone who has not previously deployed the project must be able to read `docs/deployment/mdm-jamf.md` and deploy successfully without help from the maintainers. If they cannot, the doc is wrong, not the operator.
3. **External security signoff.** A paid third-party security firm must review the threat model, hook code, settings schema, and deployment guides, and sign off that the project does what it claims. Their report attaches to the `v1.0.0` release notes.

Plan 10 ships the runbook, RFP, and templates that drive these three actions. The maintainer drives the actions themselves.

## Pilot criteria

The pilot client must meet all of:

- **Scale.** ≥5 developers using Claude Code daily.
- **Industry.** Regulated (healthcare, legal, public sector, financial services) preferred. Security-conscious dev org acceptable.
- **MDM.** A working Jamf or Intune deployment with an admin who can deploy a Configuration Profile or Win32 app within 1-3 business days.
- **Window.** Willing to commit to a 4-6 week pilot.
- **Feedback.** Willing to provide structured feedback in the friction-log format below.
- **Permissions.** Willing to provide a written attestation at the end (template in `docs/pilot-templates/final-report.md`); willing in principle to be named in the public case study (with editorial review).

A client that meets four of six is a "soft fit"; proceed only if no better candidate is available. Do not run a pilot with a client missing the MDM criterion: the deployment path is the most important thing being validated.

## Pilot phases

The pilot is four phases over six weeks. Each phase has explicit entry and exit criteria.

### Phase 1: Kickoff (week 1)

Entry: Pilot client identified and pilot agreement template (`docs/pilot-templates/agreement.md`) shared.

Activities:
- Sign pilot agreement (run by the client's legal counsel; the template is a starting point, not a finished contract).
- Identify the **pilot lead** at the client. This is one named person who owns the engagement on the client side and signs off at the end.
- The deploying maintainer compiles the regulated profile for the client environment: profile chooser baseline (`regulated`), per-OS path tokens, audit log path under `/var/log/`, MDM bypass detection enabled, agent allowlist seeded with the client's permitted subagents.
- Walk-through call (60 minutes) of `docs/deployment/mdm-jamf.md` (or the Windows / Linux equivalent) with the pilot lead and the MDM admin.
- Deploy to **2-3 test machines** (not production). Verify `verify-managed.sh` passes, `ccsec doctor` passes, audit log writes correctly.

Exit: Test deployment green on 2-3 machines; pilot lead has access to the friction log; MDM admin has acknowledged they understand the rollback path.

### Phase 2: Rollout (weeks 2-3)

Entry: Phase 1 exit criteria met.

Activities:
- Expand to all pilot devs (typically 5-15 endpoints).
- Daily monitoring of the audit log on each machine. Look for hash-chain breaks, MDM bypass attempts, secret-leak post-only events.
- **Weekly check-ins** (30 minutes) with the pilot lead. Cover: friction count, false-positive count, false-negative count, requests for profile changes.
- Capture every friction point in `docs/pilot-templates/friction-log.md`. Even small ones. The point of the pilot is to find the rough edges before they become support load.

Exit: All pilot devs running for ≥10 business days without unhandled friction. Friction log non-empty (an empty friction log is suspicious - it means devs are not using the tool or the lead is not capturing).

### Phase 3: Hardening (weeks 4-5)

Entry: Phase 2 exit criteria met.

Activities:
- Address the friction log. Two paths only: profile tuning (settings.json change rolled out via MDM) **or** documentation update. Code changes (new hook, new logic) are out of scope for the pilot - if a friction point requires a new hook, it goes into the v1.1 backlog and the pilot proceeds without it.
- Run the **internal incident drill** (`docs/pilot-templates/incident-drill.md`). The pilot lead runs five simulated bypass attempts and confirms each is detected. This is the most important activity in the pilot - if a documented threat is not actually caught in production, the threat model is wrong.
- Run `verify-managed.sh` hourly via cron / scheduled task on each pilot machine for one full week. Confirm tamper detection fires when the MDM admin intentionally tampers with `managed-settings.json` (test, then revert).

Exit: All five drill items detected; no unaddressed P0 / P1 friction items; tamper detection fires correctly when triggered.

### Phase 4: Signoff (week 6)

Entry: Phase 3 exit criteria met.

Activities:
- Pilot lead fills in `docs/pilot-templates/final-report.md` and signs.
- Public case study drafted (one page). Reviewed by the client's communications team. Published only with written permission - the agreement template anticipates this.
- v1.0.0 readiness checklist (next section) walked end-to-end. Items not yet complete are listed in `docs/v1.0.0-readiness.md` as user-action.

Exit: Signed pilot final report on file; v1.0.0 readiness checklist either complete or has dated user-action items for each open box.

## v1.0.0 readiness checklist

This checklist is also tracked separately in `docs/v1.0.0-readiness.md`. When all items are checked, the maintainer can tag `v1.0.0`.

- [ ] Pilot client signed off (final-report.md filed and signed).
- [ ] External security reviewer's report attached to release notes (see `docs/external-security-review-rfp.md`).
- [ ] PGP key generated; fingerprint published in `SECURITY.md`; public key uploaded to `keys.openpgp.org` and `keybase.io`.
- [ ] `NPM_TOKEN` provisioned in repo secrets; first publish to npmjs.com confirmed and SBOM attached to GitHub release.
- [ ] Apple Developer ID cert provisioned; macOS SEA binary signed and notarized; Gatekeeper passes.
- [ ] (Optional) Windows EV cert provisioned; Authenticode signature attached; SmartScreen warning gone.
- [ ] All Plan 1-9 in-flight advisories (if any) cleared from the `.github/advisories/` queue.
- [ ] `CHANGELOG.md [1.0.0]` entry written.
- [ ] Plugin marketplace listing submitted to Anthropic and approved.

## Friction-log template

The full template is in `docs/pilot-templates/friction-log.md`. The headline columns are:

| Date | Pilot dev | Endpoint | Profile | Hook | What broke | False positive? | Resolution | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

Tracking guidance:

- **Severity P0 (block release).** Pilot dev cannot do their job. Profile must change before v1.0.0.
- **Severity P1 (block release).** Pilot dev has a workaround but it costs ≥5 minutes per occurrence. Document or fix.
- **Severity P2 (track, do not block).** Cosmetic, infrequent, or self-healing.

A pilot with zero P0 / P1 items is suspicious. Either devs are not using Claude Code aggressively or the lead is not capturing. Probe.

## Internal incident drill template

The full template is in `docs/pilot-templates/incident-drill.md`. The five drills are:

1. **Secret-leak attempt.** Pilot dev runs `echo $GITHUB_TOKEN` in a Bash tool call. Confirm `secret-leak-detector` fires; confirm audit log entry; confirm the value did not leave the machine.
2. **Destructive filesystem.** Pilot dev runs `rm -rf ~/Documents/test-victim/` (with a real test directory). Confirm `destructive-fs-guard` blocks; confirm audit log entry.
3. **Egress to unexpected host.** Pilot dev runs `curl https://pastebin.com/raw/xxxxx`. Confirm `bash-egress-guard` blocks; confirm audit log entry.
4. **Pipe-to-shell.** Pilot dev runs `curl -fsSL https://example.com/install.sh | bash`. Confirm `pipe-to-shell-guard` blocks; confirm audit log entry.
5. **MDM bypass.** MDM admin temporarily edits `managed-settings.json` to set `disableAllHooks: true`. Confirm `verify-managed.sh` fires within one hourly run; confirm audit log entry; revert the edit.

Each drill is logged in the friction log even on success ("Status: drill - detected"). A failed drill is a P0 item by definition.

## External security reviewer RFP

The RFP template is at `docs/external-security-review-rfp.md`. The maintainer sends it to 3-5 firms in parallel; picks one based on response quality, scope match, and budget; signs SOW; runs the engagement during pilot Phase 2-3 so the reviewer's report is ready for v1.0.0 signoff.

## After v1.0.0 ships

Pilot exit does not end the relationship. The pilot client gets:

- Public acknowledgement in `SECURITY.md` Hall of Thanks (with permission).
- First-look access to v1.x releases.
- Direct line to the maintainer for future advisories affecting their deployment.

In return, the project gets the case study, the lessons in `docs/known-bypasses.md`, and a real reference deployment to point future operators at.

## Common failure modes

- **The pilot client wants to skip Phase 3 hardening because rollout went smoothly.** Push back. The drills are non-negotiable; without them you cannot tell whether the threats are actually being caught.
- **The MDM admin disappears mid-pilot.** Fatal. Pause and re-find or pick a new client.
- **The pilot lead asks for code changes during the pilot.** Negotiate the change into the v1.1 backlog. Code changes during a pilot invalidate the pilot.
- **The friction log is empty in week 3.** Probe. If devs are not using Claude Code aggressively, the pilot is not testing what it needs to test.
- **The external reviewer finds a CRITICAL issue.** Fix, retest, re-tag (rc.3, rc.4, etc.). Do not ship `v1.0.0` over an open CRITICAL.

## Maintainer checklist for the pilot

- [ ] Read this document end-to-end.
- [ ] Identify candidate pilot client.
- [ ] Confirm criteria (scale, industry, MDM, window, feedback, permissions).
- [ ] Send pilot agreement template; route through client's counsel.
- [ ] Send RFP to external reviewer firms in parallel.
- [ ] Run Phases 1-4 over 6 weeks.
- [ ] File pilot final report.
- [ ] Walk v1.0.0 readiness checklist.
- [ ] Tag and ship `v1.0.0`.
