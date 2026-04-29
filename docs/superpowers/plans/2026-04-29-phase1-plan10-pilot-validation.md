# Plan - Phase 1, Plan 10 - Pilot Validation

> Date: 2026-04-29. Final plan of Phase 1. Predecessor: `v0.9.0-rc.1`.

## Documentation-only plan

This plan is **documentation-only**. It cannot be fully shipped autonomously because:

1. Pilot validation requires a real BITSUMMIT customer engagement (multi-week, on real fleets, with humans).
2. External security review requires hiring a paid security firm.

What Claude Code ships here is the runbook + RFP template + pilot templates + readiness checklist. The maintainer ships `v1.0.0` after the user-action items in `docs/v1.0.0-readiness.md` complete.

## Steps

### 1. Specs + plan

- `docs/superpowers/specs/2026-04-29-plan10-pilot-validation.md` (companion spec).
- `docs/superpowers/plans/2026-04-29-phase1-plan10-pilot-validation.md` (this file).

### 2. Pilot runbook

`docs/pilot-validation.md`:

- Why a pilot (real-world deployment validation; non-BITSUMMIT walks the MDM doc; external security signoff).
- Candidate pilot clients (a regulated municipal agency, a regional law-enforcement service, a federally-regulated research organization, plus opportunistic).
- Pilot criteria (≥5 devs, regulated industry preferred, MDM admin available, 4-6 week window, structured feedback).
- Four-phase rollout (kickoff, rollout, hardening, signoff) with weekly checkpoints.
- v1.0.0 readiness checklist.
- Friction-log template inline.
- Internal incident drill template inline.
- Pointer to the external security review RFP.

### 3. External security review RFP

`docs/external-security-review-rfp.md`:

- Project overview.
- Scope (threat model, hook code, settings, deployment guides).
- Out of scope (Claude Code itself, OS-level security, third-party hooks).
- Deliverables (written report, severity-ranked findings, retest after fixes).
- Timeline (4-6 weeks).
- Budget guidance ($15-30K, non-authoritative).
- Candidate firms (Trail of Bits, NCC Group, Doyensec, Cure53, Atredis, Include Security; user picks).
- Engagement Q&A template the firm fills out before signing.

### 4. Pilot templates

`docs/pilot-templates/`:

- `agreement.md`: pilot agreement template + counsel disclaimer.
- `friction-log.md`: running friction log table.
- `incident-drill.md`: 5 simulated bypass attempts the pilot lead runs.
- `final-report.md`: pilot signoff template.

### 5. README updates

- Status banner: "Plan 9 of 10 shipped (`v0.9.0-rc.2`). Plan 10 is user-action: pilot validation. v1.0.0 ships when the maintainer completes Plan 10."
- "v1.0.0 path" section near the top, linking `docs/pilot-validation.md`, `docs/external-security-review-rfp.md`, and `docs/v1.0.0-readiness.md`.

### 6. v1.0.0 readiness summary

`docs/v1.0.0-readiness.md`: one-page summary of remaining user-action items.

### 7. CHANGELOG + tag

Add `[0.9.0-rc.2] - 2026-04-29` entry. Tag `v0.9.0-rc.2`. Push. GitHub release.

**Do NOT tag `v1.0.0`.** That tag belongs to the maintainer.

## Acceptance

- All 313 Plan 1-9 tests still pass.
- Seven new doc files created.
- README updated with the v1.0.0 path.
- CHANGELOG entry written.
- Tag `v0.9.0-rc.2` published.

## Out of Scope

- Running the pilot.
- Hiring the security reviewer.
- Provisioning release secrets.
- Tagging `v1.0.0`.
