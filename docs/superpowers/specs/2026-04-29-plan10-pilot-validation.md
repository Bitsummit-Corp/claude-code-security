# Spec - Plan 10 - Pilot Validation

> Date: 2026-04-29. Phase 1, Plan 10 of 10. Predecessor: `v0.9.0-rc.1`.

## Problem

`v0.9.0-rc.1` shipped the release-engineering substrate: SBOM, GHSA pipeline scaffolding, SEA binary templates, provenance, and the canonical release runbook. The hook surface is feature-complete (26 hooks, 18 threats, 313 tests passing). All Track 1-5 documentation is shipped.

What is missing for `v1.0.0` is **real-world validation**. A hardening reference that has never been deployed in a production fleet, and has never been independently reviewed, has not earned its `1.0` label. Plan 10 is the bridge from "feature-complete" to "trustworthy in the field".

## Documentation-only plan

Plan 10 is **NOT** a code-implementation plan and cannot be fully shipped autonomously by Claude Code. It requires two user actions that no agent can perform:

1. **Pilot validation** requires a real BITSUMMIT customer engagement (a regulated client matching one of the candidate profiles documented in the runbook; specific client tracked privately). The deployment, friction-log, incident-drill, and signoff happen with humans, on real fleets, over 4-6 weeks.
2. **External security review** requires hiring a paid security firm (Trail of Bits, NCC Group, Doyensec, Cure53, etc.). The engagement is multi-week, costs five figures, and the final report goes into the public release notes.

What Claude Code **can** ship in this plan is the **runbook + RFP template + readiness checklist + pilot templates** the maintainer will execute. The actual `v1.0.0` ship is gated on the maintainer completing those user-action items.

## In Scope (Documentation Only)

1. `docs/pilot-validation.md`: canonical pilot runbook covering candidate clients, criteria, four-phase rollout, friction log, internal incident drill, and v1.0.0 readiness checklist.
2. `docs/external-security-review-rfp.md`: RFP template the maintainer can send to security firms.
3. `docs/pilot-templates/agreement.md`: pilot agreement template (with explicit disclaimer that it does not substitute for contract counsel).
4. `docs/pilot-templates/friction-log.md`: running friction-log template for the pilot lead.
5. `docs/pilot-templates/incident-drill.md`: simulated bypass-attempt drill template.
6. `docs/pilot-templates/final-report.md`: pilot signoff template.
7. `docs/v1.0.0-readiness.md`: single-page summary of remaining user actions before `v1.0.0`.
8. README updates: status banner reflecting plan-10 user-action gating; "v1.0.0 path" pointer block.
9. CHANGELOG entry + tag `v0.9.0-rc.2`.

## Out of Scope (User-Action)

These are listed explicitly so they cannot drift back into scope:

- Running the pilot. (Maintainer + pilot client.)
- Hiring and managing the external security reviewer. (Maintainer.)
- Generating the PGP release key and publishing the fingerprint in `SECURITY.md`. (Maintainer.)
- Provisioning `NPM_TOKEN`, Apple Developer ID cert, optional Windows EV cert. (Maintainer.)
- Writing the `[1.0.0]` CHANGELOG entry. (Maintainer; gated on the above completing.)
- Submitting the plugin marketplace listing to Anthropic. (Maintainer.)

## Acceptance

1. All seven docs above exist, with substantive content (no stubs, no TODOs in the body of the runbook or the RFP).
2. README banner explicitly states that `v1.0.0` ships when the maintainer completes Plan 10.
3. CHANGELOG `[0.9.0-rc.2]` entry written with the seven-doc inventory.
4. Tag `v0.9.0-rc.2` pushed; GitHub release created.
5. **NO** `v1.0.0` tag created. `v1.0.0` is the maintainer's call after pilot signoff.
6. All 313 Plan 1-9 tests still pass (Plan 10 ships docs, not code, so test count is unchanged).

## Why this is the final plan in the sequence

Plans 1-5 built the hook surface. Plan 6 shipped distribution. Plan 7 shipped MDM + tamper detection. Plan 8 shipped the documentation tracks. Plan 9 shipped the release-engineering substrate. Plan 10 is the bridge from "we built a hardening reference" to "the hardening reference has been validated in the field and reviewed by a third party".

Once Plan 10 user-actions complete, `v1.0.0` is a one-command ship. The release-engineering CI in Plan 9 publishes to npm, generates SBOM, builds SEA binaries, and attaches `SHA256SUMS` automatically.
