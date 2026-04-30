# Maintainer's Build Journal

This directory contains the brainstorm / spec / plan artifacts the maintainer produced while building `claude-code-security`. They are kept in the public repo for transparency and as a historical record of the design decisions, but they are **not** load-bearing for using or deploying the project.

If you are an adopter, IT admin, or external operator, you do **not** need to read anything in this directory. The user-facing documentation lives at the repo root and under `docs/` (one level up): `README.md`, `SECURITY.md`, `docs/threat-model.md`, `docs/coverage-matrix.md`, `docs/known-bypasses.md`, `docs/pilot-validation.md`, `docs/deployment/`, `docs/hooks/`, `docs/adr/`, and `docs/settings-reference.md`.

## What is in here

- `plans/` - per-plan implementation sequences (Plan 1 through Plan 10) used during the build. Each plan was executed in a separate Claude Code session.
- `specs/` - design specs that preceded each plan. The repo-level design spec is `2026-04-29-claude-code-security-repo-design.md`.

## Voice and references

These files are written in the maintainer's internal voice and reference BITSUMMIT-specific tooling, terminology, and pipeline context that is not relevant to external adopters. The files were not rewritten for general audiences after the build completed; rewriting them would erase the historical record without meaningfully improving the project's usability. Treat them as you would any maintainer's design notes published alongside an open-source project.

## Authoritative documents

For the user-facing equivalents of what is in here, see:

- Architecture decisions: `docs/adr/0001` through `docs/adr/0006`.
- Threat coverage: `docs/threat-model.md` and `docs/coverage-matrix.md`.
- Per-hook behavior: `docs/hooks/<name>.md`.
- Pilot runbook: `docs/pilot-validation.md`.
- External security review template: `docs/external-security-review-rfp.md`.
- v1.0.0 readiness checklist: `docs/v1.0.0-readiness.md`.
