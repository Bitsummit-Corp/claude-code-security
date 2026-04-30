# Security Advisory Template

Use this template when filing a private security advisory at <https://github.com/Bitsummit-Corp/claude-code-governance/security/advisories>. Sections marked **(maintainer)** are filled in during triage; reporters complete the rest.

## Summary

[1-2 sentences: what's affected, what an attacker can do.]

## Affected Versions

[e.g. `>= 0.5.0-beta.0, < 0.9.0-rc.1` - or "all versions to date".]

## Severity (maintainer)

[CRITICAL / HIGH / MEDIUM / LOW] - CVSS 4.0 vector: `[vector string]` - score: `[N.N]`

## Threat ID (maintainer)

[T-NNN if maps to an existing entry in `docs/threat-model.md`; otherwise mark "new" and propose an ID.]

## Reproduction

Minimum reproducer:

```
[steps / commands / inputs]
```

Expected (hardened) behavior: [what should happen]
Observed behavior: [what actually happens]

## Impact

- Confidentiality: [None / Low / High]
- Integrity: [None / Low / High]
- Availability: [None / Low / High]
- Scope: [Unchanged / Changed]

## Mitigation Before Patch

[Workarounds users can apply right now, or "none available".]

## Patch (maintainer)

- Commit: `[sha]`
- Released in: `[vX.Y.Z]`
- Backports: `[release/v1.x branches updated, if any]`

## Disclosure Timeline (maintainer)

- Reported: `[YYYY-MM-DD]`
- Acknowledged: `[YYYY-MM-DD]`
- Triage complete: `[YYYY-MM-DD]`
- Fix released: `[YYYY-MM-DD]`
- Public disclosure: `[YYYY-MM-DD]`

## Credit

Reported by [name + handle]. Listed in `SECURITY.md` Hall of Thanks with reporter's permission.

## References

- GHSA: `[GHSA-xxxx-xxxx-xxxx]`
- CVE: `[CVE-YYYY-NNNNN if assigned]`
- Related issues / PRs: [links]
