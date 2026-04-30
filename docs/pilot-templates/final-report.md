# Pilot Final Report

The pilot lead fills out this report at the end of Phase 4 (week 6) and signs. The signed report is the gating artifact for the maintainer tagging `v1.0.0`.

## Identification

- **Pilot Client:** ___________________________________________
- **Pilot Lead:** ___________________________________________
- **MDM Admin:** ___________________________________________
- **Pilot Window:** YYYY-MM-DD through YYYY-MM-DD
- **Software version under pilot:** v0.9.0-rc.2 (or later RC if rerolled during pilot)
- **Profile deployed:** baseline / strict / regulated
- **Endpoint count:** ___ (split by OS: macOS ___ / Windows ___ / Linux ___)

## Phase completion

| Phase | Window | Entry criteria met | Exit criteria met | Date completed |
| --- | --- | --- | --- | --- |
| 1 - Kickoff | Week 1 | Yes / No | Yes / No | YYYY-MM-DD |
| 2 - Rollout | Weeks 2-3 | Yes / No | Yes / No | YYYY-MM-DD |
| 3 - Hardening | Weeks 4-5 | Yes / No | Yes / No | YYYY-MM-DD |
| 4 - Signoff | Week 6 | Yes / No | Yes / No | YYYY-MM-DD |

## Friction summary

From the pilot friction log:

- Total friction items captured: ___
- P0 captured: ___ / closed: ___
- P1 captured: ___ / closed: ___ / deferred to v1.1: ___
- P2 captured: ___ / closed: ___ / deferred to v1.1: ___
- False positive rate: ___% (FP / total non-drill items)

**P0 closure status:** All P0 items closed before signoff: Yes / No

If No: list each open P0 with rationale for shipping anyway. (Reminder: open P0 typically blocks `v1.0.0`.)

## Drill results

| Drill | Threat | Result | Notes |
| --- | --- | --- | --- |
| 1 - Secret leak | T-001 | Pass / Fail | |
| 2 - Destructive FS | T-005 | Pass / Fail | |
| 3 - Egress | T-007 | Pass / Fail | |
| 4 - Pipe-to-shell | T-008 | Pass / Fail | |
| 5 - MDM bypass | T-014 | Pass / Fail | |

All five drills must Pass for pilot signoff.

## Audit log integrity

- Audit log path on endpoints: ___________________________
- Audit log entries written during pilot: ___________
- Hash chain integrity verified: Yes / No
- Tamper detection (`verify-managed.sh`) ran hourly for ___ days
- Tamper detection fired correctly during Drill 5: Yes / No

## Operational observations

Free-form. The pilot lead writes 100-300 words on what worked, what did not, and what the maintainer should know. Examples:

- Did developers find the project's friction acceptable?
- Did the MDM admin find the deployment doc sufficient?
- Were there profile tweaks that should ship in default `regulated`?
- Did any threat surface in the pilot that is not in the threat model?
- How did the project compare to whatever the client used previously?

```
[FILL]
```

## Recommendations to maintainer

The pilot lead lists (in priority order) what the maintainer should change before tagging `v1.0.0`. Items the maintainer disagrees with go into the v1.1 backlog with rationale.

1. ___________________________________________
2. ___________________________________________
3. ___________________________________________

## Public case study

The pilot client elects:

- [ ] Public case study with client name disclosed.
- [ ] Public case study with client identified by sector + geography only (e.g. "regulated public-sector client, Ontario, Canada").
- [ ] No public case study; pilot remains internal.

If a case study is published, the pilot client retains the right to redact specific endpoint counts, vulnerability details, and operational details. The maintainer respects redaction requests received within 30 days of pilot completion.

## v1.0.0 readiness

The pilot lead confirms or does not confirm pilot-side readiness for the maintainer to tag `v1.0.0`:

- [ ] All P0 items closed.
- [ ] All five drills Pass.
- [ ] Tamper detection verified.
- [ ] Pilot client has no objection to maintainer publishing `v1.0.0` referencing this engagement.

If any box is unchecked, list the blocker:

```
[FILL]
```

## Signatures

**Pilot Lead:** ___________________________ Date: ___________

**MDM Admin (as observed):** ___________________________ Date: ___________

**Pilot Client authorized signatory:** ___________________________ Date: ___________

**Provider:** ___________________________ Date: ___________

> Provider is the deploying organization (BITSUMMIT for BITSUMMIT-led pilots; the adopting organization otherwise).

---

This signed report is filed by the maintainer alongside the v1.0.0 release notes. Sensitive details may be redacted from the public version per the case-study election above.
