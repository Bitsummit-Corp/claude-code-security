# Pilot Agreement Template

> **Disclaimer.** This template is a starting point for negotiation between the project's deploying organization (the **Provider**) and the **Pilot Client**. It is published openly so any organization adopting `claude-code-security` can use it; BITSUMMIT itself uses it as Provider for BITSUMMIT-led pilots. It is not a finished contract. It has not been reviewed by counsel for either party. Before signing, both parties must route this through their own legal counsel. Sections marked `[FILL]` require negotiation. Sections marked `[BOILERPLATE]` are common in pilot agreements but should be reviewed for your jurisdiction.

## Parties

- **Provider:** `[FILL legal entity name and address]` (BITSUMMIT for BITSUMMIT-led pilots; substitute the deploying organization otherwise).
- **Pilot Client:** `[FILL legal entity name and address]`.
- **Effective Date:** `[FILL]`.
- **Pilot Window:** Six weeks from Effective Date, extendable by mutual written agreement.

## Subject

The Provider grants the Pilot Client a no-charge license to deploy `claude-code-security` (the "Software") to up to `[FILL]` endpoints during the Pilot Window. The Software is the open-source project at `https://github.com/Bitsummit-Corp/claude-code-governance`, licensed under MIT, deployed via the Pilot Client's existing MDM (Jamf, Intune, or Ansible).

## Pilot Scope

The Pilot Client will:

1. Identify a single Pilot Lead who serves as the named point of contact for the Pilot Window.
2. Deploy the Software to 2-3 test endpoints in Phase 1 (week 1).
3. Expand to all pilot endpoints in Phase 2 (weeks 2-3).
4. Run the internal incident drill in Phase 3 (weeks 4-5).
5. Sign off via the final report template in Phase 4 (week 6).
6. Provide weekly structured feedback in the friction-log format specified in `docs/pilot-validation.md`.

The Provider will:

1. Compile and provide the regulated-profile settings configured for the Pilot Client's environment.
2. Conduct a kickoff walkthrough call (60 minutes) with the Pilot Lead and MDM admin.
3. Hold weekly 30-minute check-ins for the duration of the Pilot Window.
4. Address P0 / P1 friction items within 5 business days of capture.
5. Provide rollback support if the deployment must be reverted.

## Costs

The pilot is no-charge for the Pilot Window. After the Pilot Window, ongoing support is governed by a separate commercial agreement (out of scope for this template). The Software remains MIT-licensed regardless.

## Confidentiality

`[BOILERPLATE]` Mutual NDA covering the Pilot Client's technical environment, the Software's pre-`v1.0.0` posture, and any vulnerabilities identified during the pilot. Vulnerabilities follow the disclosure timeline in `SECURITY.md` (acknowledgement within 72 hours, fix or roadmap within 14-30 days depending on severity, public disclosure at 90 days unless coordinated otherwise).

`[FILL]` jurisdiction-specific clauses required by the Pilot Client's regulator (e.g. PIPEDA for Canadian public-sector clients, HIPAA for US healthcare, GDPR for EU).

## Public case study

The Pilot Client agrees in principle that the Provider may publish a one-page case study referencing the engagement, subject to:

- Final editorial review by the Pilot Client.
- Right to redact any specific endpoint counts, vulnerability details, or operational details the Pilot Client considers sensitive.
- Right to withdraw consent in writing within 30 days of pilot completion. After 30 days, consent is final.

If the Pilot Client elects to remain anonymous, the case study identifies them as `[regulated client - sector, geography]` only.

## Liability

`[BOILERPLATE]` The Software is provided AS-IS under the MIT License. The Provider's liability is limited to direct damages, capped at zero for the Pilot Window since no fees are paid. Standard mutual indemnification for IP infringement claims. Carve-outs as required by the Pilot Client's regulator.

`[FILL]` jurisdiction-specific liability clauses.

## Termination

Either party may terminate the pilot at any time with 5 business days' written notice. On termination:

- The Pilot Client uninstalls the Software via the documented uninstall path.
- All pilot-specific data (friction logs, drill results, settings derivatives) is shared in writing with the Provider for project improvement.
- The mutual NDA survives termination per `[FILL term]`.

## Signatures

**Provider:** ________________________ Date: ___________

**Pilot Client:** ________________________ Date: ___________

---

> Reminder: This template is **not a finished contract**. Before signing, both parties' counsel must review and complete the `[FILL]` sections.
