# External Security Review - Request for Proposal

This is a template the maintainer uses to solicit a paid third-party security review of `claude-code-security` before tagging `v1.0.0`. Send to 3-5 firms in parallel. Pick based on response quality, scope match, and budget. Adopters running their own deployment of this project may also use this RFP template; substitute your contact details in the Submission section below.

## Project overview

`claude-code-security` (also distributed as `@bitsummit/claude-code-security` on npm and as the `bitsummit/hardening` Claude Code plugin) is an open-source hardening reference for Anthropic's Claude Code CLI. It ships 26 PreToolUse / PostToolUse / SubagentStart / SubagentStop hooks, three layered settings profiles (`baseline`, `strict`, `regulated`), behavioral CLAUDE.md rules, and OS-specific MDM deployment installers (macOS Jamf, Windows Intune, Linux Ansible / .deb / .rpm). It targets two audiences: individual developers hardening their own install, and IT admins deploying a vetted policy to a regulated fleet via MDM. The project is at `v0.9.0-rc.2` as of this RFP; `v1.0.0` ships once a pilot validation and this external review complete. Source: `https://github.com/Bitsummit-Corp/claude-code-governance`.

## Engagement scope

The reviewer evaluates whether the project does what it claims, finds and reports any gaps between the threat model and the implementation, and signs off (or does not) on the threat model itself.

**In scope:**

1. **Threat model review.** `docs/threat-model.md` enumerates 18 threats (T-001 through T-018). Validate that the model is complete for the stated audience, that severities are reasonable, and that no significant threats are missing. Cross-check against OWASP LLM Top 10, OWASP Agentic Top 10, and STRIDE.
2. **Hook code review.** All 26 hooks live in `packages/hooks/src/<name>/index.ts` with companion `<name>.test.ts`. The reviewer reads each hook's logic, identifies bypasses beyond the documented `docs/known-bypasses.md`, and grades the test coverage's adequacy against the threat the hook claims to mitigate.
3. **Settings schema review.** `docs/settings-reference.md` is the schema-of-record. Reviewer validates that every key is documented, that `permissions.deny[].pattern` cannot be bypassed by adversarial path token expansion, that the `regulated` profile actually achieves what it says, and that profile-layering (`baseline` -> `strict` -> `regulated`) does not produce unexpected escalations.
4. **Deployment guide review.** `docs/deployment/mdm-jamf.md`, `installers/windows/README.md`, `installers/linux/README.md`. Reviewer confirms the deployed artifact actually has the intended properties (root-owned, immutable on macOS via `chflags schg`, NTFS ACL hardened on Windows, `chattr +i` on Linux), and that `verify-managed.sh` actually detects tampering.
5. **Audit log integrity.** The hash-chained audit log is the project's accountability primitive. Reviewer attempts to forge entries, splice the chain, induce false positives via concurrent writes, and validates the recovery path.
6. **Tamper detection.** `verify-managed.sh` is supposed to detect `disableAllHooks` MDM bypass attempts (per ADR-0003 and Anthropic issue #26637). Reviewer attempts to defeat the detection.

**Out of scope:**

1. **Claude Code itself.** Bugs in Anthropic's CLI are out of scope - report them to Anthropic. The review covers what `claude-code-security` adds **on top of** Claude Code.
2. **OS-level security primitives.** macOS TCC, Windows DAC ACLs, Linux DAC / AppArmor / SELinux are assumed to function. The review does not test for kernel privilege escalation.
3. **Third-party hooks installed alongside this project.** Hooks shipped by other vendors are out of scope. The review covers only hooks under `packages/hooks/src/` and settings under `packages/settings/profiles/`.
4. **The pilot client's MDM configuration outside this project.** Their Jamf or Intune posture in general is their own audit's concern.
5. **Supply chain of upstream npm packages.** SBOM is shipped, but a deep CVE audit of every transitive dependency is a separate engagement.

## Deliverables

The reviewer produces:

1. **Written report** (PDF, 20-50 pages typical). Executive summary, methodology, findings, recommendations, retest results.
2. **Severity-ranked findings.** Each finding tagged Critical / High / Medium / Low / Informational, with CVSS 4.0 vector, reproduction steps, recommended remediation.
3. **Retest after fixes.** The maintainer fixes Critical / High findings; the reviewer retests and confirms remediation. Retest is part of the engagement, not a follow-on.
4. **Public-release version of the report.** A redacted version suitable for attaching to the `v1.0.0` GitHub release. Sensitive details (working exploit primitives, internal client names) redacted.
5. **One-page executive summary.** Suitable for inclusion in `SECURITY.md` and the release notes.

## Timeline

Suggested 4-6 weeks end-to-end:

- Week 0: SOW signed; access provisioned (read-only repo access, test environment provisioned by maintainer).
- Weeks 1-3: Active testing.
- Week 4: Initial report delivered; Critical / High findings shared early so remediation can start.
- Week 5: Retest after fixes.
- Week 6: Final report delivered; one-page summary signed.

The pilot validation (`docs/pilot-validation.md`) runs in parallel with this engagement so the `v1.0.0` window is six weeks total, not twelve.

## Budget guidance

The maintainer expects a focused engagement at this scope to fall in the **15,000-30,000 USD** range. This is non-authoritative - it is a budget anchor for the maintainer's planning, not a price set for the firm. The firm quotes its own price; the maintainer compares quotes from 3-5 firms before signing.

If a quote is dramatically lower or higher than the band, the maintainer asks why before judging. A 5K quote suggests the firm has not understood scope; a 75K quote suggests the firm is pricing for a deeper engagement than this RFP describes (e.g. fuzzing infrastructure standup, custom tooling).

## Candidate firms

The maintainer sends this RFP to 3-5 of the following well-known firms. Inclusion here is not an endorsement; it is a starting list of firms with public reputations for the kind of work this engagement asks for.

- **Trail of Bits** - `https://www.trailofbits.com`. Strong on systems security, cryptography, supply chain. Very busy; expect long lead times.
- **NCC Group** - `https://www.nccgroup.com`. Large firm; cryptography services and applied research labs. Good fit for the breadth of this scope.
- **Doyensec** - `https://doyensec.com`. Boutique; deep web / cloud / dev tooling expertise. Often a good fit for projects in this category.
- **Cure53** - `https://cure53.de`. Berlin; deep web app + browser security; many open-source audits.
- **Atredis Partners** - `https://www.atredis.com`. Hardware and applied red team; would be a less common pick for this scope but has the bench.
- **Include Security** - `https://includesecurity.com`. Strong for application security; good track record on JavaScript / TypeScript codebases.

The maintainer is encouraged to add or remove firms based on personal references, geographic preference, and budget alignment.

## Engagement Q&A template

The firm fills this out before signing the SOW. Replies under 150 words per question are encouraged.

```
1. Who on your bench leads this engagement, and what is their background relevant to:
   - LLM-agent security (Claude Code, OpenAI Codex, Cursor, etc.)
   - JavaScript / TypeScript codebase review
   - macOS / Windows / Linux MDM deployment review
   - Hash-chained audit log analysis

2. How many engagements has your firm performed on similar scope (open-source dev-tool hardening
   reference) in the last 24 months? Any you can name as references?

3. What is your typical methodology for a 4-6 week engagement of this scope? Specifically:
   - How is testing time allocated across threat-model review vs hook code review vs deployment review?
   - Do you fuzz hook input? Use static analysis? Both?
   - How do you handle bypass research vs reporting tradeoffs?

4. What deliverable format do you produce? Will the public-release redacted version meet
   our requirement to attach to a GitHub release?

5. Can you commit to retest within the same engagement window (week 5 in our timeline)?

6. What is your fixed-fee quote for this scope, including retest? What is the day rate
   if scope expands?

7. What access do you require? Read-only GitHub repo access is provisioned by us.
   Do you need a test environment? Do you need the pilot client's MDM configuration?
   (Note: pilot client's MDM is out of scope per RFP.)

8. What is your earliest start date?

9. Are there any out-of-scope items in our RFP that you believe should be in scope?
   (We respect strong arguments to expand or contract scope.)

10. Do you have any conflicts of interest with Anthropic, BITSUMMIT, or the candidate
    pilot clients? (Specific client names disclosed under NDA on engagement.)
```

## Submission

For BITSUMMIT-issued RFPs, contact is `security@bitsummit.com`. PGP key fingerprint to be published in `SECURITY.md` once generated; until then plain email is acceptable but treat the contents as untrusted by transport. Adopters using this template substitute their own contact channel here.

Responses requested within 10 business days of RFP receipt. Engagement signed within 20 business days of receipt.
