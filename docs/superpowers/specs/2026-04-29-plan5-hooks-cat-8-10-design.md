# Design: Plan 5 - Hooks Categories 8-10 + Profile Differentiation

**Status:** Locked autonomous-mode design
**Date:** 2026-04-29
**Plan target tag:** `v0.5.0-beta.0`
**Predecessor:** Plan 4 (`v0.4.0-alpha.0`; 18 hooks, 252 tests, 97.49% coverage)

---

## 1. Purpose & Scope

Plan 5 lands the final 8 hooks of Phase 1's hook coverage (categories 8, 9, 10), introduces behavioral CLAUDE.md hardening templates, and **differentiates strict and regulated profiles for real** (Plans 1-4 shipped them as identical-content shells). After Plan 5 the project transitions from `alpha` to `beta` because the hook surface is feature-complete.

**In scope:**

- 8 new hooks (3 behavioral + 2 MDM-bypass + 3 agent-gating)
- New `packages/rules/` package with CLAUDE.md hardening templates
- New overlays: `behavioral.json`, `mdm-bypass.json`, `agent-gating.json`
- **Real strict/regulated differentiation**: strict adds tighter egress + behavioral; regulated adds MDM bypass + agent-gating + tightest egress
- Threat ID cleanup (T-005 was reused; rename Plan 3's `T-005-supply-chain-submodule` -> `T-013-supply-chain-submodule` in hook code; threat-model already aligned)
- 4 new integration transcripts: behavioral-bypass, mdm-bypass, subagent-escape, regulated-profile-end-to-end
- Threat model: T-010 prompt injection, T-011 subagent escape, T-012 MDM bypass, T-013 settings precedence, T-018 supply-chain-via-hooks; remaining threats noted as "covered" with cross-references
- Coverage matrix updated; profile rationale doc

**Out of scope:**

- Plugin/npm distribution (Plan 6)
- Jamf integration / managed-settings.json deployment (Plan 7)
- Full Track 1-5 docs + auto-generation (Plan 8)
- Release engineering hardening (signing, SBOM, GHSA) (Plan 9)
- Pilot validation (Plan 10)

---

## 2. Hook List

| Hook | Event | Matchers | Threat | Severity |
|---|---|---|---|---|
| `behavioral-rule-enforcer` | UserPromptSubmit | * | T-010-prompt-injection | log all profiles |
| `claude-md-validator` | SessionStart | * | T-010-prompt-injection | warn baseline / block strict+regulated |
| `untrusted-content-tagger` | PostToolUse | WebFetch, Read | T-010-prompt-injection | log all profiles |
| `disable-all-hooks-detector` | SessionStart, PreToolUse | * | T-012-mdm-bypass | warn all profiles (passive per spec ADR-0003) |
| `local-settings-precedence-checker` | SessionStart | * | T-013-settings-precedence | warn baseline / block regulated |
| `subagent-spawn-guard` | SubagentStart | * | T-011-subagent-escape | warn baseline / block strict+regulated |
| `task-tool-input-guard` | PreToolUse | Task | T-011-subagent-escape | block all profiles |
| `agent-allowlist-enforcer` | SubagentStart | * | T-011-subagent-escape | block regulated only (audit baseline+strict) |

### 2.1 Behavioral notes

**`behavioral-rule-enforcer`** (UserPromptSubmit, log) emits an audit record for every user prompt with metadata about its length, presence of risky patterns (e.g., "ignore previous instructions", "system prompt"), and tool-mention counts. Does not block; provides the prompt-injection forensic trail.

**`claude-md-validator`** (SessionStart) checks for the presence of a project `CLAUDE.md` file. If present, validates that it does not contain known-bad patterns (instructions to disable hooks, to skip permission prompts, etc.). Per-profile severity: warn on baseline, block on strict+regulated.

**`untrusted-content-tagger`** (PostToolUse on WebFetch and Read) tags tool output with a metadata marker indicating it came from an untrusted source. Audit-log only; downstream tools and the model itself can read this from the audit trail. Does not block.

**`disable-all-hooks-detector`** (SessionStart + PreToolUse) - the centerpiece passive mitigation for issue #26637. Reads `.claude/settings.local.json` if present, checks for `disableAllHooks: true`. If found, emits an audit record (`warn` severity per ADR-0003 passive-only posture). Does NOT block. The audit trail captures the bypass attempt.

**`local-settings-precedence-checker`** (SessionStart) checks whether `.claude/settings.local.json` exists alongside the managed settings, and whether its content overrides the managed-side deny rules. Emits a per-profile severity warn/block.

**`subagent-spawn-guard`** (SubagentStart) gates subagent spawns by the `Task` tool. Per-profile severity: warn on baseline (audit), block on strict+regulated unless the subagent type is in an allowlist.

**`task-tool-input-guard`** (PreToolUse on Task) inspects Task input for prompt-injection patterns OR for instructions that would dispatch un-vetted agents. Always blocks if it finds such patterns.

**`agent-allowlist-enforcer`** (SubagentStart) cross-references the spawned subagent type against an allowlist (read from settings or env). On regulated profile, blocks any non-allowlisted spawn; on baseline+strict it audits but allows.

### 2.2 Threat ID cleanup

Plan 3's submodule-injection-guard hook declares `threat: 'T-005-supply-chain-submodule'`. Plan 4's threat-model.md renumbered this to T-013. Update the hook's manifest to use `T-013-supply-chain-submodule`. Update the hook's tests. Update related deny patterns in `overlays/branch-guards.json`.

### 2.3 CLAUDE.md hardening templates (`packages/rules/`)

New workspace package `@bitsummit/ccsec-rules` (no TS, just markdown templates):

- `templates/baseline.md`: minimal hardening rules (no eval, no curl|sh, no force-push)
- `templates/strict.md`: baseline + structural-bash discipline + branch-guard rules
- `templates/regulated.md`: strict + MDM bypass disclosures + agent allowlist + audit confirmation requirements
- `templates/snippets/`: reusable rule snippets that the per-profile templates compose

These are referenced in the hook docs and can be auto-installed by the CLI in Plan 6 via `ccsec apply --profile X --install-rules`.

---

## 3. Profile Differentiation (Real)

Until Plan 5 all 3 profiles extended the same overlay set. Plan 5 differentiates:

**baseline** extends:
```
[base, secrets, destructive, sensitive-paths, bash-structural, branch-guards, network-egress, audit, behavioral]
```

**strict** extends:
```
[base, secrets, destructive, sensitive-paths, bash-structural, branch-guards, network-egress (tighter allowlist override), audit, behavioral, agent-gating]
```

**regulated** extends:
```
[base, secrets, destructive, sensitive-paths, bash-structural, branch-guards, network-egress (tightest), audit, behavioral, agent-gating, mdm-bypass]
```

The "tighter network-egress" for strict/regulated is achieved via the profile's `overrides` block which restricts the egress allowlist. baseline allows 8 hosts; strict allows only 4 (anthropic.com, github.com, npmjs.org, pypi.org); regulated allows only 2 (anthropic.com, github.com).

Hook `severity` records (per-profile) drive most behavior differences; the overlay set difference is for opt-in protection layers.

---

## 4. Test Corpus

4 new integration transcripts:

1. `behavioral-bypass-attempt.json` - prompts containing "ignore previous instructions"; tool output with embedded prompt-injection.
2. `mdm-bypass-attempt.json` - simulates `.claude/settings.local.json` with `disableAllHooks: true`; expects warn from disable-all-hooks-detector.
3. `subagent-escape-attempt.json` - Task tool with malicious prompt; un-allowlisted subagent type.
4. `regulated-profile-end-to-end.json` - same events as the Plan 4 attack-chain, but run under profile=regulated; verifies that strict/regulated block where baseline warns.

---

## 5. Threat Model Expansion

`docs/threat-model.md` adds:
- **T-010 Prompt Injection from Tool Output** - behavioral-rule-enforcer audit + untrusted-content-tagger + claude-md-validator
- **T-011 Subagent Escape / Unauthorized Spawn** - subagent-spawn-guard + task-tool-input-guard + agent-allowlist-enforcer
- **T-012 MDM Bypass via disableAllHooks** - disable-all-hooks-detector (passive per ADR-0003)
- **T-013 Local Settings Overriding Managed** - local-settings-precedence-checker
- **T-018 Supply Chain Attack on Hooks** - documented; mitigation is signed releases (Plan 9 hardens further)

After Plan 5, threats T-001 through T-018 are all documented; mitigations exist for T-001 through T-017 with varying coverage levels.

---

## 6. Implementation Sequence (12 tasks)

1. Threat ID cleanup (rename T-005 to T-013 in submodule-injection-guard)
2. behavioral-rule-enforcer hook
3. claude-md-validator hook
4. untrusted-content-tagger hook
5. disable-all-hooks-detector hook
6. local-settings-precedence-checker hook
7. subagent-spawn-guard hook
8. task-tool-input-guard hook
9. agent-allowlist-enforcer hook
10. Three new overlays + `packages/rules/` package + profile differentiation + snapshot regen
11. 4 integration transcripts + threat model + coverage matrix + CHANGELOG
12. Final checks + tag v0.5.0-beta.0 + push + GitHub release

---

## 7. Success Criteria

- v0.5.0-beta.0 tagged (note: beta, not alpha; hook surface is now feature-complete)
- All 8 new hooks shipping; 26 hooks total
- Profile differentiation real: baseline / strict / regulated produce distinct compiled settings
- 15 integration tests pass (11 prior + 4 new)
- Threat IDs internally consistent (Plan 3 hook now uses T-013)
- All Plan 1-4 tests still pass
- Coverage stays above 90 percent

---

## 8. References

- [Parent spec](./2026-04-29-claude-code-security-repo-design.md)
- [Plan 4 plan](../plans/2026-04-29-phase1-plan4-hooks-cat-6-7.md)
- [v0.4.0-alpha.0 release](https://github.com/Bitsummit-Corp/claude-code-governance/releases/tag/v0.4.0-alpha.0)
- [anthropics/claude-code#26637](https://github.com/anthropics/claude-code/issues/26637) - the `disableAllHooks` MDM bypass
