# Design: Plan 3 - Hooks Categories 4-5 (Bash Structural, Branch Guards)

**Status:** Locked (autonomous-mode design; user reviews at end of Plan 10)
**Date:** 2026-04-29
**Owner:** Haseeb Minhas (BITSUMMIT)
**Parent spec:** `docs/superpowers/specs/2026-04-29-claude-code-security-repo-design.md`
**Plan target tag:** `v0.3.0-alpha.0`
**Predecessor:** Plan 2 (`v0.2.0-alpha.0` shipped; 7 hooks across categories 1-3, contract bumps for per-profile severity + matcher wildcards + PostToolUse response)

---

## 1. Purpose & Scope

Plan 3 adds hooks for categories 4 (bash structural) and 5 (branch guards), tightens the existing bash-parser, and lands a basic property-based fuzz test. After Plan 3 the project has 14 hooks total (Plan 1: 1, Plan 2: 7, Plan 3: 6) covering threats T-001 through T-009.

**In scope:**

- 6 new hooks (2 bash-structural + 4 branch-guards)
- Bash parser improvements (Plan 1 advisory carryforward): fullwidth-pipe lookalike, fullwidth-dollar lookalike, background-operator detection, escape-handling documented
- New overlays: `bash-structural.json`, `branch-guards.json`
- Updated profiles to extend new overlays
- Basic fast-check property test for bash-parser (no separate fuzz cron; that's Plan 9)
- 3 new integration transcripts: bash-structural-attempt, branch-sabotage-attempt, history-rewrite-attempt
- Threat model entries: T-005, T-006, T-007, T-008, T-009; T-004 marked fully covered
- Coverage matrix updated

**Out of scope:**

- Network egress / WebFetch allowlist (Plan 4)
- Audit-log concurrency hardening (Plan 4)
- Full strict/regulated profile differentiation (Plan 5)
- Plugin / npm distribution (Plan 6)
- Long-running fuzz cron and SIEM-style continuous regression (Plan 9)

---

## 2. Hook List

| Hook | Event | Matchers | Threat | Severity |
|---|---|---|---|---|
| `bash-structural-guard` | PreToolUse | Bash | T-006/T-007/T-009 | warn baseline / block strict+regulated |
| `pipe-to-shell-guard` | PreToolUse | Bash | T-006-pipe-to-shell | block all profiles |
| `branch-protection-guard` | PreToolUse | Bash | T-004-branch-sabotage | warn baseline / block strict+regulated |
| `commit-amend-pushed-guard` | PreToolUse | Bash | T-004-branch-sabotage | warn baseline / block strict+regulated |
| `submodule-injection-guard` | PreToolUse | Edit, Write, Bash | T-005-supply-chain-submodule | block all profiles |
| `git-history-rewrite-guard` | PreToolUse | Bash | T-008-history-rewrite | block all profiles |

### 2.1 Behavioral notes

**`bash-structural-guard`** uses `detectStructuralRisks` from `@bitsummit/ccsec-core/bash-parser`. Configurable list of risk kinds to block: by default blocks `pipe_to_shell`, `command_substitution`, `process_substitution`, `unicode_lookalike`. Allows `chained_and`, `chained_or`, `chained_semicolon`, `leading_cd` (these are everyday shell idioms). Per-profile severity: warn on baseline (let users see the audit trail without breaking flow); block on strict and regulated.

**`pipe-to-shell-guard`** narrow, fast pre-filter for the most dangerous structural risk: `curl | sh`, `wget -O- | bash`, etc. Always blocks. Redundant with bash-structural-guard for this kind, but provides a focused hook that strict environments can rely on alone if they disable structural-guard.

**`branch-protection-guard`** flags any direct commit on protected branches (main/master/release/develop/prod/production), commits with `--no-verify` or `--no-gpg-sign`, and pushes to protected branches without an explicit `--allow-protected` env var (which the user can set when they truly intend to push to main). Per-profile severity.

**`commit-amend-pushed-guard`** detects `git commit --amend` invocations and emits warn/block. Cannot determine "already pushed" from the command line alone (would need to query git state); defaults to warning on every amend so users are reminded that amending pushed commits will require force-push. Per-profile severity.

**`submodule-injection-guard`** matches Edit/Write on `.gitmodules` and Bash invocations of `git submodule add`. Threat: a malicious submodule URL (or `update --init` running an arbitrary post-checkout hook) is a real supply-chain vector. Always blocks.

**`git-history-rewrite-guard`** matches `git filter-branch`, `git filter-repo`, references to BFG (`bfg --strip-blobs-bigger-than`, etc.), `git replace`, `git update-ref` of HEAD/refs in unusual ways. Always blocks. These commands rewrite history irreversibly.

### 2.2 Bash parser improvements (Plan 1 advisory carryforward)

In `packages/core/src/bash-parser.ts`:

1. Add to `UNICODE_LOOKALIKES`: `｜` (U+FF5C fullwidth pipe), `＄` (U+FF04 fullwidth dollar). Existing entries (U+FF1B, U+FF06) stay.
2. Add new risk kind `background_operator` matching standalone `&` not preceded by another `&` (which would be `&&`). Update `detectStructuralRisks` to scan for it.
3. Document the escape-handling limitation in `maskQuotedRegions` with an inline comment: it does not honor `\` escapes inside double-quoted strings, which causes over-flagging on malformed quotes. This is the safe-default tradeoff.
4. Update Plan 1's bash-parser tests to cover the new lookalikes and background operator.

---

## 3. Settings

### 3.1 New overlays

**`overlays/bash-structural.json`**:

```json
{
  "permissions": {
    "deny": [
      { "pattern": "Bash(curl * | sh)",       "threat": "T-006-pipe-to-shell" },
      { "pattern": "Bash(curl * | bash)",     "threat": "T-006-pipe-to-shell" },
      { "pattern": "Bash(wget * | sh)",       "threat": "T-006-pipe-to-shell" },
      { "pattern": "Bash(wget * | bash)",     "threat": "T-006-pipe-to-shell" }
    ]
  },
  "hooks": {
    "PreToolUse": [
      { "name": "bash-structural-guard" },
      { "name": "pipe-to-shell-guard" }
    ]
  }
}
```

**`overlays/branch-guards.json`**:

```json
{
  "permissions": {
    "deny": [
      { "pattern": "Bash(git filter-branch *)",      "threat": "T-008-history-rewrite" },
      { "pattern": "Bash(git filter-repo *)",        "threat": "T-008-history-rewrite" },
      { "pattern": "Edit(*.gitmodules)",             "threat": "T-005-supply-chain-submodule" },
      { "pattern": "Write(*.gitmodules)",            "threat": "T-005-supply-chain-submodule" }
    ]
  },
  "hooks": {
    "PreToolUse": [
      { "name": "branch-protection-guard" },
      { "name": "commit-amend-pushed-guard" },
      { "name": "submodule-injection-guard" },
      { "name": "git-history-rewrite-guard" }
    ]
  }
}
```

### 3.2 Profiles

baseline / strict / regulated all extend `["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths", "overlays/bash-structural", "overlays/branch-guards"]` (Plan 5 will start differentiating).

### 3.3 Compiled snapshots

Regenerate all 3. Snapshot test continues to cover all 3.

---

## 4. Test Corpus

3 new integration transcripts:

1. **`bash-structural-attempt.json`** - command injection variants: `curl x | sh`, `echo $(whoami)`, `diff <(ls a) <(ls b)`, `echo a；rm b` (unicode lookalike), `echo a｜sh` (fullwidth pipe).
2. **`branch-sabotage-attempt.json`** - direct commit on main, commit with `--no-verify`, branch deletion, amend on what looks like a pushed commit.
3. **`history-rewrite-attempt.json`** - filter-branch, filter-repo, .gitmodules edit, BFG-style invocations.

Plus: one fast-check property test in `packages/core/tests/bash-parser-fuzz.test.ts` that generates random shell snippets and asserts:
- The parser never throws on any input
- Adversarial unicode strings (fullwidth lookalikes) are detected when expected
- Plain commands return empty risks

---

## 5. Threat Model Expansion

`docs/threat-model.md` adds:

- **T-004** marked fully covered (was partial in Plan 2)
- **T-005 Supply Chain via Submodule** - submodule-injection-guard
- **T-006 Pipe-to-Shell Remote Execution** - pipe-to-shell-guard, bash-structural-guard, deny patterns
- **T-007 Command Chaining Bypass** - bash-structural-guard (chained_and, chained_or, chained_semicolon are surfaced as audit but not blocked by default)
- **T-008 Git History Rewrite** - git-history-rewrite-guard, filter-branch deny pattern
- **T-009 Arbitrary Code via eval / Command Substitution** - bash-structural-guard

Coverage matrix updated.

---

## 6. Implementation Sequence (16 tasks)

1. Bash-parser improvements (TDD, extend Plan 1 tests)
2. ADR-0005 documenting the parser changes (if needed; minor change, may skip)
3. fast-check fuzz test for bash-parser (TDD-adjacent)
4. bash-structural-guard hook (TDD)
5. pipe-to-shell-guard hook (TDD)
6. branch-protection-guard hook (TDD)
7. commit-amend-pushed-guard hook (TDD)
8. submodule-injection-guard hook (TDD)
9. git-history-rewrite-guard hook (TDD)
10. overlays/bash-structural.json + overlays/branch-guards.json
11. profiles updated, compiled snapshots regenerated
12. 3 integration transcripts + replay tests
13. Threat model expansion + coverage matrix update
14. CHANGELOG entry
15. Final checks + smoke test
16. Tag v0.3.0-alpha.0, push, GitHub release

---

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| `bash-structural-guard` blocks too aggressively (chained_and is everyday shell) | Default config blocks only the truly dangerous kinds (pipe_to_shell, command_substitution, process_substitution, unicode_lookalike); chained_and/or/semicolon and leading_cd are allowed-by-default |
| `commit-amend-pushed-guard` cannot reliably detect "already pushed" | Hook warns on every amend; documentation guides users to dismiss the warn when amending unpushed commits |
| Per-profile severity tuning across multiple hooks could regress integration tests | Integration test fixtures pin expected outcomes; CI catches regressions |
| Fuzz test runtime growth in CI | Fast-check defaults to ~100 runs; bounded property test, not a cron job |
| New overlays grow compiled settings.json size | Acceptable; snapshot tests just expand |

---

## 8. Success Criteria

- v0.3.0-alpha.0 tagged with all 6 hooks shipping
- Bash parser improvements live (fullwidth pipe + dollar + background)
- Fast-check fuzz test passes
- 8 integration tests pass (5 prior + 3 new)
- Snapshot tests for 3 profiles all green
- All Plan 1 + Plan 2 tests pass unchanged
- CI green
- Coverage stays >= 90%

---

## 9. References

- [Parent spec](./2026-04-29-claude-code-security-repo-design.md)
- [Plan 1 plan](../plans/2026-04-29-phase1-plan1-foundation-walking-skeleton.md)
- [Plan 2 plan](../plans/2026-04-29-phase1-plan2-hooks-cat-1-3.md)
- [v0.2.0-alpha.0 release](https://github.com/Bitsummit-Corp/claude-code-governance/releases/tag/v0.2.0-alpha.0)
