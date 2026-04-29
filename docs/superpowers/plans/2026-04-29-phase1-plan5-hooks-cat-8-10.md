# Phase 1 / Plan 5: Hooks Categories 8-10 + Profile Differentiation

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Add 8 hooks (3 behavioral + 2 MDM-bypass + 3 agent-gating), introduce CLAUDE.md hardening templates, **truly differentiate strict and regulated profiles**, ship `v0.5.0-beta.0`.

**Architecture:** Builds on Plans 1-4. New hooks finish the threat coverage from the parent spec. New `packages/rules/` package ships markdown templates. Profile JSONs gain real `overrides` blocks (tighter egress allowlists for strict/regulated; additional overlays for regulated only).

**Predecessor commit:** `804ba44` (Plan 4 CHANGELOG; v0.4.0-alpha.0 tagged).

---

## Task 1: Threat ID Cleanup

**Files:** `packages/hooks/src/submodule-injection-guard/index.ts`, `submodule-injection-guard.test.ts`, `packages/settings/overlays/branch-guards.json`

- Change manifest `threat: 'T-005-supply-chain-submodule'` -> `'T-013-supply-chain-submodule'`.
- Update test that asserts threat ID.
- Update branch-guards.json deny patterns that use `T-005-supply-chain-submodule` -> `T-013-supply-chain-submodule`.
- Rebuild dist; rerun tests; commit: `fix: rename submodule threat ID to T-013 to align with threat-model`

---

## Tasks 2-9: Eight New Hooks

Same TDD pattern as Plans 1-4. Each hook gets `packages/hooks/src/<name>/{index.ts, <name>.test.ts}`. Each commits separately.

### Task 2: behavioral-rule-enforcer
- UserPromptSubmit, matchers `['*']`, threat `T-010-prompt-injection`, severity scalar `'log'`, profiles all 3, timeout 1500.
- Logic: emit audit-only record. Detect risky patterns in `ctx.input.prompt` (or `ctx.input.message`): "ignore previous instructions", "system prompt", "you are now", "override". Always allow with evidence describing matched patterns + prompt length + tool-mention count.
- Tests: emits evidence on injection patterns; emits clean evidence on benign prompts; non-string prompt -> allow with empty evidence; manifest validity.

### Task 3: claude-md-validator
- SessionStart, matchers `['*']`, threat `T-010-prompt-injection`, severity `{baseline:'warn', strict:'block', regulated:'block'}`, profiles all 3, timeout 2000.
- Logic: read `${ctx.paths.home}/CLAUDE.md` if exists OR `<cwd>/CLAUDE.md` (use ctx.env or process.cwd). Scan for known-bad patterns: "disable hooks", "skip permission", "bypass security", "ignore audit". Block if matches.
- Tests: returns allow if no CLAUDE.md exists; returns allow if CLAUDE.md is benign; returns block if file contains bad pattern; manifest validity; uses CCSEC_CLAUDEMD_PATH env override for testability.

### Task 4: untrusted-content-tagger
- PostToolUse, matchers `['WebFetch', 'Read']`, threat `T-010-prompt-injection`, severity scalar `'log'`, profiles all 3, timeout 1500.
- Logic: PostToolUse on WebFetch or Read. Extract response stdout/output. Detect prompt-injection markers in the response: "system:", "<system>", "ignore", "<![CDATA[". Emit audit record with kind='untrusted-content', source=ctx.tool, marker_count. Always allow.
- Tests: emits no markers on benign content; emits markers on suspect content; non-string response -> allow.

### Task 5: disable-all-hooks-detector
- SessionStart and PreToolUse, matchers `['*']`, threat `T-012-mdm-bypass`, severity scalar `'warn'` (passive per ADR-0003), profiles all 3, timeout 1500.
- Logic: read `${ctx.paths.home}/.claude/settings.local.json` if exists. Parse JSON. Check for `disableAllHooks === true`. If found, return warn with evidence `{ kind: 'disableAllHooks-bypass', settings_local_path }`. Always passive (warn only, never block).
- Tests: returns allow if file missing; returns warn if file contains disableAllHooks:true; returns allow if file lacks the flag; uses CCSEC_LOCAL_SETTINGS_PATH env override.

### Task 6: local-settings-precedence-checker
- SessionStart, matchers `['*']`, threat `T-013-settings-precedence`, severity `{baseline:'warn', strict:'warn', regulated:'block'}`, profiles all 3, timeout 1500.
- Logic: detect when `.claude/settings.local.json` exists alongside the managed settings.json. Per spec, local settings take precedence over user but not managed (per docs); but issue #26637 shows the precedence is broken. The hook flags presence as a warn baseline+strict, block on regulated.
- Tests: returns allow if file missing; returns warn baseline; returns block regulated (test by calling run() directly and checking the runner's profile-severity resolution would land on block - but in the test we just assert decision='block' from run() and trust the runner; OR we test that severity record has the right values).

### Task 7: subagent-spawn-guard
- SubagentStart, matchers `['*']`, threat `T-011-subagent-escape`, severity `{baseline:'warn', strict:'block', regulated:'block'}`, profiles all 3, timeout 1500.
- Logic: emit warn/block on every subagent spawn unless ctx.input.subagent_type is in an allowlist. Allowlist read from settings or env (CCSEC_AGENT_ALLOWLIST as comma-separated string).
- Tests: blocks unauthorized subagent_type; allows allowlisted; manifest validity; allows if no input.subagent_type field.

### Task 8: task-tool-input-guard
- PreToolUse, matchers `['Task']`, threat `T-011-subagent-escape`, severity scalar `'block'`, profiles all 3, timeout 1500.
- Logic: scan ctx.input.prompt and ctx.input.description for prompt-injection patterns OR for instructions to "spawn", "delegate", "ignore policy" without proper context.
- Tests: blocks suspicious prompts; allows benign Task invocations.

### Task 9: agent-allowlist-enforcer
- SubagentStart, matchers `['*']`, threat `T-011-subagent-escape`, severity `{baseline:'log', strict:'log', regulated:'block'}`, profiles all 3, timeout 1500.
- Logic: same as subagent-spawn-guard but stricter on regulated. Cross-references against an explicit allowlist; emits log/log/block per profile.
- Tests: emits log on allowlisted; emits log on unallowlisted (baseline+strict); blocks on regulated.

---

## Task 10: Overlays + Rules Package + Profile Differentiation + Snapshots

**New overlays:**
- `packages/settings/overlays/behavioral.json` (claude-md, behavioral-rule-enforcer, untrusted-content-tagger)
- `packages/settings/overlays/mdm-bypass.json` (disable-all-hooks-detector, local-settings-precedence-checker)
- `packages/settings/overlays/agent-gating.json` (subagent-spawn-guard, task-tool-input-guard, agent-allowlist-enforcer)

**New package: `packages/rules/`**
- `package.json`: `@bitsummit/ccsec-rules`, type module, files include templates/.
- `templates/baseline.md`: minimal CLAUDE.md hardening rules.
- `templates/strict.md`: baseline + structural-bash + branch-guard rules.
- `templates/regulated.md`: strict + MDM bypass disclosures + agent allowlist.
- `templates/snippets/no-eval.md`, `no-curl-pipe-shell.md`, `no-force-push.md`, etc. (reusable building blocks).

**Profile differentiation:**

`profiles/baseline.json`:
```json
{ "extends": ["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths", "overlays/bash-structural", "overlays/branch-guards", "overlays/network-egress", "overlays/audit", "overlays/behavioral"], "overrides": {} }
```

`profiles/strict.json`:
```json
{
  "extends": ["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths", "overlays/bash-structural", "overlays/branch-guards", "overlays/network-egress", "overlays/audit", "overlays/behavioral", "overlays/agent-gating"],
  "overrides": {
    "audit": { "egress_allowlist": ["docs.anthropic.com", "github.com", "registry.npmjs.org", "pypi.org"] }
  }
}
```

`profiles/regulated.json`:
```json
{
  "extends": ["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths", "overlays/bash-structural", "overlays/branch-guards", "overlays/network-egress", "overlays/audit", "overlays/behavioral", "overlays/agent-gating", "overlays/mdm-bypass"],
  "overrides": {
    "audit": { "egress_allowlist": ["docs.anthropic.com", "github.com"] }
  }
}
```

The compiler needs to handle the `overrides.audit.egress_allowlist` correctly - the compiler currently only handles `permissions.deny`, `permissions.allow`, and `hooks`. It needs to also propagate `audit` and other top-level keys from overrides (and from extended fragments). Look at the compiler's `mergeFragments` function in `packages/cli/src/compiler.ts` and ensure top-level keys other than permissions/hooks are correctly propagated. If not, add that logic.

Specifically: extends fragment's `audit.egress_allowlist` should be merged into target's `audit` block; then overrides' `audit.egress_allowlist` should REPLACE rather than concatenate.

If the compiler doesn't currently handle this, this task includes a tiny compiler fix.

Build cli; regenerate all 3 compiled snapshots (each will now be DIFFERENT). Update snapshot test (already covers all 3) via `vitest -u`. Verify clean.

Commit (multiple commits OK):
- `feat(rules): @bitsummit/ccsec-rules with CLAUDE.md hardening templates`
- `feat(settings): behavioral, mdm-bypass, agent-gating overlays`
- `feat(cli): compiler propagates non-permissions/hooks top-level keys (audit etc.)`
- `feat(settings): real strict/regulated profile differentiation with tighter egress`

---

## Task 11: Integration Transcripts + Threat Model + CHANGELOG

4 new transcripts:
- `behavioral-bypass-attempt.json`: prompts with injection patterns; tool output with system tags
- `mdm-bypass-attempt.json`: file-system fixture with `.claude/settings.local.json` containing `disableAllHooks:true`; expects warn
- `subagent-escape-attempt.json`: Task with un-allowlisted subagent_type; Task with prompt-injection
- `regulated-profile-end-to-end.json`: replays the Plan 4 attack-chain under profile=regulated; verifies stricter outcomes

For mdm-bypass-attempt the test must create a temp file at `<HOME>/.claude/settings.local.json` with the bypass flag and set `CCSEC_LOCAL_SETTINGS_PATH` env to point the hook at it.

Update threat model with T-010, T-011, T-012, T-013, T-018; mark all coverage complete or note partial.

Update coverage matrix with new threat rows.

Append CHANGELOG `[0.5.0-beta.0] - 2026-04-29` block listing all 8 hooks, rules package, overlay/profile changes, threat ID cleanup, and **NOTE: this is the first beta** (hook surface complete; remaining plans are distribution, deployment, docs, release-eng, pilot).

Commits:
- `test(integration): behavioral, mdm-bypass, subagent-escape, regulated-end-to-end transcripts`
- `docs: T-010/T-011/T-012/T-013/T-018 added; CHANGELOG v0.5.0-beta.0`

---

## Task 12: Final Checks + Tag v0.5.0-beta.0 + Push + Release

Same procedure as Plans 1-4. Tag is `v0.5.0-beta.0` (beta, not alpha).

Release notes emphasize:
- 8 hooks landed; 26 total
- Profile differentiation now real
- All 18 documented threats have stated coverage
- Phase 1 hook surface complete; Plans 6-10 are distribution + docs + release-eng

Plan 5 sealed. Project moves from `alpha` to `beta`.

---

## Self-Review

- Spec coverage: every section of spec maps to a task.
- Backward compat: Plans 1-4 hooks must still pass.
- Profile differentiation snapshots will now diverge across baseline/strict/regulated.
