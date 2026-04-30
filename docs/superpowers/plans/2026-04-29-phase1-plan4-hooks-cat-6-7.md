# Phase 1 / Plan 4: Hooks Categories 6-7 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Add 4 hooks (2 egress + 2 audit), harden the audit logger (write queue + verify safety), ship `v0.4.0-alpha.0`.

**Architecture:** Builds on Plans 1-3. Egress hooks gate WebFetch and Bash curl/wget against an allowlist with deny-by-default posture. Audit hooks add tamper detection and session summaries. Audit-logger hardening closes the in-process concurrency race noted by Plan 1 review.

**Tech Stack:** unchanged.

**Predecessor:** `19c73a7` (Plan 3 CHANGELOG entry; v0.3.0-alpha.0 tagged).

---

## Conventions (unchanged from Plans 2-3)

- Working dir `/Users/haseebminhas/Projects.DEV/Claude-Code-Security/`
- TDD: failing test first.
- No em dashes; no Claude footers; no `git push` until Task 10.

---

## Task 1: Audit-Logger Hardening

**Files:** `packages/core/src/audit-logger.ts`, `packages/core/tests/audit-logger.test.ts`

- [ ] Append failing tests:
  - **concurrent writes serialize correctly**: fire 5 `logger.write()` calls in parallel; expect chain to remain valid (verify returns ok=true).
  - **verify on missing file returns `{ok:true, records:0}`** (not throw).
  - **verify on file with invalid JSON line returns `{ok:false, brokenAt:N}`** (not throw).
  - **loadLastHash on corrupted last line starts new chain** (returns undefined, does not crash).

- [ ] Run, expect 4 NEW failures (existing 6 pass).

- [ ] Update `audit-logger.ts`:
  - Add `private pending: Promise<void> = Promise.resolve();` field.
  - Wrap `write(input)` body so it awaits `this.pending`, then sets `this.pending = (async () => { /* original body */ })();` and returns that promise. This serializes concurrent writes.
  - In `verify()`: wrap `await readFile` in try/catch; on ENOENT return `{ ok: true, records: 0 }`. Wrap each `JSON.parse(line)` in try/catch; on failure return `{ ok: false, records: lines.length, brokenAt: i }` with reason field.
  - In `loadLastHash()`: keep current try/catch but log to `console.warn` if parse fails (so corruption is visible).

- [ ] Run, all 10 tests PASS.

- [ ] Commit: `feat(core): audit-logger in-process write queue and safer verify`

---

## Task 2: webfetch-egress-guard Hook (TDD)

- Manifest: PreToolUse, matchers `['WebFetch']`, threat `T-005-network-exfil`, severity scalar `'block'`, profiles all 3, timeout 1500.
- Logic: read `ctx.input.url`. Parse hostname via `new URL()`. Allowlist (hardcoded for Plan 4; later plans can read from settings):
  ```ts
  const ALLOWLIST = new Set(['docs.anthropic.com', 'github.com', 'raw.githubusercontent.com', 'api.github.com', 'developer.mozilla.org', 'nodejs.org', 'registry.npmjs.org', 'pypi.org']);
  ```
  Block if hostname is not in allowlist OR matches IP-literal pattern OR matches DoH hosts (`cloudflare-dns.com`, `dns.google`, etc.).
- Tests: allows docs.anthropic.com; allows github.com; blocks evil.com; blocks IP literal `https://1.2.3.4/`; blocks `https://cloudflare-dns.com/dns-query`; manifest validity; non-string url -> allow; malformed url -> block (suspicious).

Commit: `feat(hooks): webfetch-egress-guard with deny-by-default allowlist`

---

## Task 3: bash-egress-guard Hook (TDD)

- Manifest: PreToolUse, matchers `['Bash']`, threat `T-005-network-exfil`, severity `{baseline:'warn', strict:'block', regulated:'block'}`, profiles all 3, timeout 1500.
- Logic: detect curl/wget/fetch invocations in command. Extract URLs. Use the same allowlist as webfetch-egress-guard. Plus heuristics:
  - IP literal in URL: block.
  - `pastebin.com`, `transfer.sh`, `requestbin.com`, `paste.ee`: block (always; even if they were in allowlist).
  - DoH hosts: block.
  - Base64-encoded URL heuristic: command contains a long string starting with `aHR0c` (decodes to `http`): block.
- Tests: warn (baseline) on `curl evil.com`; allow `curl github.com`; block (always) on `curl pastebin.com/raw/x`; block on `wget 1.2.3.4`; block on `curl https://cloudflare-dns.com/dns-query`; block on base64 heuristic.

Commit: `feat(hooks): bash-egress-guard for curl/wget/fetch with allowlist and exfil-target denylist`

---

## Task 4: audit-tamper-detector Hook (TDD)

- Manifest: PostToolUse, matchers `['*']` (any tool), threat `T-015-audit-tampering`, severity `{baseline:'warn', strict:'block', regulated:'block'}`, profiles all 3, timeout 2000 (verify can scan whole log).
- Logic: read audit log path from `ctx.env?.CCSEC_AUDIT_LOG_PATH || \`${ctx.paths.home}/.claude/ccsec-audit.jsonl\``. Call `AuditLogger.verify(path)`. If `ok: false`, return block with evidence `{ broken_at: result.brokenAt, total_records: result.records }`. If `ok: true`, return allow.
- Tests: returns allow on intact log; returns block on tampered log; returns allow on missing log; uses CCSEC_AUDIT_LOG_PATH env override.

Commit: `feat(hooks): audit-tamper-detector verifying log chain on every PostToolUse`

---

## Task 5: audit-session-summary Hook (TDD)

- Manifest: SubagentStop, matchers `['*']`, threat `T-017-repudiation`, severity scalar `'log'`, profiles all 3, timeout 2000.
- Logic: read audit log path same way as audit-tamper-detector. Read all records since the session start (use `ctx.env?.CCSEC_SESSION_START_TS` or fall back to "all records in current file"). Aggregate counts: total records, by hook, by decision, total duration. Emit a single new audit record via `AuditLogger.write` with `{ hook: 'audit-session-summary', tool: 'session', decision: 'log', reason: 'session summary', evidence_digest: <count + decision summary> }`. Return `{ decision: 'allow', reason: 'summary emitted', evidence: <stats> }`.
- Tests: returns allow; emits a summary record (verify by reading log after); evidence includes hook count and decision count.

Commit: `feat(hooks): audit-session-summary aggregating session stats on SubagentStop`

---

## Task 6: New Overlays

- Create `packages/settings/overlays/network-egress.json` (full content in spec section 3.1)
- Create `packages/settings/overlays/audit.json` (full content in spec section 3.1)

Commit: `feat(settings): network-egress and audit overlays`

---

## Task 7: Profile Wiring + Compiled Snapshots

- Update each of `profiles/baseline.json`, `strict.json`, `regulated.json` to extend the new overlays:
  ```json
  { "extends": ["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths", "overlays/bash-structural", "overlays/branch-guards", "overlays/network-egress", "overlays/audit"], "overrides": {} }
  ```
- Build cli; regenerate all 3 compiled snapshots; refresh snapshot file via `vitest -u`; verify clean.

Commit: `feat(settings): wire network-egress + audit overlays into all profiles`

---

## Task 8: Integration Transcripts (3 new)

Create:
- `tests/integration/transcripts/webfetch-exfil-attempt.json` (4 events: allowlisted allow, non-allow block, pastebin block, IP literal block)
- `tests/integration/transcripts/bash-egress-attempt.json` (4 events: allowlisted warn, pastebin block, IP block, DoH block)
- `tests/integration/transcripts/audit-tamper-attempt.json` (sequence: write a record, mutate the file, expect audit-tamper-detector to fire on next PostToolUse)

Plus matching test files. Each imports all 18 hooks (1+7+6+4) from dist. Set `HOME=/Users/x` in beforeAll.

Build hooks dist; run integration tests:
```bash
pnpm --filter @bitsummit/ccsec-core build
pnpm --filter @bitsummit/ccsec-hooks build
pnpm vitest run tests/integration/
```
Expected: 11 tests pass (8 prior + 3 new).

Commit: `test(integration): webfetch-exfil, bash-egress, audit-tamper transcripts`

---

## Task 9: Threat Model + Coverage Matrix + CHANGELOG

Update `docs/threat-model.md`:
- T-005 status fully-covered with the 2 egress hooks + deny patterns
- Add T-014 Tool Spoofing via MCP (vector: MCP; STRIDE: Spoofing; Agentic: A8 proxy; mitigation: noted as partial; full coverage in later plan)
- Add T-015 Audit Log Tampering (vector: FS; STRIDE: Tampering; Agentic: A6; mitigation: audit-tamper-detector + hash chain + verify())
- Add T-017 Repudiation of Risky Action (vector: any; STRIDE: Repudiation; Agentic: A6; mitigation: audit-session-summary + full audit log)
- Add T-016 Hook DoS / Runaway Timeout (already covered in Plan 1's runner; documented here for completeness)

Update `docs/coverage-matrix.md` with the new threats.

Insert above existing `[0.3.0-alpha.0]`:

```markdown
## [0.4.0-alpha.0] - 2026-04-29

### Added
- 4 new hooks: `webfetch-egress-guard`, `bash-egress-guard`, `audit-tamper-detector`, `audit-session-summary`.
- New overlays: `overlays/network-egress.json` and `overlays/audit.json`.
- Integration transcripts: webfetch-exfil-attempt, bash-egress-attempt, audit-tamper-attempt.
- Threat model entries: T-005 fully covered, T-014 Tool Spoofing via MCP (partial), T-015 Audit Log Tampering, T-017 Repudiation of Risky Action.

### Changed
- `AuditLogger.write()` now serializes concurrent in-process writes via an internal promise queue; closes the race noted in Plan 1 review.
- `AuditLogger.verify()` returns `{ ok: true, records: 0 }` on missing file (was throwing) and `{ ok: false, brokenAt: i }` on JSON-parse failure (was throwing).
- All 3 profiles extend the network-egress and audit overlays.

### Notes
- Cross-process audit log safety still tracked for a future plan (per-PID files or flock; not in v0.4).
- Strict / regulated profile differentiation still tracked for Plan 5.
- Plugin / npm distribution still tracked for Plan 6.
```

Commit: `docs: T-014/T-015/T-017 added; T-005 fully covered; v0.4.0-alpha.0 changelog`

---

## Task 10: Final Checks + Tag + Push + Release

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm build
pnpm test -- --coverage
bats installers/macos/tests/install.bats
TMPHOME=$(mktemp -d)
HOME=$TMPHOME ./installers/macos/install.sh --profile baseline --claude-dir "$TMPHOME/.claude"
HOME=$TMPHOME ./installers/macos/verify.sh --claude-dir "$TMPHOME/.claude"
rm -rf "$TMPHOME"
git tag -a v0.4.0-alpha.0 -m "v0.4.0-alpha.0: network egress + audit hardening"
git push origin main
git push origin v0.4.0-alpha.0
```

Then `gh release create v0.4.0-alpha.0 --repo Bitsummit-Corp/claude-code-governance --title "v0.4.0-alpha.0 - Network Egress + Audit Hardening" --notes-file <notes> --prerelease`. Notes summarize the 4 hooks, audit-logger hardening, and threats covered.

Plan 4 sealed.

---

## Self-Review

- All spec sections map to tasks.
- No placeholders.
- Plan 1+2+3 backward compat preserved (existing tests must still pass).

## Plan Complete

After Task 10, Plan 5 (behavioral + MDM bypass + agent gating + strict/regulated differentiation) is next.
