# Design: Plan 4 - Hooks Categories 6-7 (Network Egress, Audit)

**Status:** Locked autonomous-mode design
**Date:** 2026-04-29
**Plan target tag:** `v0.4.0-alpha.0`
**Predecessor:** Plan 3 (`v0.3.0-alpha.0`; 14 hooks total, 215 tests, 99.11% coverage)

---

## 1. Purpose & Scope

Plan 4 closes the egress-exfil and audit-trail integrity gaps. After Plan 4 the project has 18 hooks, 16 documented threats covered, and a hardened audit log.

**In scope:**

- 4 new hooks (2 egress + 2 audit)
- Bash-parser-side hardening: extended URL pattern detection (data exfil via DNS, base64-encoded URLs)
- New overlays: `network-egress.json`, `audit.json`
- Audit-logger hardening (Plan 1 advisory carryforward): in-process write queue, JSON.parse error handling in verify(), ENOENT semantics
- Updated profiles to extend new overlays
- 3 new integration transcripts: webfetch-exfil, dns-exfil, audit-tamper
- Threat model: T-005 (existing) + T-010 prompt injection from tool output, T-011 subagent escape (deferred to Plan 5), T-012 MDM bypass (Plan 5), T-014 MCP spoofing, T-015 audit log tampering
- Coverage matrix updated

**Out of scope:**

- Real strict/regulated profile differentiation (Plan 5)
- MDM bypass passive detector (Plan 5)
- Plugin/npm distribution (Plan 6)
- SIEM shipper (uncommitted backlog; not in Plan 4)
- Cross-process audit log safety (deferred to a future plan; Plan 4 ships single-process serialization only)

---

## 2. Hook List

| Hook | Event | Matchers | Threat | Severity |
|---|---|---|---|---|
| `webfetch-egress-guard` | PreToolUse | WebFetch | T-005-network-exfil | block all profiles |
| `bash-egress-guard` | PreToolUse | Bash | T-005-network-exfil | warn baseline / block strict+regulated |
| `audit-tamper-detector` | PostToolUse | * | T-015-audit-tampering | warn baseline / block strict+regulated |
| `audit-session-summary` | SubagentStop | * | T-017-repudiation | log all profiles (audit-only) |

### 2.1 Behavioral notes

**`webfetch-egress-guard`** matches the WebFetch tool. Reads an allowlist of domains from a settings field (`audit.egress_allowlist`) or hook config. Default allowlist (deny-by-default posture from parent spec): `docs.anthropic.com`, `github.com`, `raw.githubusercontent.com`, `api.github.com`, `developer.mozilla.org`, `nodejs.org`, `npmjs.com`, `pypi.org`. Block any URL whose hostname is not in the allowlist. Returns evidence including the rejected hostname.

**`bash-egress-guard`** matches Bash invocations of curl/wget/fetch and inspects the URL. Same allowlist as webfetch-egress-guard. Detects:
- Direct URLs in command (`curl https://x.com/api`)
- IP literals (treated as suspicious; always blocked regardless of allowlist)
- Pastebin / requestbin / transfer.sh patterns (always blocked even if hostname is in allowlist due to common exfil targeting)
- DNS-over-HTTPS endpoints (cloudflare-dns.com, dns.google, etc. - always blocked)
- Base64-encoded URLs (heuristic: long base64 string starting with `aHR0c` which decodes to `http`)

Per-profile severity: warn on baseline (egress is common in dev workflows; warn so users see the audit trail without breaking flow), block on strict+regulated.

**`audit-tamper-detector`** runs on every PostToolUse. Reads the audit log path from settings, calls `AuditLogger.verify(path)`, and if `verify` returns `ok: false` emits a warn/block. This catches situations where someone (or another process) modified the log file outside the runner. Per-profile severity.

**`audit-session-summary`** runs on `SubagentStop`. Aggregates the session's audit records (count by hook, count by decision, total duration) and emits a single audit record with `kind: 'session-summary'`. Decision is always `allow` (this is logging, not gating). Provides a single-record summary of what each subagent session did.

### 2.2 Audit-logger hardening (Plan 1 advisory carryforward)

In `packages/core/src/audit-logger.ts`:

1. **In-process write queue.** `AuditLogger` keeps a `private pending: Promise<void>` chained from each call. New writes await the previous one before reading `prevHash`, computing the new hash, appending. Closes the concurrency race noted by Plan 1 review.

2. **JSON.parse safety in verify().** Wrap each line's parse in try/catch. On parse failure, return `{ ok: false, brokenAt: i, reason: 'invalid_json' }`.

3. **ENOENT semantics in verify().** Catch ENOENT from `readFile` and return `{ ok: true, records: 0 }` to give callers a defined "no log yet" result.

4. **`loadLastHash` corruption awareness.** If the last line is unparseable, log a warning to stderr and return `undefined` (start a new chain) but DO NOT silently mask the problem - the next `verify()` will detect the broken line.

Cross-process safety is **NOT addressed in Plan 4**. Documented as a Plan-future-stage concern in the threat model.

---

## 3. Settings

### 3.1 New overlays

**`overlays/network-egress.json`**:

```json
{
  "permissions": {
    "deny": [
      { "pattern": "WebFetch(*pastebin.com*)",     "threat": "T-005-network-exfil" },
      { "pattern": "WebFetch(*paste.ee*)",         "threat": "T-005-network-exfil" },
      { "pattern": "WebFetch(*requestbin.com*)",   "threat": "T-005-network-exfil" },
      { "pattern": "WebFetch(*transfer.sh*)",      "threat": "T-005-network-exfil" },
      { "pattern": "Bash(curl * pastebin.com*)",   "threat": "T-005-network-exfil" },
      { "pattern": "Bash(curl * transfer.sh*)",    "threat": "T-005-network-exfil" },
      { "pattern": "Bash(curl https://[0-9]*)",    "threat": "T-005-network-exfil" },
      { "pattern": "Bash(wget https://[0-9]*)",    "threat": "T-005-network-exfil" }
    ],
    "allow": []
  },
  "audit": {
    "egress_allowlist": [
      "docs.anthropic.com",
      "github.com",
      "raw.githubusercontent.com",
      "api.github.com",
      "developer.mozilla.org",
      "nodejs.org",
      "registry.npmjs.org",
      "pypi.org"
    ]
  },
  "hooks": {
    "PreToolUse": [
      { "name": "webfetch-egress-guard" },
      { "name": "bash-egress-guard" }
    ]
  }
}
```

**`overlays/audit.json`**:

```json
{
  "audit": {
    "verify_on_session_start": true
  },
  "hooks": {
    "PostToolUse": [
      { "name": "audit-tamper-detector" }
    ],
    "SubagentStop": [
      { "name": "audit-session-summary" }
    ]
  }
}
```

### 3.2 Profiles

baseline / strict / regulated all extend `["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths", "overlays/bash-structural", "overlays/branch-guards", "overlays/network-egress", "overlays/audit"]` (Plan 5 will start differentiating).

### 3.3 Compiled snapshots

Regenerate all 3.

---

## 4. Test Corpus

3 new integration transcripts:

1. **`webfetch-exfil-attempt.json`** - WebFetch to allowlisted domain (allow), to non-allowlisted (block by webfetch-egress-guard), to pastebin (block by deny pattern), to IP literal (block).
2. **`bash-egress-attempt.json`** - curl to allowlisted (warn on baseline), wget to pastebin (block by deny + warn from bash-egress-guard), curl to IP literal (block), DNS-over-HTTPS to dns.google (block).
3. **`audit-tamper-attempt.json`** - simulates a tampered audit log: writes a record, mutates the file outside the runner, expects `audit-tamper-detector` to flag on the next PostToolUse.

---

## 5. Threat Model Expansion

`docs/threat-model.md` adds:
- **T-005 Network Exfil via WebFetch** (already mentioned; now fully covered with webfetch-egress-guard, bash-egress-guard, deny patterns)
- **T-014 Tool Spoofing via MCP** - partial coverage. Documented; full mitigation deferred to a later plan.
- **T-015 Audit Log Tampering** - audit-tamper-detector catches in-runner detection; cross-process tampering noted as out-of-scope for Plan 4.
- **T-017 Repudiation of Risky Action** - audit-session-summary provides a forensic record per subagent session.
- **T-016 Hook DoS / Runaway Timeout** - already mitigated in Plan 1's runner with timeout enforcement; documented here for completeness.

Coverage matrix updated.

---

## 6. Implementation Sequence (10 tasks)

1. Audit-logger hardening (write queue + verify safety + ENOENT)
2. webfetch-egress-guard hook
3. bash-egress-guard hook
4. audit-tamper-detector hook
5. audit-session-summary hook
6. New overlays (network-egress + audit)
7. Profile wiring + compiled snapshot regen
8. 3 integration transcripts + tests
9. Threat model + coverage matrix update + CHANGELOG
10. Final checks + tag + push + GitHub release

---

## 7. Success Criteria

- v0.4.0-alpha.0 tagged with all 4 hooks shipping
- Audit-logger concurrent-write tests pass (in-process serialization works)
- 11 integration tests pass (8 prior + 3 new)
- Snapshot tests for 3 profiles still green
- All Plan 1-3 tests pass unchanged
- Coverage stays >= 90%

---

## 8. References

- [Parent spec](./2026-04-29-claude-code-security-repo-design.md)
- [Plan 3 plan](../plans/2026-04-29-phase1-plan3-hooks-cat-4-5.md)
- [v0.3.0-alpha.0 release](https://github.com/Bitsummit-Corp/claude-code-security/releases/tag/v0.3.0-alpha.0)
