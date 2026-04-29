# Coverage Matrix

> Hand-maintained for Plans 1-5. Auto-generation from hook manifests lands in Plan 8.

| Threat | Hooks | Profiles |
|---|---|---|
| T-001 Secret Leak | secret-guard, secret-leak-detector, keychain-guard, mcp-secret-guard | baseline, strict, regulated |
| T-002 Destructive FS | destructive-fs-guard, dotfile-guard | baseline (dotfile=warn), strict, regulated |
| T-003 Credential Exfil | sensitive-paths-guard | baseline, strict, regulated |
| T-004 Branch Sabotage | git-destructive-guard, branch-protection-guard, commit-amend-pushed-guard | baseline (warn), strict (block), regulated (block) |
| T-005 Network Exfil via WebFetch and Bash | webfetch-egress-guard, bash-egress-guard | baseline (bash-egress=warn, webfetch-egress=block), strict (block), regulated (block) |
| T-006 Pipe-to-Shell Remote Execution | pipe-to-shell-guard, bash-structural-guard | baseline (bash-structural=warn, pipe-to-shell=block), strict (block), regulated (block) |
| T-007 Command Chaining Bypass | bash-structural-guard (audit-only; chained_and/or/semicolon and leading_cd allowed by default) | baseline, strict, regulated (audit-only across profiles) |
| T-008 Git History Rewrite | git-history-rewrite-guard | baseline, strict, regulated |
| T-009 Arbitrary Code via eval / Command Substitution | bash-structural-guard | baseline (warn), strict (block), regulated (block) |
| T-010 Prompt Injection from Tool Output | behavioral-rule-enforcer, untrusted-content-tagger, claude-md-validator | baseline (claude-md=warn, others=log), strict (claude-md=block, others=log), regulated (claude-md=block, others=log) |
| T-011 Subagent Escape | subagent-spawn-guard, task-tool-input-guard, agent-allowlist-enforcer | baseline (task-input=block, spawn=warn, allowlist=log), strict (spawn=block, allowlist=log), regulated (allowlist=block) |
| T-012 MDM Bypass via disableAllHooks | disable-all-hooks-detector | baseline, strict, regulated (passive warn across profiles per ADR-0003) |
| T-013 Local Settings Overriding Managed | local-settings-precedence-checker | baseline (warn), strict (warn), regulated (block) |
| T-014 Tool Spoofing via MCP | mcp-secret-guard (partial; payload scan only) | baseline, strict, regulated (partial) |
| T-015 Audit Log Tampering | audit-tamper-detector + AuditLogger sha256 hash chain | baseline (warn), strict (block), regulated (block) |
| T-016 Hook DoS / Runaway Timeout | runner timeout enforcement (Plan 1) | baseline, strict, regulated |
| T-017 Repudiation of Risky Action | audit-session-summary + full audit log | baseline, strict, regulated |
| T-018 Supply Chain via Submodule (was T-013) | submodule-injection-guard | baseline, strict, regulated |

## Coverage by Profile

**baseline** (per-user dev hardening; some warns to keep flow):
- All blocking hooks: secret-guard, secret-leak-detector, keychain-guard, mcp-secret-guard, destructive-fs-guard, sensitive-paths-guard, pipe-to-shell-guard, submodule-injection-guard, git-history-rewrite-guard, webfetch-egress-guard, task-tool-input-guard
- Warn hooks: git-destructive-guard, dotfile-guard, branch-protection-guard, commit-amend-pushed-guard, bash-structural-guard, bash-egress-guard, audit-tamper-detector, claude-md-validator, disable-all-hooks-detector, local-settings-precedence-checker, subagent-spawn-guard
- Log-only hooks: audit-session-summary, behavioral-rule-enforcer, untrusted-content-tagger, agent-allowlist-enforcer

**strict** (team / shared infra; everything blocking that can be):
- Same hooks as baseline plus the agent-gating overlay (subagent-spawn-guard, task-tool-input-guard, agent-allowlist-enforcer)
- git-destructive-guard, dotfile-guard, branch-protection-guard, commit-amend-pushed-guard, bash-structural-guard, bash-egress-guard, audit-tamper-detector, claude-md-validator, subagent-spawn-guard upgrade to block
- audit.egress_allowlist tightened to 4 hosts (docs.anthropic.com, github.com, registry.npmjs.org, pypi.org)

**regulated** (healthcare, legal, public-sector):
- Same as strict plus the mdm-bypass overlay (disable-all-hooks-detector, local-settings-precedence-checker)
- local-settings-precedence-checker and agent-allowlist-enforcer upgrade to block
- audit.egress_allowlist tightened to 2 hosts (docs.anthropic.com, github.com)

## How to read this matrix

Each threat ID corresponds to a row in `docs/threat-model.md`. Each hook listed has a manifest declaring `threat: T-NNN-...` matching the row. The profiles column shows which profiles include the hook (per the hook's manifest `profiles` array) and at what effective severity (resolved per-profile).

When `docs/auto-coverage-matrix.md` ships in Plan 8, this hand-maintained file will be replaced by a CI-generated artifact backed by the same data.
