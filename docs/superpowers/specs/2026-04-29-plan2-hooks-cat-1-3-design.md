# Design: Plan 2 - Hooks Categories 1-3 (Secrets, Destructive, Sensitive Paths)

**Status:** Draft, awaiting user review
**Date:** 2026-04-29
**Owner:** Haseeb Minhas (BITSUMMIT)
**Parent spec:** `docs/superpowers/specs/2026-04-29-claude-code-security-repo-design.md`
**Plan target tag:** `v0.2.0-alpha.0`
**Predecessor plan:** Plan 1 foundation walking skeleton (`v0.1.0-alpha.0` shipped)

---

## 1. Purpose & Scope

Plan 2 is the second of ten plans in Phase 1. It adds hooks for categories 1-3 of the parent spec (secrets, destructive operations, sensitive paths) on top of the foundation laid by Plan 1.

**In scope:**

- 7 new hooks (3 secrets + 2 destructive + 2 paths)
- Expanded `overlays/secrets.json`, new `overlays/destructive.json`, new `overlays/sensitive-paths.json`
- `profiles/strict.json` and `profiles/regulated.json` shells (content identical to baseline for now; Plan 5 differentiates)
- 4 new integration test transcripts (3 threat-level + 1 attack-chain)
- Threat model expansion: T-002, T-003, T-004 documented; T-001 expanded
- New coverage matrix doc
- Manifest contract bumps: per-profile severity, matcher wildcards, PostToolUse `response` field
- One new ADR documenting the contract bumps

**Explicitly out of scope:**

- Egress / WebFetch allowlist (Plan 4)
- Structural-bash hook using the existing parser (Plan 3)
- Real strict/regulated profile differentiation (Plan 5)
- Hook config / per-user overrides (Plan 6)
- Plugin / npm distribution (Plan 6)
- Auto-generation of coverage matrix and hook docs (Plan 8)

---

## 2. Hook List & Manifests

Allocation A from brainstorming: 3 secret hooks + 2 destructive + 2 path-related.

| Hook | Event | Matchers | Threat | Severity | Profiles |
|---|---|---|---|---|---|
| `secret-leak-detector` | PostToolUse | Bash, Read | T-001-secret-leak | block | baseline, strict, regulated |
| `keychain-guard` | PreToolUse | Bash | T-001-secret-leak | block | baseline, strict, regulated |
| `mcp-secret-guard` | PreToolUse | mcp__* (wildcard) | T-001-secret-leak | block | baseline, strict, regulated |
| `destructive-fs-guard` | PreToolUse | Bash | T-002-destructive-fs | block | baseline, strict, regulated |
| `git-destructive-guard` | PreToolUse | Bash | T-004-branch-sabotage | warn / block / block | baseline, strict, regulated |
| `sensitive-paths-guard` | PreToolUse | Read, Bash | T-003-credential-exfil | block | baseline, strict, regulated |
| `dotfile-guard` | PreToolUse | Edit, Write | T-002-destructive-fs (persistence) | warn / block / block | baseline, strict, regulated |

### 2.1 Behavioral notes

**`secret-leak-detector`** scans `tool_response.stdout`/`stderr`/`output` using `detectSecrets` from `@bitsummit/ccsec-core`. Blocks if any pattern hits. Returns redacted evidence. PostToolUse semantics: block here surfaces as a warning record in audit since the tool already ran; main use is forensics + alerting that a leak occurred.

**`keychain-guard`** narrows the existing broad `Bash(security find-generic-password *)` deny rule. The deny pattern stays as a backstop. The hook specifically blocks invocations containing the value-printing flags (the only flags that print raw secrets to stdout). Existence-checks (no flag, or `-a`/`-s`) are allowed through, removing false-positive friction for legitimate keychain CLI usage.

**`mcp-secret-guard`** runs on any tool whose name starts with `mcp__`. Scans `tool.input` for secret patterns using `detectSecrets`. Blocks if any pattern hits. Defends against secrets being passed as arguments to MCP servers (which may log or persist them).

**`destructive-fs-guard`** matches a curated list of destructive Bash patterns: recursive removal of root or HOME, `mkfs *`, `dd if=* of=/dev/*`, `shred -u`, `chmod 000` on root, etc. Blocks. Specific safe patterns (`rm -rf /tmp/foo`) pass through.

**`git-destructive-guard`** matches `git reset --hard *`, `git clean -fd`, `git branch -D <protected>`, `git push --force *`, `git push -f *`, `git rebase -i HEAD~*`, `git commit --amend` on already-pushed commits. Severity is per-profile: baseline warns, strict and regulated block. The "warn" outcome on baseline is a real notification (audit log entry) but does not block the operation.

**`sensitive-paths-guard`** is a hook-side belt-and-suspenders for the deny patterns in `secrets.json` and `sensitive-paths.json`. Blocks any Read or Bash whose target resolves to a path inside `${SSH}`, `${AWS}`, `${KEYS}`, or the additional sensitive paths declared in the overlay. Provides better evidence (named match) than the deny-pattern engine alone.

**`dotfile-guard`** matches Edit and Write to shell rc files (`.zshrc`, `.bashrc`, `.bash_profile`, `.profile`), git config files (`.gitconfig`, `.git/config`), and SSH config (`.ssh/config`). Threat is persistence (modifying these enables PATH injection, alias hijack, automatic key trust). Severity per-profile: baseline warns, strict and regulated block.

### 2.2 Per-profile severity contract

The `HookManifest.severity` field becomes:

```ts
type HookSeverity = "block" | "warn" | "log";
type ProfileSeverity = HookSeverity | Record<HookProfile, HookSeverity>;
```

A scalar value applies to all profiles. A record keys per profile. Validator (zod) accepts both. Runner consults the active profile to resolve the effective severity. This sets the pattern for all future per-profile severity tuning (Plan 5 will use it heavily).

### 2.3 Matcher wildcard convention

The `HookManifest.matchers` array gains support for two glob-like patterns:

- `*` matches any tool name (use sparingly; intended for future audit-only hooks)
- `<prefix>*` matches any tool whose name starts with `<prefix>` (used by `mcp-secret-guard` with `mcp__*`)

Implementation: replace `matchers.includes(tool)` with a small helper `matchesAny(tool, matchers)` that handles plain equality, `*`, and prefix-with-trailing-`*`. No full glob library is needed.

---

## 3. Settings Templates

### 3.1 `packages/settings/overlays/secrets.json` (expand)

Deny rules unchanged from Plan 1. Hook references gain `keychain-guard` and `mcp-secret-guard` on PreToolUse, plus a new PostToolUse entry for `secret-leak-detector`.

### 3.2 `packages/settings/overlays/destructive.json` (new)

Deny patterns for destructive Bash variants and forced git pushes. Hook references for `destructive-fs-guard` and `git-destructive-guard`.

### 3.3 `packages/settings/overlays/sensitive-paths.json` (new)

Deny patterns for `${HOME}/.kube/**`, `${HOME}/.docker/config.json`, `${HOME}/.netrc`, `${HOME}/.config/gh/hosts.yml`, `/etc/sudoers`, `/etc/sudoers.d/**`. Hook references for `sensitive-paths-guard` and `dotfile-guard`.

Note: `${HOME}/.ssh/**`, `${HOME}/.aws/credentials`, `${HOME}/.gnupg/**` remain in `secrets.json` overlay (not duplicated).

### 3.4 Profiles

- `profiles/baseline.json` extends `["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths"]`
- `profiles/strict.json` (new) extends the same set; content identical to baseline for now
- `profiles/regulated.json` (new) extends the same set; content identical to baseline for now

Per-hook severity overrides (e.g., `git-destructive-guard` warn-on-baseline / block-on-strict) live in the hook manifest, not in the profile JSON.

### 3.5 Compiled snapshots

- `compiled/baseline.json` regenerated to include the new overlays
- `compiled/strict.json` (new)
- `compiled/regulated.json` (new)
- Snapshot test extended to cover all three; drift detection fails CI on any unintended change

---

## 4. Test Corpus Expansion

Four new transcripts in `tests/integration/transcripts/`:

### 4.1 `secret-leak-postonly.json`

Exercises PostToolUse path. PreToolUse passes a benign-looking command; tool output contains an AWS key. `secret-leak-detector` fires.

### 4.2 `destructive-attempt.json`

Three Bash commands: a safe `rm -rf /tmp/x` (allowed), a dangerous recursive removal of HOME (blocked), a forced git push (blocked by deny + warn from `git-destructive-guard` on baseline).

### 4.3 `sensitive-paths-attempt.json`

Read attempts on `${HOME}/.ssh/id_rsa`, `${HOME}/.kube/config`, `${HOME}/.netrc`, plus an Edit on `${HOME}/.zshrc` (`dotfile-guard` warns on baseline).

### 4.4 `attack-chain.json`

Multi-step blue-team scenario:

1. Bash: read AWS credentials and base64-encode them (blocked at the Read step)
2. Bash: pipe an STS session token to `curl -X POST` to an attacker domain (Plan 2 partial: secret-leak-detector catches the token in stdout; full egress block lands Plan 4)
3. Edit: append a malicious alias to `~/.zshrc` (`dotfile-guard` warns on baseline)
4. Bash: dump the entire environment via `printenv` (blocked by Plan 1 secret-guard's bare-env path)

The transcript fixture documents which steps Plan 2 fully blocks vs. partially catches; expectation file pins the Plan-2-current decisions and includes TODO markers for Plan 4 closure points.

---

## 5. Threat Model Expansion

`docs/threat-model.md` grows from 1 to 4 documented threats:

- T-001 Secret Leak via Tool Output (expanded coverage: PreToolUse + PostToolUse + MCP + keychain)
- T-002 Destructive Filesystem Op (new)
- T-003 Credential File Exfil (new)
- T-004 Force-Push / Branch Sabotage (new partial coverage; full branch-guard suite is Plan 3)

Each new threat gets the standard one-page format: vector, STRIDE, Agentic Top 10, default mitigation, coverage profiles, known limitations.

---

## 6. Coverage Matrix

`docs/coverage-matrix.md` (new) maps every hook manifest `threat` field to the threats register:

| Threat | Hooks | Profiles |
|---|---|---|
| T-001 | secret-guard, secret-leak-detector, keychain-guard, mcp-secret-guard | all |
| T-002 | destructive-fs-guard, dotfile-guard | all |
| T-003 | sensitive-paths-guard | all |
| T-004 | git-destructive-guard | baseline (warn), strict (block), regulated (block) |

Hand-maintained for Plan 2; auto-generation from manifests lands in Plan 8.

---

## 7. ADR-0004: Hook Contract Bumps

`docs/adr/0004-hook-contract-bumps-plan2.md` documents three additions to the Plan 1 contract:

1. **Per-profile severity** as `Record<HookProfile, HookSeverity>` alongside the scalar form. Why: Plan 2 has hooks (`git-destructive-guard`, `dotfile-guard`) where the right severity differs by profile, and forking the hook code per profile is worse than expressing the policy declaratively.
2. **Matcher wildcards** (`*` and `<prefix>*`). Why: `mcp-secret-guard` needs to match all MCP-prefixed tools without enumerating them; future audit-only hooks may need `*`.
3. **PostToolUse `response` field on `HookContext`**. Why: PostToolUse hooks need access to tool output; PreToolUse hooks have no use for it. Optional field is the cleanest backwards-compatible add.

The ADR explains alternatives considered (e.g., always-record severity, full glob library, separate PostToolUseContext type) and why they were rejected.

---

## 8. Plan 2 Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Manifest contract bumps could break external hooks | None exist (v0.1.0-alpha is internal); bumps are additive (scalar severity still works) |
| Runner changes might regress Plan 1 PreToolUse paths | All Plan 1 tests must still pass; CI gate enforces |
| MCP matcher pattern depends on Claude Code naming convention | Documented in hook docs page; flagged for monitoring |
| Compiled snapshot drift triples with 3 profiles | Snapshot tests cover all three; CI fails on unintended drift |
| `secret-leak-detector` performance on large stdouts | If scan exceeds 100ms on 1MB, add max-bytes guard (truncate to first 256KB and emit warning); test corpus exercises a large-output case |

---

## 9. Success Criteria

- `v0.2.0-alpha.0` tagged with all 7 hooks shipping
- Snapshot tests for 3 profiles all green
- 4 new transcript replays passing (with documented partial-block expectations on attack-chain)
- Coverage matrix doc exists and lines up with hook manifests
- ADR-0004 explains the contract bumps
- All Plan 1 tests pass unchanged (zero regressions)
- CI green on macos-14 runner
- New commit count: roughly one per hook (7) + overlays (3) + profiles (3) + ADR (1) + threat model expansion (1) + coverage matrix (1) + contract bump (1) + snapshot regen (1) + integration tests (1) + tag (1), approximately 20 commits

---

## 10. References

- [Parent spec](./2026-04-29-claude-code-security-repo-design.md)
- [Plan 1 plan doc](../plans/2026-04-29-phase1-plan1-foundation-walking-skeleton.md)
- [v0.1.0-alpha.0 release](https://github.com/Bitsummit-Corp/claude-code-governance/releases/tag/v0.1.0-alpha.0)
