# Design: claude-code-security - Open-Source Hardening Reference for Claude Code

**Status:** Draft, awaiting user review
**Date:** 2026-04-29
**Owner:** Haseeb Minhas (BITSUMMIT)
**License:** MIT
**Repo (proposed):** `github.com/bit-haseebminhas/claude-code-security` (or BITSUMMIT-org)

---

## 1. Purpose & Positioning

A public, BITSUMMIT-stewarded reference repository that lets individual developers harden their own Claude Code installs and lets enterprises deploy a vetted security policy via MDM. The repo bundles a hooks library, layered settings templates, behavioral CLAUDE.md rules, multi-channel installers, and a documented threat model.

The unique value vs. existing public projects (yurukusa/cc-safe-setup, pixelitobenito's gist, etc.) is the **enterprise/MDM track plus the documented bypass surface** - specifically passive detection of the `disableAllHooks` bypass described in [anthropics/claude-code#26637](https://github.com/anthropics/claude-code/issues/26637). Most public hooks repos optimize for solo autonomous-dev safety; this one targets regulated and managed-endpoint environments while still serving solo devs.

**In scope:**

- Per-user hardening kit (devs)
- MDM deployment package (IT admins)
- Threat model, deployment guides, audit log format
- Three distribution channels: Claude Code plugin, npm, raw repo

**Explicitly out of scope:**

- Sandboxing or runtime jailing
- Active monitoring daemons / SIEM-shipping daemons
- Auto-remediation of tampered settings
- Hosted service / SaaS dashboard
- Custom MCP servers
- Per-client paid customization service

---

## 2. Architectural Decisions (Locked)

| Axis | Decision | Rationale |
|---|---|---|
| Audience | Layered: per-user kit + MDM enterprise package | Single repo, two install paths, shared hooks library |
| Hook implementation language | Node.js | Claude Code already ships Node; cross-platform with one codebase |
| Platform coverage (v1) | macOS first; Windows + Linux installers in v1.1 / v1.2 | Hook library cross-platform from day one; installer plumbing phased |
| Enforcement posture | Passive only - no daemon, no auto-remediation, no SIEM coupling | Explicit user choice; keeps repo a *reference*, not a *product* |
| Hook coverage breadth | "Security + governance" - categories 1-10, ~25 hooks | Differentiates from commodity hardening (1-7) without diluting into productivity hooks |
| Distribution channels | npm + Claude Code plugin + raw repo (3 channels, 1 source) | Plugin for marketplace discoverability; npm for CI; raw for MDM admins |
| License | MIT | Maximum adoption; standard for security reference repos |

---

## 3. Repo Layout

```
claude-code-security/
├── packages/
│   ├── core/                    # Hook runner, schema validation, OS path resolver, structural-bash parser, secret patterns, JSONL audit logger
│   ├── hooks/                   # ~25 hooks (Node modules, one per concern)
│   ├── settings/                # Versioned base + overlays + 3 profiles
│   ├── rules/                   # CLAUDE.md hardening templates
│   ├── plugin/                  # Claude Code plugin manifest + glue
│   └── cli/                     # `ccsec` CLI: apply, doctor, audit, lint, compile, verify
├── installers/
│   ├── macos/                   # bash installer, Jamf profile template, verify.sh
│   ├── windows/                 # v1.1 - PowerShell installer, Intune ADMX, MSI
│   └── linux/                   # v1.2 - shell installer, Ansible role, .deb/.rpm
├── docs/
│   ├── threat-model.md
│   ├── deployment/              # per-OS, per-channel guides
│   ├── hooks/                   # auto-generated, one page per hook
│   ├── settings-reference.md
│   ├── known-bypasses.md
│   ├── profiles/                # rationale per profile
│   └── adr/                     # architecture decision records
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security-regression/
├── examples/
│   ├── profile-baseline/
│   ├── profile-strict/
│   └── profile-regulated/
├── .github/
├── CHANGELOG.md
├── README.md
├── SECURITY.md
├── OWNERS.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
└── LICENSE
```

Three layout choices to flag:

1. **Monorepo with `packages/`** so npm package, plugin, and CLI all share `core`. One place to fix a security bug.
2. **`installers/` separate from `packages/`** because installers are per-OS shell glue, not Node code.
3. **`profile-baseline | strict | regulated` examples** ship alongside the source profiles so admins can see compiled output before deploying.
4. **`installers/windows/` and `installers/linux/` exist in v1.0 as stub directories** with README files describing planned scope and target version. Empty-but-present preserves the layout shown above and signals roadmap commitment to early adopters reading the source.

---

## 4. Hook Runtime & Contract

Every hook is a Node module exporting a single function with a declarative manifest:

```js
// packages/hooks/secret-guard/index.js
export default {
  manifest: {
    name: 'secret-guard',
    event: 'PreToolUse',           // PreToolUse | PostToolUse | UserPromptSubmit | SessionStart | SubagentStart | ...
    matchers: ['Bash'],            // tool names this hook applies to
    threat: 'T-001-secret-leak',   // ID into the threat register (Section 7)
    profiles: ['baseline','strict','regulated'],
    severity: 'block',             // 'block' | 'warn' | 'log'
    timeout_ms: 1500,
  },
  async run(ctx) {
    // ctx = { tool, input, env, paths, log, abort, allow }
    return { decision: 'allow' | 'block' | 'warn', reason, evidence }
  }
}
```

**Contract guarantees:**

1. **Single export, declarative manifest** - runner introspects every hook without executing it. Powers `ccsec audit`, the docs generator, and the settings linter.
2. **OS-portable `ctx`** - runner provides normalized paths/env/tool input. Hooks never branch on `process.platform`. All cross-platform handling lives in `packages/core/`.
3. **Per-hook `severity`** - same hook can be `warn` in baseline and `block` in regulated. No copy-paste between profiles.
4. **Mandatory `timeout_ms`** - runaway hook = Claude Code DoS. Default 1500ms; runner kills overruns and emits a `hook-timeout` audit record.
5. **Hooks are pure decision-makers, not effectors** - return a decision; runner owns logging, allowlist updates, and side effects. Easier to sandbox, easier to test.
6. **Structured JSONL audit output** - every hook invocation emits one line with name, decision, reason, evidence digest, duration. Greppable, future-shippable to any SIEM if a client later upgrades from passive.

---

## 5. Settings Templates & Profile Layering

Settings ship as layered JSON, not three monolithic copies. A profile is the result of merging base + overlays.

```
packages/settings/
├── base.json                # universal: never-deny rules, schema version, audit-log path
├── overlays/
│   ├── secrets.json         # category 1
│   ├── destructive.json     # category 2
│   ├── sensitive-paths.json # category 3
│   ├── bash-structural.json # category 4
│   ├── branch-guards.json   # category 5
│   ├── network-egress.json  # category 6 (WebFetch domain allowlist, DENY-by-default)
│   ├── audit.json           # category 7
│   ├── behavioral.json      # category 8
│   ├── mdm-bypass.json      # category 9 (passive disableAllHooks detector)
│   └── agent-gating.json    # category 10
└── profiles/
    ├── baseline.json        # base + secrets + destructive + sensitive-paths + audit
    ├── strict.json          # baseline + bash-structural + branch-guards + network-egress + behavioral
    └── regulated.json       # strict + mdm-bypass + agent-gating + tighter egress allowlist
```

Each `profiles/*.json` is `{ "extends": [...], "overrides": {...} }`. The CLI's `ccsec compile <profile>` resolves layers into a single flat `settings.json` ready for `~/.claude/` or `managed-settings.json`. **Compiled outputs are checked in** for transparency - admins can diff exactly what they're deploying.

**Path tokens for OS portability:**

```
${HOME}    → /Users/x | /home/x | C:\Users\x
${SSH}     → ${HOME}/.ssh
${AWS}     → ${HOME}/.aws
${KEYS}    → platform-specific list of credential dirs
${TMP}     → /tmp | %TEMP%
```

Compiler resolves tokens at install time per target OS. Same source template, different output per platform - no separate Windows fork of policy.

**Threat-tagged deny rules:**

```json
{
  "permissions": {
    "deny": [
      { "pattern": "Bash(sudo *)",     "threat": "T-008-privilege-escalation" },
      { "pattern": "Bash(rm -rf *)",   "threat": "T-002-destructive-fs" },
      { "pattern": "Read(${SSH}/**)",  "threat": "T-003-credential-exfil" },
      { "pattern": "Bash(* | sh)",     "threat": "T-009-pipe-to-shell" }
    ]
  }
}
```

The `threat` field is non-standard JSON for Claude Code (it ignores unknown keys) but the compiler strips it before deploy and uses it to auto-generate the `coverage-matrix.md` doc. Single source of truth.

**Opinionated default - flagged explicitly in `known-bypasses.md`:** `network-egress.json` ships **deny-by-default** for WebFetch with a small allowlist (`docs.anthropic.com`, `github.com`, `developer.mozilla.org`, etc.). Aggressive, but it is the only credible defense against exfil-via-WebFetch. Admins can loosen for their environment with full disclosure of the trade-off.

---

## 6. Distribution Channels & Installers

Three install channels, one source of truth. CI builds all three from the same monorepo on each tag.

### Channel 1 - Claude Code Plugin (per-user, default)

```
/plugin install bitsummit/claude-code-security
ccsec apply --profile baseline
```

Plugin manifest registers the `ccsec` slash command, hooks, and settings. `ccsec apply` writes `~/.claude/settings.json` and `~/.claude/hooks/`. `--dry-run` previews the diff. CLI maintains a small lockfile so future updates can detect user-modified files and refuse to clobber.

### Channel 2 - npm (per-user CLI + CI use)

```
npm i -g @bitsummit/claude-code-security
ccsec doctor                            # diagnose current ~/.claude/ state
ccsec apply --profile strict
ccsec audit                             # print active rules + threat coverage
ccsec lint <path-to-settings.json>      # validate against schema + best-practices
ccsec compile --profile <name> --target managed
ccsec verify                            # check installed files against expected hashes
```

Same CLI as the plugin. npm is for users without the plugin marketplace, for CI pipelines that gate PRs against profile regressions, and for power users who prefer global binaries.

### Channel 3 - Raw repo (MDM admins)

Admins clone, run `ccsec compile --profile regulated --target managed`, get a single `managed-settings.json` for Jamf/Intune/Ansible. The `installers/macos/` directory ships:

- `install.sh` - copies hooks to `/Library/Application Support/ClaudeCode/hooks/`, writes `managed-settings.json`
- `jamf/` - config profile XML + smart-group recipe
- `verify.sh` - admin-side health check (file perms, hook presence, settings hash)

### Tamper protection on `managed-settings.json` (passive layer)

- `install.sh` sets owner `root:wheel`, mode `0644`. On macOS also `chflags uchg` (immutable bit).
- File's SHA-256 recorded in `/Library/Application Support/ClaudeCode/.ccsec-manifest`. `ccsec verify` reports drift. **No daemon** - the admin schedules `ccsec verify` themselves (cron, LaunchDaemon, GPO, or Intune compliance script).
- `known-bypasses.md` documents `disableAllHooks` (issue #26637) with a passive-detection recipe: a hook in the `audit` overlay scans for `.claude/settings.local.json` containing the flag and emits a `warn` to the audit log on every PreToolUse. Doesn't block (passive posture); evidence is there for review.

### Release engineering

- Tagged releases produce: signed npm package, plugin tarball, `ccsec` standalone binaries (Node SEA: macOS arm64+x64, Windows x64, Linux x64), SHA-256 manifest signed with the org's release key.
- `SECURITY.md` defines a 90-day disclosure window with `security@bitsummit.com` and a public PGP key.
- CI publishes a CycloneDX SBOM per release.

---

## 7. Threat Model

Two frameworks woven together: **STRIDE** for the agent process, **OWASP Agentic Top 10 (2025)** for LLM-specific concerns. Single threat register, dual taxonomy.

### Trust boundaries

1. User prompt → Claude Code process
2. Claude Code → Tool invocations (Bash, Edit, Write, WebFetch, MCP)
3. Tool → Host filesystem / network / credentials
4. Subagent ↔ Parent agent
5. Local settings ↔ Managed settings

### Threat register

| ID | Title | Vector | STRIDE | Agentic Top 10 | Default mitigation |
|---|---|---|---|---|---|
| T-001 | Secret leak via tool output | Bash, Read | I | A4 Sensitive Info Disclosure | secret-guard (block) + secret-leak-detector (post) |
| T-002 | Destructive filesystem op | Bash | T | A6 Excessive Agency | destructive-guard |
| T-003 | Credential file exfil | Read, Bash | I | A4 | sensitive-paths overlay |
| T-004 | Force-push / branch sabotage | Bash | T | A6 | branch-guard |
| T-005 | Network exfil via WebFetch | WebFetch | I | A4 | egress allowlist |
| T-006 | Pipe-to-shell remote exec | Bash | E | A6 | bash-structural-guard |
| T-007 | Command chaining bypass | Bash | E | A6 | bash-structural-guard |
| T-008 | Privilege escalation (sudo) | Bash | E | A6 | deny `sudo *` |
| T-009 | Arbitrary code via `eval` | Bash | E | A6 | deny `eval *`, structural |
| T-010 | Prompt injection from tool output | * | T+I | A1 Prompt Injection | url-verify, content-source labelling, behavioral rule |
| T-011 | Subagent escape / unauthorized spawn | Task | E | A5 Improper Output Handling | agent-gating, required-agents |
| T-012 | MDM bypass via `disableAllHooks` | Settings | T | A6 | passive detector + admin verify cron |
| T-013 | Local settings overriding managed | Settings | T | A6 | settings-precedence linter |
| T-014 | Tool spoofing via MCP | MCP | S | A8 (proxy) | MCP allowlist, signature pinning |
| T-015 | Audit log tampering | FS | T | A6 | append-only JSONL + hash chain |
| T-016 | Hook DoS / runaway timeout | Hook runtime | D | A6 | mandatory `timeout_ms`, runner-enforced kill |
| T-017 | Repudiation of risky action | * | R | A6 | full audit log with prompt + tool + decision + user |
| T-018 | Supply-chain attack on hooks | npm/plugin | T | A3 Supply Chain | signed releases, SBOM, pinned deps |

### Explicit non-goals (sets reader expectations)

- **Not a sandbox.** Claude Code runs as the user; we restrict, we don't isolate.
- **Not a runtime jail.** Determined attacker with shell access wins.
- **Not a network firewall.** Egress allowlist is best-effort; bypass via DoH or IP literals possible.
- **Not a remote management system.** No daemon, no SIEM coupling, no auto-remediation (out by design).

### Coverage matrix

Auto-generated from hook manifests + overlay metadata. CI fails if a profile claims to be `regulated` but doesn't cover T-001 through T-013.

---

## 8. Documentation Structure

Five tracks, each with a specific reader.

### Track 1 - `README.md` + landing page

Reader: anyone arriving from search or LinkedIn.

- One-paragraph "what this is" + threat summary
- 60-second install for each of three channels
- "What's protected / what's not" honesty box (lifted from threat-model non-goals)
- Badges: license, version, hook count, threat coverage %, CI status, OpenSSF Scorecard
- Links into the rest of the docs

### Track 2 - `docs/deployment/`

Reader: implementer (IT admin, DevOps, individual dev).

- `developer-quickstart.md`
- `mdm-jamf.md` - full Jamf walkthrough with screenshots
- `mdm-intune.md` - Intune via PowerShell + ADMX (v1.1 placeholder in v1)
- `linux-ansible.md` - placeholder for v1.2
- `ci-integration.md` - using `ccsec lint` to gate PRs that modify `.claude/settings.json`
- `upgrade-guide.md` - version-to-version migrations, breaking changes per major

### Track 3 - `docs/threat-model.md` + `docs/hooks/`

Reader: security reviewer, auditor.

- Full threat-model doc with Mermaid diagrams, T-IDs, STRIDE/Agentic mapping
- Auto-generated page per hook from manifest: name, threat addressed, profiles, severity, false-positive notes, evidence format, disabling guidance
- `coverage-matrix.md` - profile × threat ID
- `known-bypasses.md` - incl. #26637 with detection recipe and explicit candor on what we don't fully fix

### Track 4 - `docs/settings-reference.md` + `docs/profiles/`

Reader: anyone tuning policy.

- Every settings.json key documented with security implications, examples of safe/unsafe values
- Per-profile rationale: assumed user, what it protects, what it costs in friction
- Migration guide between profiles (baseline → strict → regulated)

### Track 5 - `docs/adr/` + `CHANGELOG.md` + `SECURITY.md`

Reader: future maintainer, contributor, security researcher.

- ADRs documenting why Node, why monorepo, why passive-only, why deny-by-default WebFetch, why no auto-remediation, etc.
- `CHANGELOG.md` follows Keep a Changelog
- `SECURITY.md` defines disclosure: 90-day window, `security@bitsummit.com`, PGP key, hall-of-thanks for verified reports

### Cross-cutting docs hygiene

- `markdownlint` + `vale` in CI
- Docs-coverage check fails build if a hook lacks a docs page or a settings key lacks a reference entry
- All external URLs verified at CI time
- Diagrams in Mermaid (renders on GitHub natively)

### Auto-generation pillar

Hook docs, coverage matrix, and threat-to-rule index are **generated, not hand-written**. Hand-written docs rot; generated docs stay honest. The cost: hook manifest schema must be rich - already reflected in Section 4's contract.

---

## 9. Testing Strategy

Three layers, each closing a different failure mode. CI runs all three on every PR; release tags require full green.

### Layer 1 - Unit tests (per hook, per core module)

- `vitest`
- Each hook has a `*.test.ts` next to it: feed synthetic `ctx`, assert decision + reason
- Core modules (path resolver, structural-bash parser, manifest validator, JSONL audit logger) have their own suites
- Coverage gate: ≥90% line coverage on `packages/core/`, ≥85% on `packages/hooks/`
- Snapshot tests for compiled profiles - `ccsec compile baseline` output is checked in; CI fails on unintended drift

### Layer 2 - Integration tests

- Fixture corpus of recorded Claude Code tool-call sequences (sanitized, public, checked in)
- Test runner replays each sequence through the hook chain, asserts the decision matrix
- Tests *interactions*: e.g., does `secret-guard` fire before `audit` so the audit log captures redaction?
- Per-OS matrix: macOS runners (v1), Windows (v1.1), Linux (v1.2)
- Tests installer end-to-end: clean container, run `install.sh` or `ccsec apply`, verify resulting `~/.claude/` matches expectation bit-for-bit

### Layer 3 - Security regression tests

Every known bypass becomes a permanent test that fails on regression. This is what makes the repo defensible long-term.

- **Malicious-prompt corpus** - public datasets (Lakera Gandalf, etc.) + hand-crafted attempts at destructive ops, secret exfil, exfil to attacker domains. Asserts hooks block.
- **Command-injection corpus** - pipe-to-shell, command substitution, here-doc tricks, encoded payloads, Unicode lookalike tricks (e.g., `；` U+FF1B vs `;`). Asserts `bash-structural-guard` catches each.
- **Exfil-pattern corpus** - WebFetch attempts to pastebin, transfer.sh, requestbin, raw IPs, DoH endpoints, base64-encoded URLs. Asserts egress allowlist catches.
- **Bypass-regression corpus** - every bypass we close gets a permanent test. Issue #26637 detector test lives here from day one.
- **Subagent-escape corpus** - prompts attempting unapproved Task spawns, abusing Task to chain into Bash with looser policy. Asserts `agent-gating` holds.

### Continuous fuzzing

Short-running fuzz job in CI (~60s) using a grammar-aware fuzzer against the structural-bash parser. Catches edge cases - historically where bypass discoveries happen.

### Weekly red-team CI

Cron-scheduled job pulls latest published prompt-injection corpora, runs them against the regulated profile. Failures auto-open `bypass: investigation` issues. Keeps the repo *alive* over years.

### Test data hygiene

- No real secrets in fixtures - synthetic patterns that match known formats (AWS, GitHub, Stripe) without being valid
- All bypass test names are public; corpus contents that demo bypasses are gated behind a "responsible disclosure" branch so we don't ship working exploits at the same time as the fix

---

## 10. Versioning, Release & Maintenance

### SemVer with security carve-out

- **MAJOR**: hook contract changes, profile semantic changes, removal of any deny rule
- **MINOR**: new hooks, new overlays, new profile, additive settings keys
- **PATCH**: bug fixes, doc updates, threat-model clarifications, test additions
- **Security carve-out**: a fix that *tightens* policy (closes a bypass) ships in PATCH and is flagged in `CHANGELOG.md` under `### Security`. Tightening in patch is allowed because the alternative - admins skipping security patches because they bumped a major - is worse than SemVer purity.

### Release cadence

- PATCH: as needed; target ≤72hrs from confirmed bypass to released fix
- MINOR: every 6-8 weeks, batched
- MAJOR: at most twice a year, deprecation window of one full minor

### Release artifacts (every tag, signed)

- npm package: `@bitsummit/claude-code-security`
- Plugin tarball: GitHub Releases + plugin marketplace
- Standalone `ccsec` binaries via Node SEA: macOS arm64/x64, Windows x64, Linux x64
- CycloneDX SBOM
- SLSA Level 3 provenance via GitHub OIDC + npm provenance
- Signed SHA-256 manifest of all artifacts (org PGP key)

### Branching

- `main` always releasable
- `release/v1.x` long-lived branches per major for security-patch backports (12-month support window after a major's last minor)
- Feature work in short-lived branches, PR with required review

### Required PR checks

- Lint, type-check, full test matrix (unit + integration + regression)
- Coverage gate
- `ccsec lint` against compiled profile snapshots
- Markdown + Vale on docs
- `Threat-ID:` trailer required on any commit touching `packages/hooks/` or `packages/settings/`. CI fails if missing.

### Disclosure & advisory pipeline

- `SECURITY.md` channel: `security@bitsummit.com` with PGP, plus GitHub Security Advisories
- 90-day default disclosure window, negotiable
- Shipped advisories cross-link threat ID, regression test added, affected profiles
- Automated GHSA generation on tagged security patches

### Maintenance signals (prevent abandonment)

- `OWNERS.md` lists named maintainers + responsibilities + backups (not "the BITSUMMIT team")
- Triage SLA: ack ≤72hrs, fix or roadmap ≤14 days for HIGH, ≤30 days for MEDIUM
- Monthly "state of the project" issue auto-opened by a workflow: open bypasses, recent advisories, hook-coverage drift, dependency staleness
- Stale-issue bot configured generously; security repos with hostile stale-bots earn a bad reputation

### Sustainability

- BITSUMMIT-stewarded but contributor-friendly: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, "good first issue" labels, transparent governance note in `OWNERS.md` describing the path to maintainer status
- Optional public roadmap project board
- Optional sponsorship config

---

## 11. Roadmap & Phasing

### Phase 1 - `v1.0` macOS + per-user (~6 weeks)

- `packages/core/` - runner, manifest validator, path-token resolver, structural-bash parser, JSONL audit logger
- `packages/hooks/` - all ~25 hooks across categories 1-10
- `packages/settings/` - base + 10 overlays + 3 profiles
- `packages/rules/` - CLAUDE.md hardening templates
- `packages/cli/` - `ccsec apply | doctor | audit | lint | compile | verify`
- `packages/plugin/` - plugin manifest, slash-command glue
- `installers/macos/` - `install.sh`, Jamf config profile, `verify.sh`, manifest hashing
- `docs/` - full Track 1-5 content for macOS scope; Windows/Linux marked "planned" with concrete dates
- `tests/` - unit + integration (macOS) + security regression (all corpora)
- Three distribution channels live: npm, plugin, raw repo
- `SECURITY.md`, `OWNERS.md`, signed releases, SBOM, GHSA enabled

### Phase 2 - `v1.1` Windows (4-5 weeks after v1.0)

- `installers/windows/` - PowerShell installer, Intune ADMX, optional MSI
- Hook portability validation: every hook re-runs against Windows transcripts in CI
- `docs/deployment/mdm-intune.md` written and tested against a real Intune tenant (BITSUMMIT lab)
- `ccsec` Windows binary signed with EV cert (Authenticode)
- Windows fixtures added to integration corpus

### Phase 3 - `v1.2` Linux + ecosystem (4-6 weeks after v1.1)

- `installers/linux/` - shell installer, Ansible role, .deb + .rpm packages
- Systemd unit samples (still passive - no daemon)
- Hook contract published as standalone spec doc → opens door for third-party hook authors
- `examples/community-hooks/` shows how third party would author against the contract
- Optional: `awesome-claude-code-security` discoverability page seeded with curated third-party hooks

### Backlog (uncommitted, public)

- "Active monitoring tier" (option B from posture decision) as opt-in if clients ask
- SIEM shipper for Splunk/Sentinel/Datadog (passive log forwarder, no daemon)
- Web-based policy editor compiling to settings.json
- Reference upstream patch / proposal to Anthropic for issue #26637, once we have field data

### Phase 1 success criteria

- Three-channel install works end-to-end on a clean Mac
- All security-regression corpora pass against `regulated` profile
- A non-BITSUMMIT person can read `docs/deployment/mdm-jamf.md` and ship the policy without our help (validated with one external pilot)
- Named external security reviewer (paid pre-release) signs off on threat model

### Deliberately NOT in roadmap

- Hosted service / SaaS dashboard
- Active enforcement / auto-remediation
- Custom MCP servers
- Per-client custom hook service

---

## 12. Open Questions for Implementation Plan

**Scope note for the implementation plan:** the plan that follows from this spec is scoped to **Phase 1 (`v1.0` macOS + per-user)** only. Phase 2 (Windows) and Phase 3 (Linux) get their own spec/plan cycles when v1.0 is in pilot. This keeps the first plan executable without overcommitting on platform plumbing that benefits from v1.0 field data first.

These do not block design approval but should be resolved during writing-plans:

1. **Plugin marketplace listing name** vs. **GitHub repo name** - should both be `claude-code-security` or should the marketplace use `bitsummit-claude-code-security` for branding?
2. **Org for the GitHub repo** - `bit-haseebminhas/` (personal) vs. a BITSUMMIT GitHub org? Affects ownership perception and the `security@` mailbox.
3. **External pre-release security reviewer** - name, budget, timeline. Critical for credibility on day-one launch.
4. **PGP key custody** - release-signing key generation, storage, and rotation procedure.
5. **Pilot client for `regulated` profile validation** - which existing BITSUMMIT client is best suited (specific candidates tracked privately in the maintainer's pipeline; profiles described in `docs/pilot-validation.md`) and what does their participation look like?
6. **Audit log format** - JSONL is decided; the per-record schema (CEF, ECS, custom) is not. Recommend ECS so future SIEM integration is one-shot.

---

## 13. References

- [yurukusa/claude-code-hooks](https://github.com/yurukusa/claude-code-hooks) - 16-hook autonomous-safety reference; superseded by [cc-safe-setup](https://github.com/yurukusa/cc-safe-setup)
- [pixelitobenito gist](https://gist.github.com/pixelitobenito/728f5fcb9d9c5dc6310722d66ff77792) - three-layer defense: deny-list + structural blocker + behavioral rules
- [anthropics/claude-code#26637](https://github.com/anthropics/claude-code/issues/26637) - `disableAllHooks` MDM bypass (unpatched as of design date)
- [OWASP Agentic Security Initiative - Top 10](https://genai.owasp.org/llm-top-10/) - 2025 taxonomy
- [STRIDE](https://en.wikipedia.org/wiki/STRIDE_model)
- [Keep a Changelog](https://keepachangelog.com/)
- [SLSA](https://slsa.dev/)
- [CycloneDX](https://cyclonedx.org/)
