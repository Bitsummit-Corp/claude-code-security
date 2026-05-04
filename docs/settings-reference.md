# Settings Reference

> Status: 2026-04-29. Reference for every key the project uses in `settings.json` (per-user) and `managed-settings.json` (MDM-deployed).

This document is the schema-of-record for the JSON files this project compiles and writes. Every key below is either read by the Claude Code harness, by `ccsec` hooks, or by `ccsec` runtime code. Keys not listed are not used and will be ignored (or, with `--strict`, rejected at compile time).

The compiled output is the union of `base.json`, the overlays referenced by the chosen profile, and any `overrides`. The compiler resolves path tokens (`${HOME}`, `{TMP}`, etc.) per the `--os` flag.

## Top-level keys

### `schema` (number, required)

Version of the settings schema. Currently `1`. The compiler refuses to load files with a higher schema version than it understands.

### `ccsec_version` (string, required)

Version of the ccsec package that compiled this file. Used by `ccsec doctor` to detect when a deployed `managed-settings.json` is older than the installed CLI.

### `audit` (object, required)

Configuration for the audit-logging subsystem. See `audit.*` keys below.

### `permissions` (object, required)

Harness-level permission rules. The Claude Code harness reads `permissions.deny[].pattern` and `permissions.allow[].pattern` and short-circuits tool calls that match a deny pattern.

### `hooks` (object, required)

Map from hook event name to ordered hook list. The runner invokes each hook in order, in parallel where the harness allows it. See `hooks.*` keys below.

---

## `audit.*` keys

### `audit.log_path` (string, required)

Filesystem path to the audit log JSONL file. Path tokens (`${HOME}`, `${TMP}`, etc.) are resolved at compile time per `--os`. Default: `${HOME}/.claude/ccsec-audit.jsonl` on per-user; on managed deployments, may point to a fleet-shared sink.

### `audit.egress_allowlist` (string[], optional)

List of hostnames the egress hooks (`webfetch-egress-guard`, `bash-egress-guard`) treat as allowed. A request to a host not in this list produces a block decision on the configured profile severity. Per-profile defaults:

- `baseline`: 8 hosts (Anthropic docs, GitHub, MDN, Node.js, npm, PyPI).
- `strict`: 4 hosts (Anthropic docs, GitHub, npm, PyPI).
- `regulated`: 2 hosts (Anthropic docs, GitHub).

### `audit.verify_on_session_start` (boolean, optional)

When `true`, the `audit-tamper-detector` hook runs on `SessionStart` in addition to `PostToolUse`, so a tampered audit log is detected at session entry. Set by the `audit` overlay; false by default to keep `baseline` startup latency low.

---

## `permissions.*` keys

### `permissions.deny[]` (array of objects, required)

Each entry is `{ "pattern": "<harness-permission-pattern>", "threat": "T-NNN-<slug>" }`.

- `pattern`: a harness-evaluated permission pattern. Examples: `Read(${HOME}/.aws/credentials)`, `Bash(curl * pastebin.com*)`, `WebFetch(*paste.ee*)`. The harness short-circuits matching tool calls.
- `threat`: a threat ID from `docs/threat-model.md`. Used by `ccsec doctor` to ensure every deny pattern is tied to a documented threat. This is a contract: deny patterns without a threat ID will fail `ccsec doctor`.

### `permissions.allow[]` (array of objects, optional)

Same shape as `deny[]`. Allow patterns override deny patterns when both match. Use sparingly; an over-broad `allow` defeats the deny layer.

---

## `hooks.<event>[]` keys

### `hooks.PreToolUse[]` (array of objects)

Hooks that run before a tool invocation. Each entry: `{ "name": "<hook-name>" }`. The runner resolves the hook by name from `@bitsummit/ccsec-hooks` and invokes its `run(ctx)` function. A `block` decision short-circuits the tool call and emits an audit record.

### `hooks.PostToolUse[]` (array of objects)

Hooks that run after a tool invocation, with access to the tool's `response.stdout` / `response.stderr` / `response.output`. A `block` decision after the fact emits an audit record but cannot un-call the tool.

### `hooks.UserPromptSubmit[]` (array of objects)

Hooks that run when the user submits a prompt. Used for prompt-injection detection (`untrusted-content-tagger`).

### `hooks.SessionStart[]` (array of objects)

Hooks that run on session start. Used for environment validation (`disable-all-hooks-detector`, `local-settings-precedence-checker`, `claude-md-validator`) and audit log integrity check (`audit-tamper-detector` when `verify_on_session_start` is true).

### `hooks.SubagentStart[]` (array of objects)

Hooks that run when a subagent is spawned. Used for subagent escape detection (`agent-allowlist-enforcer`, `subagent-spawn-guard`).

### `hooks.SubagentStop[]` (array of objects)

Hooks that run when a subagent stops. Used for session summarization (`audit-session-summary`).

---

## Hook entry shape

Each hook entry is a single-key object: `{ "name": "<hook-name>" }`. The runner looks up the hook's manifest (`archive/hooks-rc2/<hook-name>/index.ts` in the v0.1.0 reset state) and uses its declared:

- `event`: must match the parent key in `hooks.<event>[]` (compiler rejects mismatches).
- `matchers`: tool name patterns the hook fires on. The runner short-circuits if the current tool name does not match any pattern.
- `threat`: the threat ID (must exist in `docs/threat-model.md`).
- `profiles`: which profiles include this hook. The compiler skips hooks whose `profiles` list does not include the active profile.
- `severity`: scalar (`block` / `warn` / `log`) or per-profile object. The runner uses the active profile's severity to modulate the hook's `block` decision (see ADR-0004).
- `timeout_ms`: per-hook timeout. The runner aborts the hook if it does not return within this budget and logs a `T-016-hook-dos` event.

The hook's `run(ctx)` function is not configurable from settings.json; it is shipped in the hook package.

---

## Path tokens

The compiler resolves these tokens per `--os`:

| Token | macOS | Linux | Windows |
| --- | --- | --- | --- |
| `${HOME}` | `/Users/<user>` (per-user) or `/Users/Shared` (managed) | `/home/<user>` (per-user) or `/etc/skel` (managed) | `%USERPROFILE%` (per-user) or `%PROGRAMDATA%` (managed) |
| `${TMP}` | `/tmp` | `/tmp` | `%TEMP%` |
| `${SSH}` | `${HOME}/.ssh` | `${HOME}/.ssh` | `%USERPROFILE%\.ssh` |
| `${AWS}` | `${HOME}/.aws` | `${HOME}/.aws` | `%USERPROFILE%\.aws` |

See `packages/core/src/path-tokens.ts` for the canonical resolver and `packages/settings/templates/` for the per-OS template files.

---

## Profile chooser

Three profiles ship out of the box:

| Profile | Audience | Posture |
| --- | --- | --- |
| `baseline` | Solo dev | Mostly warns; does not block normal flow |
| `strict` | Team / shared infra | Blocks dotfile, branch sabotage, structural risks |
| `regulated` | Healthcare / legal / public sector | Tightest egress + MDM bypass + agent allowlist |

Each profile is a `extends + overrides` JSON file at `packages/settings/profiles/<profile>.json`. The compiler resolves `extends` recursively, applies overlays in order, and emits the compiled `settings.json`.

---

## Compile invocation

```
node packages/cli/bin/ccsec.js compile \
  --profile <baseline|strict|regulated> \
  --target <user|managed> \
  --os <macos|linux|windows> \
  --settings-root packages/settings \
  --out /path/to/settings.json
```

`--target user` writes to `~/.claude/settings.json` semantics; `--target managed` writes to `/Library/Application Support/ClaudeCode/managed-settings.json` (or per-OS equivalent) semantics. The output JSON is validated against the schema before write.

---

## See also

- `docs/threat-model.md`: full threat register.
- `docs/coverage-matrix.md`: auto-generated threat-to-hook map (regenerate with `pnpm gen:coverage-matrix`).
- `docs/hooks/<name>.md`: per-hook reference (regenerate with `pnpm gen:hook-docs`).
- `docs/known-bypasses.md`: documented detection gaps.
- `docs/adr/0004-hook-contract-bumps-plan2.md`: hook manifest schema details.
- `docs/adr/0006-mdm-deployment-decision.md`: per-OS path templates rationale.
