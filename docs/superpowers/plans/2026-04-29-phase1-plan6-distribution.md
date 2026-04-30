# Phase 1 / Plan 6: Plugin + npm Distribution

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Ship the Claude Code plugin (`@bitsummit/ccsec-plugin`), the npm package (`@bitsummit/claude-code-security` umbrella + per-package), CLI lockfile robustness improvements, and tag `v0.6.0-beta.0`.

**Architecture:** Builds on Plan 5 (`v0.5.0-beta.0`; 26 hooks, profile differentiation real). Plan 6 produces the artifacts that allow per-user install via two channels:
- **Plugin:** `/plugin install bitsummit/hardening` (marketplace name: BITSUMMIT Hardening)
- **npm:** `npm i -g @bitsummit/claude-code-security`

The raw-repo channel for MDM admins continues to work via `installers/macos/install.sh`.

**Predecessor commit:** `ad21b47` (Plan 5 CHANGELOG; v0.5.0-beta.0 tagged).

---

## In Scope

- New `packages/plugin/` workspace package with Claude Code plugin manifest (`.claude-plugin/plugin.json`) + slash command `/ccsec` glue.
- npm publish-readiness for `@bitsummit/ccsec-core`, `@bitsummit/ccsec-hooks`, `@bitsummit/ccsec-cli`, `@bitsummit/ccsec-rules`, plus a thin meta-package `@bitsummit/claude-code-security` that depends on all four.
- GitHub Actions workflow `release.yml` that publishes to npm on tag push (gated on tag matching `v*`). Note: requires `NPM_TOKEN` secret which the user provisions; the workflow tolerates absence and skips publish with a documented warning.
- CLI lockfile improvements:
  - `ccsec apply --force` flag (override the user-modification guard)
  - `ccsec apply --no-rules` flag (skip CLAUDE.md rule template installation)
  - `ccsec apply --rules` flag (auto-install `@bitsummit/ccsec-rules` template for the chosen profile to `<claude-dir>/CLAUDE.md` if absent)
- README.md update: install instructions for all 3 channels with full command examples.

## Out of Scope

- Actual npm publish (requires NPM_TOKEN; workflow ships but user runs).
- Actual plugin marketplace listing submission (Anthropic-side action).
- Jamf / managed-settings.json deployment (Plan 7).
- Full Track 1-5 docs (Plan 8).
- Release engineering: signing, SBOM, GHSA, Node SEA binaries (Plan 9).
- Pilot validation (Plan 10).

---

## Tasks

### Task 1: `packages/plugin/` Scaffold

- Create `packages/plugin/package.json` (`@bitsummit/ccsec-plugin`, depends on workspace cli + hooks + settings).
- Create `packages/plugin/.claude-plugin/plugin.json` with manifest:
  - name: bitsummit-hardening
  - displayName: BITSUMMIT Hardening
  - version: 0.6.0-beta.0
  - description: Open-source Claude Code hardening reference. 26 hooks across secrets, destructive ops, sensitive paths, bash structural, branch guards, network egress, audit, behavioral, MDM bypass, agent gating.
  - publisher: BITSUMMIT-Corp
  - repository: https://github.com/Bitsummit-Corp/claude-code-governance
  - commands: `[{ name: 'ccsec', description: 'Apply BITSUMMIT Hardening profile' }]`
- Create `packages/plugin/commands/ccsec.md` defining the `/ccsec` slash command (delegates to `ccsec apply --profile <arg>` from the CLI).
- Run `pnpm install` to register the workspace.

Commit: `feat(plugin): @bitsummit/ccsec-plugin manifest + /ccsec slash command`

### Task 2: Meta-Package `@bitsummit/claude-code-security`

- Create `packages/meta/package.json` with name `@bitsummit/claude-code-security`, version `0.6.0-beta.0`, dependencies on `@bitsummit/ccsec-core` `@bitsummit/ccsec-hooks` `@bitsummit/ccsec-settings` `@bitsummit/ccsec-cli` `@bitsummit/ccsec-rules` workspace:* references. Bin alias `ccsec` re-exports from cli.
- This is the umbrella package users install via `npm i -g @bitsummit/claude-code-security`.

Commit: `feat(meta): @bitsummit/claude-code-security umbrella package`

### Task 3: CLI Improvements - --force, --no-rules, --rules

- Modify `packages/cli/src/commands/apply.ts`:
  - Add `force?: boolean` and `installRules?: boolean` and `noRules?: boolean` fields to `ApplyCommandArgs`.
  - When `force=true`, skip the user-modification guard (write regardless).
  - When `installRules=true`, copy the appropriate template from `@bitsummit/ccsec-rules` to `<claude-dir>/CLAUDE.md` IF it does not already exist (do not overwrite).
  - Add tests covering all three flags.
- Modify `packages/cli/src/index.ts` Commander wiring:
  - `apply` command gains `--force`, `--rules`, `--no-rules` flags (boolean).
- Verify with new tests + run all existing CLI tests.

Commit: `feat(cli): apply --force / --rules / --no-rules flags for ccsec apply`

### Task 4: GitHub Actions Release Workflow

Create `.github/workflows/release.yml`:

```yaml
name: release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: read
  id-token: write

jobs:
  publish:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v3
        with: { version: 9.12.0 }
      - uses: actions/setup-node@v4
        with:
          node-version: 20.10.0
          cache: pnpm
          registry-url: 'https://registry.npmjs.org'
      - run: pnpm install --frozen-lockfile
      - run: pnpm build
      - run: pnpm test
      - name: Publish to npm
        if: ${{ env.NPM_TOKEN != '' }}
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > ~/.npmrc
          for pkg in core hooks settings cli rules meta; do
            (cd packages/$pkg && pnpm publish --access public --no-git-checks --provenance) || true
          done
      - name: Skip note if no token
        if: ${{ env.NPM_TOKEN == '' }}
        run: echo "NPM_TOKEN not set; skipping publish step."
```

Commit: `ci: release workflow publishes to npm on tag push (skips if NPM_TOKEN absent)`

### Task 5: README.md Install Instructions

Update README.md `## Install` section to list three channels:

1. **Plugin** (recommended for individual devs): `/plugin install bitsummit/hardening` then `/ccsec apply baseline`
2. **npm** (for CI use or non-plugin users): `npm i -g @bitsummit/claude-code-security` then `ccsec apply --profile baseline`
3. **Raw repo** (for MDM admins): clone, run `installers/macos/install.sh --profile <profile>`

Add a profile chooser table:

| Profile | When to use |
|---|---|
| baseline | Solo dev. Mostly warns; doesn't break flow. |
| strict | Team / shared infra. Tight egress. Blocks dotfile and git-destructive ops. |
| regulated | Regulated environment (healthcare, legal, public sector). Tightest egress + MDM bypass detector + agent allowlist. |

Commit: `docs: README install instructions for plugin/npm/raw channels + profile chooser`

### Task 6: CHANGELOG + Threat Model + Final Checks

Add `[0.6.0-beta.0] - 2026-04-29` to CHANGELOG with the new package + workflow + CLI flags + README update.

Run all checks:
```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm build
pnpm test -- --coverage
bats installers/macos/tests/install.bats
```

Smoke test install + verify.

Commit: `docs: changelog v0.6.0-beta.0`

### Task 7: Tag + Push + Release

```bash
git tag -a v0.6.0-beta.0 -m "v0.6.0-beta.0: plugin + npm distribution channels"
git push origin main
git push origin v0.6.0-beta.0
gh release create v0.6.0-beta.0 --repo Bitsummit-Corp/claude-code-governance --title "v0.6.0-beta.0 - Plugin + npm Distribution" --notes-file <notes> --prerelease
```

Plan 6 sealed.

---

## Self-Review

- 7 tasks; all locally executable.
- Plugin manifest references real BITSUMMIT-Corp repo and Plan 5's plugin name "BITSUMMIT Hardening".
- Workflow skips publish gracefully if NPM_TOKEN is absent (user provisions on their schedule).
- README clearly documents all 3 channels.
