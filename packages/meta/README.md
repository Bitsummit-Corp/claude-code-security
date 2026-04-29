# @bitsummit/claude-code-security

Umbrella package for BITSUMMIT Hardening - the open-source security reference for Anthropic's Claude Code.

## Install

```
npm i -g @bitsummit/claude-code-security
```

This pulls in all sibling packages:

- `@bitsummit/ccsec-core` - hook contract types, runner, audit logger
- `@bitsummit/ccsec-hooks` - 26 hooks across secrets, destructive ops, sensitive paths, bash structural, branch guards, network egress, audit, behavioral, MDM bypass, agent gating
- `@bitsummit/ccsec-settings` - layered settings (base, overlays, profiles, compiled snapshots)
- `@bitsummit/ccsec-cli` - `ccsec` binary (`compile`, `apply`, `doctor`)
- `@bitsummit/ccsec-rules` - CLAUDE.md hardening templates per profile

## Quickstart

```
ccsec apply --profile baseline
ccsec doctor
```

## Profiles

| Profile | When to use |
|---|---|
| baseline | Solo dev. Mostly warns. Doesn't break flow. |
| strict | Team / shared infra. Tighter egress. Blocks dotfile + git-destructive ops. |
| regulated | Regulated environment (healthcare, legal, public sector). Tightest egress + MDM bypass detector + agent allowlist. |

## Documentation

See the main repository: https://github.com/Bitsummit-Corp/claude-code-security

## License

MIT.
