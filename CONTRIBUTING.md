# Contributing to claude-code-governance

> **v0.1.0 scope-reset notice (2026-05-04).** The rc.x architecture has been retired and the 26 hooks moved to `archive/hooks-rc2/`. New hook authoring is paused until the M1 rebuild lands a single integration-tested hook. The "Adding a new hook" section below is preserved as historical reference for the rc.x flow; the M1+ authoring flow will be documented when it ships. See the [README scope reset section](./README.md#scope-reset-may-2026) for the current state.

Thanks for considering a contribution. This project is a hardening reference for Anthropic's Claude Code CLI; small, targeted contributions land easily, and the bar for landing depends on the kind of change. This guide explains how to set up, what kinds of contributions are welcomed, and how to get a change reviewed.

If you are reporting a security vulnerability, **do not open a public issue**. See [`SECURITY.md`](./SECURITY.md) for the private disclosure channel.

## Code of conduct

Participation is governed by the [Contributor Covenant 2.1](./CODE_OF_CONDUCT.md). Reports of unacceptable behavior go to `conduct@bitsummit.com`.

## What kinds of contributions are welcomed

| Kind | Bar | Where to start |
| --- | --- | --- |
| **Bug fix** in a hook | Reproducer + test that fails before the fix and passes after. | Open a PR. |
| **New hook** for a documented threat | Manifest, implementation, test, doc page, threat-model link. See "Adding a new hook" below. | Open an issue first to confirm the threat is in scope. |
| **New threat** in `docs/threat-model.md` | Vector + detection plan (which hook covers it, or which gap it documents). | Open an issue first; threat IDs are sequential. |
| **Documentation** | Clear, scoped, no marketing voice. | Open a PR. |
| **Bypass research** for an existing hook | Reproducer + add to `docs/known-bypasses.md` if not patchable in this release. | Treat as a security report if exploitable in default profile; see `SECURITY.md`. |
| **New profile** | Strong justification. The three current profiles (`baseline`, `strict`, `regulated`) are deliberate and a fourth profile is a high bar. | Open an issue with the use case. |
| **Refactor** without behavior change | Tests still pass; coverage does not regress. | Open a PR. Keep it tightly scoped. |

Not in scope for this repo: sandboxing, runtime jailing, active monitoring daemons, SIEM-shipping daemons, auto-remediation of tampered settings, hosted services, custom MCP servers, paid-customization shims. Open an issue if you think your idea fits one of these categories so we can discuss before you build.

## Development setup

### Prerequisites

- Node `>= 20.10`
- pnpm `>= 9.12`
- macOS, Linux, or Windows. Most development happens on macOS; CI runs the full matrix.

### Install and build

```
git clone https://github.com/Bitsummit-Corp/claude-code-governance.git
cd claude-code-governance
pnpm install --frozen-lockfile
pnpm build
```

### Run tests

```
pnpm test                 # full suite
pnpm test:watch           # watch mode
pnpm --filter @bitsummit/ccsec-hooks test    # one package
```

### Type-check and lint

```
pnpm typecheck            # full repo, runs in parallel across packages
pnpm lint                 # ESLint
pnpm format               # Prettier (writes)
```

### Regenerate auto-generated docs

```
pnpm gen:hook-docs        # rewrites docs/hooks/<name>.md from manifests
pnpm gen:coverage-matrix  # rewrites docs/coverage-matrix.md
pnpm gen:docs             # both
```

Run `gen:docs` after any hook manifest change. CI will fail if the committed docs are out of sync.

## Pull request workflow

1. Fork the repo. Branch from `main`.
2. Branch naming: `feature/<short-description>`, `fix/<short-description>`, `docs/<short-description>`.
3. Make your change. Keep PRs scoped to one concern.
4. Add or update tests. New code lands with tests; bug fixes land with a regression test.
5. Run `pnpm typecheck`, `pnpm lint`, `pnpm test`, and `pnpm gen:docs` locally before pushing.
6. Open the PR against `main` with:
   - A short title in imperative voice (e.g., `Fix heredoc parsing in bash-structural-guard`).
   - A description that explains the why, not just the what.
   - A link to the relevant issue if one exists.
7. CI must pass. Failures are not "flake" until investigated.
8. A maintainer reviews. Expect comments; address them in follow-up commits on the same branch (no force-pushes after review starts).
9. Merge is by squash by default; the squash message becomes the commit message on `main`.

## Style conventions

These are enforced in part by hooks and pre-commit checks.

### Brand and prose

- **Never use em dashes.** Use hyphens (`-`) or en dashes (`-`) only. A repo-level pre-write hook blocks em dashes; if it fires, it is not optional, fix the dash.
- **No marketing voice in technical docs.** Direct, specific, no hedging. "We" is fine in casual prose; avoid in reference docs.
- **Cite specifics over generalities.** "T-005 destructive-fs-guard fires on `rm -rf /`" beats "destructive operations are blocked".

### Code

- **TypeScript everywhere** for runtime code. ES modules. `"type": "module"` in every package.json.
- **Prettier-formatted, ESLint-clean.** `pnpm format` before commit if you skipped it.
- **Tests are vitest.** New tests go in the package's `tests/` directory or alongside the source as `<name>.test.ts`.
- **No comments that restate the code.** Comments explain *why*, not *what*. Constraints, invariants, surprises only.
- **No `any`.** If TypeScript cannot infer a type, write the type.

### Commits

- Imperative title, under 70 characters when possible.
- **No `Generated with Claude Code` footers**, no `Co-Authored-By: Claude` tags. The author of the PR is the author. (This applies even when an AI assistant produced part of the change.)
- A multi-line commit body is welcome for non-trivial changes; explain the why in plain prose.

### Git workflow

- Never force-push to `main`. Force-pushing your own feature branch is fine before review starts; avoid it after a review begins.
- Never bypass `pre-commit` hooks (`--no-verify`) without an explicit reason called out in the PR description.
- Never amend commits that are already pushed to a branch under review.

## Adding a new hook

A hook is the unit of detection in this project. Each hook lives at `archive/hooks-rc2/<name>/index.ts`, declares a manifest, exports a `run(ctx)` function, and ships with a test at `archive/hooks-rc2/<name>/<name>.test.ts`.

The minimum surface for a new hook:

1. **Pick a threat ID.** Check `docs/threat-model.md`. If your hook addresses a documented threat (T-001 through T-018 today), reuse that ID. If it addresses a new threat, open an issue first to negotiate the next sequential ID.
2. **Create the directory.** `archive/hooks-rc2/<name>/`.
3. **Write the manifest.** Manifest fields: `name`, `event` (PreToolUse / PostToolUse / SubagentStart / SubagentStop), `matchers` (tool names, e.g. `["Bash"]`), `threat` (T-NNN), `severity` (scalar string or per-profile object), `profiles` (subset of `baseline`, `strict`, `regulated`), `timeout` (ms).
4. **Write the implementation.** `run(ctx)` returns one of the standard hook results (allow / warn / block / log-only). See `packages/core/src/` for the contract types.
5. **Write the tests.** Cover the positive case (the bypass attempt is detected), the negative case (a benign call is not flagged), and at least one boundary case.
6. **Wire into the index.** Add the hook to `archive/hooks-rc2/index.ts`.
7. **Regenerate docs.** `pnpm gen:docs`. Verify `docs/hooks/<name>.md` exists and looks right.
8. **Update the profile.** If your hook should ship in a profile, add it to the relevant profile under `packages/settings/profiles/`. CI snapshot tests will fail until the snapshot is updated.

Tip: copy the closest existing hook as a starting point. `archive/hooks-rc2/secret-guard/` is a good template for input-scanning hooks; `archive/hooks-rc2/branch-protection-guard/` for git-related hooks; `archive/hooks-rc2/audit-session-summary/` for SubagentStop hooks.

## Adding a new threat

Threats are documented in `docs/threat-model.md`. Each threat has an ID, a category, a vector description, a default-profile detection status, and (usually) one or more hooks that mitigate it.

Adding a threat:

1. Open an issue describing the vector. Include a reproducer if you have one.
2. Negotiate the next sequential ID with the maintainer.
3. Add the entry to `docs/threat-model.md` in the appropriate category section.
4. Update `docs/coverage-matrix.md` (auto-generated) by either implementing a hook (preferred) or documenting the gap in `docs/known-bypasses.md`.

## Updating the threat model or known-bypasses

Both files are hand-curated. They are the authoritative reference for what this project claims to mitigate and where its current gaps are. Be specific. A vague entry in known-bypasses is worse than an honest "not detected; rely on OS layer" line.

## Releasing

Release engineering is documented in `docs/release-engineering.md`. Day-to-day contributors do not run releases; the maintainer does.

## Where to ask questions

- **Bug reports / feature requests:** [GitHub Issues](https://github.com/Bitsummit-Corp/claude-code-governance/issues).
- **Security issues:** [`SECURITY.md`](./SECURITY.md). Do not file public issues for vulnerabilities.
- **General discussion:** [GitHub Discussions](https://github.com/Bitsummit-Corp/claude-code-governance/discussions) (when enabled).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](./LICENSE).
