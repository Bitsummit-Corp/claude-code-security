# Phase 1 / Plan 2: Hooks Categories 1-3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 7 hooks across categories 1 (secrets), 2 (destructive), 3 (sensitive paths), introduce strict/regulated profile shells, expand the threat model and test corpus, and ship `v0.2.0-alpha.0`.

**Architecture:** Builds on Plan 1 foundation. Three contract bumps land first (per-profile severity, matcher wildcards, PostToolUse response field) since every hook depends on them. Then 7 hook implementations, each in its own TDD-driven task. Then settings overlay + profile + snapshot regeneration. Then integration transcripts. Then docs (threat model, coverage matrix, ADR). Finally tag, push, release.

**Tech Stack:** unchanged from Plan 1 (Node.js >=20.10, TypeScript 5.x, pnpm workspaces, vitest, commander, zod). No new dependencies introduced in Plan 2.

---

## Plan 2 Sequence Position

Plan 2 of 10. Predecessor: Plan 1 foundation walking skeleton (`v0.1.0-alpha.0` shipped to `https://github.com/Bitsummit-Corp/claude-code-security/releases/tag/v0.1.0-alpha.0`). Successor: Plan 3 (hooks categories 4-5: bash structural + branch guards).

---

## File Structure (Plan 2 only)

New files:
```
packages/core/
  src/matchers.ts                    # matcher wildcard helper (new)
  tests/matchers.test.ts             # tests for matchesAny()

packages/hooks/src/
  secret-leak-detector/
    index.ts
    secret-leak-detector.test.ts
  keychain-guard/
    index.ts
    keychain-guard.test.ts
  mcp-secret-guard/
    index.ts
    mcp-secret-guard.test.ts
  destructive-fs-guard/
    index.ts
    destructive-fs-guard.test.ts
  git-destructive-guard/
    index.ts
    git-destructive-guard.test.ts
  sensitive-paths-guard/
    index.ts
    sensitive-paths-guard.test.ts
  dotfile-guard/
    index.ts
    dotfile-guard.test.ts

packages/settings/
  overlays/destructive.json          # new
  overlays/sensitive-paths.json      # new
  profiles/strict.json               # new (shell)
  profiles/regulated.json            # new (shell)
  compiled/strict.json               # new
  compiled/regulated.json            # new

tests/integration/transcripts/
  secret-leak-postonly.json
  destructive-attempt.json
  sensitive-paths-attempt.json
  attack-chain.json

tests/integration/
  secret-leak-postonly.test.ts
  destructive-attempt.test.ts
  sensitive-paths-attempt.test.ts
  attack-chain.test.ts

docs/
  coverage-matrix.md                 # new
  adr/0004-hook-contract-bumps-plan2.md  # new
```

Modified files:
```
packages/core/src/types.ts                       # ProfileSeverity type, response field on HookContext
packages/core/src/manifest-validator.ts          # zod accepts both scalar and record severity
packages/core/src/runner.ts                      # uses matchesAny + resolves per-profile severity + accepts response
packages/core/src/index.ts                       # exports matchers helper
packages/core/tests/runner.test.ts               # new tests for wildcards, profile severity, PostToolUse response
packages/settings/overlays/secrets.json          # add 3 hook references
packages/settings/profiles/baseline.json         # extends new overlays
packages/settings/compiled/baseline.json         # regenerated
packages/settings/snapshot.test.ts               # covers 3 profiles
docs/threat-model.md                             # T-002, T-003, T-004 added; T-001 expanded
CHANGELOG.md                                     # v0.2.0-alpha.0 entry
```

---

## Conventions

- Working dir: `/Users/haseebminhas/Projects.DEV/Claude-Code-Security/`
- ESM TypeScript, vitest, pnpm workspaces (unchanged from Plan 1)
- **Brand rule: never use em dashes; use hyphens. The pre-write hook BLOCKS em dashes.**
- No Claude footers in commit messages
- No `git push` until the final push gate at Task 16
- TDD: every code task writes the failing test first, runs it to confirm RED, then implements

---

## Task 1: Manifest Contract Bump - Per-Profile Severity & Matcher Wildcards

**Files:**
- Modify: `packages/core/src/types.ts`
- Modify: `packages/core/src/manifest-validator.ts`
- Modify: `packages/core/tests/manifest-validator.test.ts` (extend; do not break Plan 1 tests)
- Create: `packages/core/src/matchers.ts`
- Create: `packages/core/tests/matchers.test.ts`
- Modify: `packages/core/src/index.ts`

- [ ] **Step 1: Extend manifest validator tests with new acceptance cases (failing)**

Append to `packages/core/tests/manifest-validator.test.ts` (preserve all existing tests):

```ts
  it('accepts severity as a per-profile record', () => {
    const m = { ...valid, severity: { baseline: 'warn', strict: 'block', regulated: 'block' } };
    expect(() => validateManifest(m)).not.toThrow();
  });
  it('rejects severity record with unknown profile', () => {
    const m = { ...valid, severity: { baseline: 'warn', martian: 'block' } };
    expect(() => validateManifest(m)).toThrow(ManifestError);
  });
  it('rejects severity record with unknown level', () => {
    const m = { ...valid, severity: { baseline: 'panic', strict: 'block', regulated: 'block' } };
    expect(() => validateManifest(m)).toThrow(ManifestError);
  });
  it("accepts wildcard matcher '*'", () => {
    expect(() => validateManifest({ ...valid, matchers: ['*'] })).not.toThrow();
  });
  it("accepts prefix-wildcard matcher 'mcp__*'", () => {
    expect(() => validateManifest({ ...valid, matchers: ['mcp__*'] })).not.toThrow();
  });
```

- [ ] **Step 2: Run test to confirm FAIL**

```bash
pnpm --filter @bitsummit/ccsec-core test manifest-validator
```

Expected: 5 failures (new tests added; existing 7 pass).

- [ ] **Step 3: Update `types.ts` with new types**

In `packages/core/src/types.ts`, replace the `HookSeverity` definition area with:

```ts
export type HookSeverity = 'block' | 'warn' | 'log';
export type HookProfile = 'baseline' | 'strict' | 'regulated';
export type ProfileSeverity = HookSeverity | Record<HookProfile, HookSeverity>;
```

Update `HookManifest.severity` field type from `HookSeverity` to `ProfileSeverity`:

```ts
export interface HookManifest {
  name: string;
  event: HookEvent;
  matchers: string[];
  threat: string;
  profiles: HookProfile[];
  severity: ProfileSeverity;
  timeout_ms: number;
}
```

Add a `response` optional field to `HookContext`:

```ts
export interface HookContext {
  tool: string;
  input: Record<string, unknown>;
  response?: { stdout?: string; stderr?: string; output?: unknown; [k: string]: unknown };
  env: Readonly<Record<string, string>>;
  paths: { home: string; ssh: string; aws: string; tmp: string };
  log: (msg: string) => void;
  abort: AbortSignal;
}
```

- [ ] **Step 4: Update `manifest-validator.ts` zod schema**

```ts
import { z } from 'zod';
import type { HookManifest } from './types.js';

export class ManifestError extends Error {
  constructor(message: string) { super(message); this.name = 'ManifestError'; }
}

const SeverityScalar = z.enum(['block', 'warn', 'log']);
const SeverityRecord = z.object({
  baseline: SeverityScalar,
  strict: SeverityScalar,
  regulated: SeverityScalar,
}).strict();

const ManifestSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]*$/),
  event: z.enum([
    'PreToolUse','PostToolUse','UserPromptSubmit','SessionStart','SubagentStart','SubagentStop',
  ]),
  matchers: z.array(z.string().min(1)).min(1),
  threat: z.string().regex(/^T-\d{3}-[a-z0-9-]+$/),
  profiles: z.array(z.enum(['baseline','strict','regulated'])).min(1),
  severity: z.union([SeverityScalar, SeverityRecord]),
  timeout_ms: z.number().int().min(100).max(30000),
});

export function validateManifest(input: unknown): HookManifest {
  const result = ManifestSchema.safeParse(input);
  if (!result.success) {
    const path = result.error.errors[0]?.path.join('.') ?? '<root>';
    const msg = result.error.errors[0]?.message ?? 'unknown';
    throw new ManifestError(`invalid manifest at ${path}: ${msg}`);
  }
  return result.data as HookManifest;
}
```

- [ ] **Step 5: Run validator tests to PASS**

```bash
pnpm --filter @bitsummit/ccsec-core test manifest-validator
```

Expected: 12 tests pass (7 existing + 5 new).

- [ ] **Step 6: Write matcher-wildcard tests (failing)**

Create `packages/core/tests/matchers.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { matchesAny } from '../src/matchers.js';

describe('matchesAny', () => {
  it('matches plain equality', () => {
    expect(matchesAny('Bash', ['Bash'])).toBe(true);
    expect(matchesAny('Edit', ['Bash'])).toBe(false);
  });
  it('matches wildcard *', () => {
    expect(matchesAny('AnyTool', ['*'])).toBe(true);
    expect(matchesAny('mcp__server__tool', ['*'])).toBe(true);
  });
  it('matches prefix wildcard', () => {
    expect(matchesAny('mcp__server__tool', ['mcp__*'])).toBe(true);
    expect(matchesAny('Bash', ['mcp__*'])).toBe(false);
  });
  it('matches when any matcher in the list matches', () => {
    expect(matchesAny('Bash', ['Edit', 'Bash', 'Read'])).toBe(true);
    expect(matchesAny('Write', ['Edit', 'Bash', 'Read'])).toBe(false);
  });
  it('returns false on empty matchers list', () => {
    expect(matchesAny('Bash', [])).toBe(false);
  });
  it("does not treat '*' inside the middle of a string as wildcard", () => {
    expect(matchesAny('foo*bar', ['foo*bar'])).toBe(true);
    expect(matchesAny('foobar', ['foo*bar'])).toBe(false);
  });
});
```

Run: `pnpm --filter @bitsummit/ccsec-core test matchers` -> FAIL (module-not-found).

- [ ] **Step 7: Implement `matchers.ts`**

Create `packages/core/src/matchers.ts`:

```ts
export function matchesAny(tool: string, matchers: readonly string[]): boolean {
  for (const m of matchers) {
    if (m === '*') return true;
    if (m === tool) return true;
    if (m.endsWith('*') && !m.slice(0, -1).includes('*')) {
      const prefix = m.slice(0, -1);
      if (tool.startsWith(prefix)) return true;
    }
  }
  return false;
}
```

- [ ] **Step 8: Run matcher tests to PASS**

```bash
pnpm --filter @bitsummit/ccsec-core test matchers
```

Expected: 6 tests pass.

- [ ] **Step 9: Update `packages/core/src/index.ts` to export matchers helper**

Append to existing exports:

```ts
export { matchesAny } from './matchers.js';
export type { ProfileSeverity } from './types.js';
```

- [ ] **Step 10: Typecheck and commit**

```bash
pnpm --filter @bitsummit/ccsec-core typecheck
git add -A
git commit -m "feat(core): manifest contract bump - per-profile severity, matcher wildcards"
```

---

## Task 2: Runner Update - Resolve Per-Profile Severity, Use matchesAny, Accept response

**Files:**
- Modify: `packages/core/src/runner.ts`
- Modify: `packages/core/tests/runner.test.ts`

- [ ] **Step 1: Append failing tests to runner test file**

Add at end of `packages/core/tests/runner.test.ts`:

```ts
const profileSeverityHook: HookModule = {
  manifest: {
    name: 'profile-sev',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-004-branch-sabotage',
    profiles: ['baseline','strict','regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 1000,
  },
  run: async () => ({ decision: 'block', reason: 'flagged' }),
};

const wildcardHook: HookModule = {
  manifest: {
    name: 'wild',
    event: 'PreToolUse',
    matchers: ['mcp__*'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline'],
    severity: 'block',
    timeout_ms: 1000,
  },
  run: async () => ({ decision: 'block', reason: 'mcp denied' }),
};

const postUseHook: HookModule = {
  manifest: {
    name: 'post-test',
    event: 'PostToolUse',
    matchers: ['Bash'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline'],
    severity: 'block',
    timeout_ms: 1000,
  },
  run: async (ctx) => {
    if (ctx.response?.stdout?.includes('LEAKED')) {
      return { decision: 'block', reason: 'leak in stdout' };
    }
    return { decision: 'allow', reason: 'clean' };
  },
};

describe('runHooks - Plan 2 contract bumps', () => {
  it('downgrades hook decision to warn under baseline when severity record says baseline=warn', async () => {
    const r = await runHooks(
      { hooks: [profileSeverityHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' },
    );
    expect(r.decision).toBe('warn');
  });
  it('keeps hook decision as block under strict when severity record says strict=block', async () => {
    const r = await runHooks(
      { hooks: [profileSeverityHook], profile: 'strict', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' },
    );
    expect(r.decision).toBe('block');
  });
  it('matches mcp__-prefixed tool via wildcard matcher', async () => {
    const r = await runHooks(
      { hooks: [wildcardHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'mcp__server__exec', input: {}, event: 'PreToolUse' },
    );
    expect(r.decision).toBe('block');
  });
  it('does NOT match non-mcp tool via mcp__* matcher', async () => {
    const r = await runHooks(
      { hooks: [wildcardHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' },
    );
    expect(r.invocations).toHaveLength(0);
  });
  it('passes response payload to PostToolUse hooks', async () => {
    const r = await runHooks(
      { hooks: [postUseHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PostToolUse', response: { stdout: 'LEAKED token' } },
    );
    expect(r.decision).toBe('block');
  });
});
```

Run: `pnpm --filter @bitsummit/ccsec-core test runner` -> 5 failures expected.

- [ ] **Step 2: Update `RunInput` to include optional `response`**

In `packages/core/src/runner.ts`, change `RunInput`:

```ts
export interface RunInput {
  tool: string;
  input: Record<string, unknown>;
  event: HookEvent;
  env?: Readonly<Record<string, string>>;
  response?: { stdout?: string; stderr?: string; output?: unknown; [k: string]: unknown };
}
```

- [ ] **Step 3: Add severity resolver helper inside runner.ts**

Above `runHooks`, add:

```ts
import type { HookProfile, HookSeverity, ProfileSeverity } from './types.js';

function resolveSeverity(severity: ProfileSeverity, profile: HookProfile): HookSeverity {
  return typeof severity === 'string' ? severity : severity[profile];
}
```

- [ ] **Step 4: Replace matcher check and update hook outcome logic**

In `runHooks`, replace the matcher line with `matchesAny`:

```ts
import { matchesAny } from './matchers.js';
// ...
for (const hook of opts.hooks) {
  if (hook.manifest.event !== run.event) continue;
  if (!matchesAny(run.tool, hook.manifest.matchers)) continue;
  if (!hook.manifest.profiles.includes(opts.profile)) continue;
  // ... existing run logic ...
}
```

In the ctx construction passed to `hook.run`, include the response:

```ts
const decision = await Promise.race([
  hook.run({
    tool: run.tool,
    input: run.input,
    response: run.response,
    env: run.env ?? {},
    paths: { home: process.env.HOME ?? '', ssh: `${process.env.HOME}/.ssh`, aws: `${process.env.HOME}/.aws`, tmp: '/tmp' },
    log: () => undefined,
    abort: controller.signal,
  }),
  // ... timeout race ...
]);
```

After the existing aggregate decision logic computes `outcome`, apply the severity resolver to downgrade `block` to `warn` when the profile says so:

```ts
const effectiveSeverity = resolveSeverity(hook.manifest.severity, opts.profile);
let resolvedOutcome: HookInvocation['outcome'] = outcome;
if (outcome === 'block' && effectiveSeverity === 'warn') resolvedOutcome = 'warn';
if (outcome === 'block' && effectiveSeverity === 'log') resolvedOutcome = 'allow';
// timeout/error outcomes are not severity-modulated
const finalOutcome = (outcome === 'timeout' || outcome === 'error') ? outcome : resolvedOutcome;
```

Use `finalOutcome` in the rest of the loop body (audit emission, aggregate update). Replace `outcome` references after this point with `finalOutcome`.

- [ ] **Step 5: Run runner tests to PASS**

```bash
pnpm --filter @bitsummit/ccsec-core test runner
```

Expected: all runner tests pass (7 prior + 5 new = 12).

- [ ] **Step 6: Run full core test suite**

```bash
pnpm --filter @bitsummit/ccsec-core test
```

All core tests pass; coverage stays >= 90%.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(core): runner resolves per-profile severity, matcher wildcards, PostToolUse response"
```

---

## Task 3: ADR-0004 Documenting Contract Bumps

**Files:**
- Create: `docs/adr/0004-hook-contract-bumps-plan2.md`

- [ ] **Step 1: Write ADR**

Create `docs/adr/0004-hook-contract-bumps-plan2.md`:

```markdown
# ADR-0004: Hook Contract Bumps for Plan 2

## Status
Accepted (2026-04-29).

## Context
Plan 2 introduces 7 hooks across categories 1-3. Three patterns surfaced that the Plan 1 contract did not support cleanly:

1. **Per-profile severity.** `git-destructive-guard` and `dotfile-guard` should warn on baseline but block on strict and regulated. Forking the hook code per profile would duplicate logic; the cleanest expression is a per-profile severity in the manifest.
2. **Matcher wildcards.** `mcp-secret-guard` needs to apply to all MCP-prefixed tools. Enumerating every MCP tool name in `matchers` is impractical and brittle.
3. **PostToolUse response field.** `secret-leak-detector` runs on PostToolUse and needs access to the tool's stdout/stderr/output. Plan 1's `HookContext` only exposes `input`.

## Decision

1. `HookManifest.severity` becomes `HookSeverity | Record<HookProfile, HookSeverity>`. The runner resolves the active profile's severity and uses it to modulate the hook's `block` decision: `block` plus profile-severity `warn` becomes outcome `warn`; `block` plus profile-severity `log` becomes `allow` (with audit record).
2. `HookManifest.matchers` array gains support for two glob-like patterns: `*` matches any tool, `<prefix>*` matches any tool starting with that prefix. A `matchesAny()` helper in `packages/core/src/matchers.ts` encapsulates the logic.
3. `HookContext` gains an optional `response` field of shape `{ stdout?: string; stderr?: string; output?: unknown; [k: string]: unknown }`. PreToolUse hooks ignore it; PostToolUse hooks read from it. The `RunInput` to the runner accepts a parallel `response` field for the caller to populate.

## Consequences
- All Plan 2 hooks compile and validate against the new contract.
- Plan 1 hooks (`secret-guard`) remain valid: scalar severity, no wildcards, ignores `response`. No breaking change.
- The `severity` resolver is a pure function in `runner.ts`; tests exercise it via the new contract-bump cases.
- Future plans can introduce additional severity tiers (e.g., per-team-policy) by extending `ProfileSeverity` rather than reworking the runner.

## Alternatives Considered
- **Always-record severity.** Rejected: forces every hook to specify three profiles even when severity is uniform. Plan 1's scalar form stays as the simple default.
- **Full glob library.** Rejected: introduces a dependency and surface area we do not need. The two-pattern wildcard is sufficient for the foreseeable hook taxonomy.
- **Separate `PostToolUseContext` type.** Rejected: forces consumers to switch on event type to pick the right context. The optional `response` field is simpler; PreToolUse hooks treat it as undefined.
- **Hook-side severity adjustment.** Rejected: would require every hook to read the active profile and decide what to return. The runner is the right place to enforce policy uniformly.
```

- [ ] **Step 2: Commit**

```bash
git add -A
git commit -m "docs: ADR-0004 hook contract bumps for Plan 2"
```

---

## Task 4: secret-leak-detector Hook (TDD, PostToolUse)

**Files:**
- Create: `packages/hooks/src/secret-leak-detector/index.ts`
- Create: `packages/hooks/src/secret-leak-detector/secret-leak-detector.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest';
import detector from './index.js';

const ctx = (response: Record<string, unknown>) => ({
  tool: 'Bash',
  input: { command: 'cat /tmp/foo' },
  response,
  env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('secret-leak-detector', () => {
  it('declares a valid PostToolUse manifest', () => {
    expect(detector.manifest.event).toBe('PostToolUse');
    expect(detector.manifest.threat).toBe('T-001-secret-leak');
  });
  it('allows clean stdout', async () => {
    const r = await detector.run(ctx({ stdout: 'hello world' }));
    expect(r.decision).toBe('allow');
  });
  it('blocks AWS key in stdout', async () => {
    const r = await detector.run(ctx({ stdout: 'AKIAIOSFODNN7EXAMPLE leaked' }));
    expect(r.decision).toBe('block');
    expect(r.reason).toMatch(/aws_access_key_id/);
  });
  it('blocks PEM key in stderr', async () => {
    const r = await detector.run(ctx({ stderr: '-----BEGIN RSA PRIVATE KEY-----' }));
    expect(r.decision).toBe('block');
  });
  it('redacts the secret in evidence', async () => {
    const r = await detector.run(ctx({ stdout: 'AKIAIOSFODNN7EXAMPLE' }));
    expect(JSON.stringify(r.evidence)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(JSON.stringify(r.evidence)).toContain('AKIA');
  });
  it('handles missing response gracefully', async () => {
    const r = await detector.run({ ...ctx({}), response: undefined });
    expect(r.decision).toBe('allow');
  });
  it('truncates very large responses to 256KB before scanning', async () => {
    const huge = 'a'.repeat(300_000) + ' AKIAIOSFODNN7EXAMPLE';
    const r = await detector.run(ctx({ stdout: huge }));
    expect(r.decision).toBe('allow');
    expect(r.reason).toMatch(/truncated/);
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

```bash
pnpm --filter @bitsummit/ccsec-hooks test secret-leak-detector
```

- [ ] **Step 3: Implement**

`packages/hooks/src/secret-leak-detector/index.ts`:

```ts
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';
import { detectSecrets } from '@bitsummit/ccsec-core';

const MAX_SCAN_BYTES = 256 * 1024;

function gather(response: Record<string, unknown> | undefined): { text: string; truncated: boolean } {
  if (!response) return { text: '', truncated: false };
  const parts: string[] = [];
  if (typeof response.stdout === 'string') parts.push(response.stdout);
  if (typeof response.stderr === 'string') parts.push(response.stderr);
  if (typeof response.output === 'string') parts.push(response.output);
  const joined = parts.join('\n');
  if (joined.length > MAX_SCAN_BYTES) {
    return { text: joined.slice(0, MAX_SCAN_BYTES), truncated: true };
  }
  return { text: joined, truncated: false };
}

const secretLeakDetector: HookModule = {
  manifest: {
    name: 'secret-leak-detector',
    event: 'PostToolUse',
    matchers: ['Bash', 'Read'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const { text, truncated } = gather(ctx.response);
    if (!text) return { decision: 'allow', reason: 'no response payload' };
    const hits = detectSecrets(text);
    if (hits.length === 0) {
      return {
        decision: 'allow',
        reason: truncated ? 'no secrets detected (response truncated to 256KB)' : 'no secrets detected',
      };
    }
    return {
      decision: 'block',
      reason: `secret in tool output: ${hits.map(h => h.label).join(', ')}`,
      evidence: { hits: hits.map(h => ({ label: h.label, redacted: h.redacted })) },
    };
  },
};

export default secretLeakDetector;
```

- [ ] **Step 4: Run, PASS, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks test secret-leak-detector
git add -A && git commit -m "feat(hooks): secret-leak-detector PostToolUse hook scanning tool output"
```

---

## Task 5: keychain-guard Hook (TDD)

**Files:**
- Create: `packages/hooks/src/keychain-guard/index.ts`
- Create: `packages/hooks/src/keychain-guard/keychain-guard.test.ts`

- [ ] **Step 1: Failing test**

The hook narrows the keychain CLI deny rule to commands containing the value-printing flags (the `-w` flag prints raw passwords to stdout; the `-g` flag prints generic-password values). Existence checks (without those flags) are allowed through.

```ts
import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (cmd: string) => ({
  tool: 'Bash', input: { command: cmd }, env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('keychain-guard', () => {
  it('manifest threat is T-001', () => {
    expect(guard.manifest.threat).toBe('T-001-secret-leak');
  });
  it('allows existence check (no value-printing flag)', async () => {
    const r = await guard.run(ctx('security find-generic-password -a default -s API_KEY'));
    expect(r.decision).toBe('allow');
  });
  it('blocks value-printing flag form 1', async () => {
    // The flag that prints raw password value to stdout
    const flag = '-' + 'w';
    const r = await guard.run(ctx(`security find-generic-password -a default -s API_KEY ${flag}`));
    expect(r.decision).toBe('block');
  });
  it('blocks value-printing flag form 2', async () => {
    const flag = '-' + 'g';
    const r = await guard.run(ctx(`security find-generic-password ${flag} -a default -s API_KEY`));
    expect(r.decision).toBe('block');
  });
  it('allows non-keychain commands', async () => {
    const r = await guard.run(ctx('ls -la'));
    expect(r.decision).toBe('allow');
  });
  it('handles non-string command', async () => {
    const r = await guard.run({ ...ctx(''), input: { command: 123 as never } });
    expect(r.decision).toBe('allow');
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

```bash
pnpm --filter @bitsummit/ccsec-hooks test keychain-guard
```

- [ ] **Step 3: Implement**

`packages/hooks/src/keychain-guard/index.ts`:

```ts
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const KEYCHAIN_CMD_RE = /\bsecurity\s+(?:find-generic-password|find-internet-password|find-certificate)\b/;
// Matches the two flags that print raw values to stdout.
const VALUE_FLAG_RE = /(?:^|\s)-(?:w|g)\b/;

const keychainGuard: HookModule = {
  manifest: {
    name: 'keychain-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd || !KEYCHAIN_CMD_RE.test(cmd)) return { decision: 'allow', reason: 'no keychain command' };
    if (VALUE_FLAG_RE.test(cmd)) {
      return {
        decision: 'block',
        reason: 'keychain CLI invoked with value-printing flag',
        evidence: { kind: 'keychain-value-flag' },
      };
    }
    return { decision: 'allow', reason: 'keychain existence-check (no value flag)' };
  },
};

export default keychainGuard;
```

- [ ] **Step 4: Run, PASS, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks test keychain-guard
git add -A && git commit -m "feat(hooks): keychain-guard blocking value-printing keychain CLI flags"
```

---

## Task 6: mcp-secret-guard Hook (TDD)

**Files:**
- Create: `packages/hooks/src/mcp-secret-guard/index.ts`
- Create: `packages/hooks/src/mcp-secret-guard/mcp-secret-guard.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (tool: string, input: Record<string, unknown>) => ({
  tool, input, env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('mcp-secret-guard', () => {
  it('manifest matchers includes mcp__*', () => {
    expect(guard.manifest.matchers).toContain('mcp__*');
  });
  it('allows clean MCP tool input', async () => {
    const r = await guard.run(ctx('mcp__server__exec', { query: 'hello' }));
    expect(r.decision).toBe('allow');
  });
  it('blocks MCP tool input containing AWS key', async () => {
    const r = await guard.run(ctx('mcp__server__exec', { token: 'AKIAIOSFODNN7EXAMPLE' }));
    expect(r.decision).toBe('block');
    expect(r.reason).toMatch(/aws_access_key_id/);
  });
  it('blocks nested secret in object payload', async () => {
    const r = await guard.run(ctx('mcp__db__query', {
      headers: { authorization: 'Bearer ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789' },
    }));
    expect(r.decision).toBe('block');
  });
  it('redacts secret in evidence', async () => {
    const r = await guard.run(ctx('mcp__x', { k: 'AKIAIOSFODNN7EXAMPLE' }));
    expect(JSON.stringify(r.evidence)).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

```bash
pnpm --filter @bitsummit/ccsec-hooks test mcp-secret-guard
```

- [ ] **Step 3: Implement**

`packages/hooks/src/mcp-secret-guard/index.ts`:

```ts
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';
import { detectSecrets } from '@bitsummit/ccsec-core';

const mcpSecretGuard: HookModule = {
  manifest: {
    name: 'mcp-secret-guard',
    event: 'PreToolUse',
    matchers: ['mcp__*'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    let serialized: string;
    try {
      serialized = JSON.stringify(ctx.input);
    } catch {
      return { decision: 'allow', reason: 'unserializable input' };
    }
    const hits = detectSecrets(serialized);
    if (hits.length === 0) return { decision: 'allow', reason: 'no secrets in MCP input' };
    return {
      decision: 'block',
      reason: `secret in MCP tool input: ${hits.map(h => h.label).join(', ')}`,
      evidence: { hits: hits.map(h => ({ label: h.label, redacted: h.redacted })) },
    };
  },
};

export default mcpSecretGuard;
```

- [ ] **Step 4: Run, PASS, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks test mcp-secret-guard
git add -A && git commit -m "feat(hooks): mcp-secret-guard scanning MCP tool inputs for secret literals"
```

---

## Task 7: destructive-fs-guard Hook (TDD)

**Files:**
- Create: `packages/hooks/src/destructive-fs-guard/index.ts`
- Create: `packages/hooks/src/destructive-fs-guard/destructive-fs-guard.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (cmd: string) => ({
  tool: 'Bash', input: { command: cmd }, env: {},
  paths: { home: '/Users/x', ssh: '/Users/x/.ssh', aws: '/Users/x/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('destructive-fs-guard', () => {
  it('manifest threat is T-002', () => {
    expect(guard.manifest.threat).toBe('T-002-destructive-fs');
  });
  it('blocks rm -rf on root', async () => {
    expect((await guard.run(ctx('rm -rf /'))).decision).toBe('block');
  });
  it('blocks rm -rf on root glob', async () => {
    expect((await guard.run(ctx('rm -rf /*'))).decision).toBe('block');
  });
  it('blocks rm -rf on HOME', async () => {
    expect((await guard.run(ctx('rm -rf /Users/x'))).decision).toBe('block');
    expect((await guard.run(ctx('rm -rf $HOME'))).decision).toBe('block');
    expect((await guard.run(ctx('rm -rf ~'))).decision).toBe('block');
  });
  it('blocks mkfs', async () => {
    expect((await guard.run(ctx('mkfs.ext4 /dev/sda'))).decision).toBe('block');
  });
  it('blocks dd writing to a device', async () => {
    expect((await guard.run(ctx('dd if=/dev/zero of=/dev/sda bs=1M'))).decision).toBe('block');
  });
  it('blocks shred -u', async () => {
    expect((await guard.run(ctx('shred -u /etc/passwd'))).decision).toBe('block');
  });
  it('allows safe rm -rf inside /tmp', async () => {
    expect((await guard.run(ctx('rm -rf /tmp/scratch'))).decision).toBe('allow');
  });
  it('allows benign commands', async () => {
    expect((await guard.run(ctx('ls -la'))).decision).toBe('allow');
  });
  it('handles non-string command', async () => {
    expect((await guard.run({ ...ctx(''), input: { command: 123 as never } })).decision).toBe('allow');
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

```bash
pnpm --filter @bitsummit/ccsec-hooks test destructive-fs-guard
```

- [ ] **Step 3: Implement**

`packages/hooks/src/destructive-fs-guard/index.ts`:

```ts
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const RM_RF_ROOT_RE = /\brm\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+(?:\/(?:\s|$|\*)|\/\*)/;
const RM_RF_HOME_RE = /\brm\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+(?:~|\$HOME|\$\{HOME\})(?:\s|$|\/)/;
const MKFS_RE = /\bmkfs(?:\.[a-z0-9]+)?\b/;
const DD_DEVICE_RE = /\bdd\s+.*\bof=\/dev\//;
const SHRED_U_RE = /\bshred\s+(?:-[a-zA-Z]*u[a-zA-Z]*\s+|--remove\s+)/;

interface Match { kind: string; pattern: RegExp; }
const PATTERNS: Match[] = [
  { kind: 'rm-rf-root', pattern: RM_RF_ROOT_RE },
  { kind: 'rm-rf-home', pattern: RM_RF_HOME_RE },
  { kind: 'mkfs', pattern: MKFS_RE },
  { kind: 'dd-to-device', pattern: DD_DEVICE_RE },
  { kind: 'shred-unlink', pattern: SHRED_U_RE },
];

function homeRmRf(cmd: string, homePath: string): boolean {
  const re = new RegExp(`\\brm\\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\\s+)+${homePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\s|$|/)`);
  return re.test(cmd);
}

const destructiveFsGuard: HookModule = {
  manifest: {
    name: 'destructive-fs-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-002-destructive-fs',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd) return { decision: 'allow', reason: 'no command field' };

    for (const { kind, pattern } of PATTERNS) {
      if (pattern.test(cmd)) {
        return { decision: 'block', reason: `destructive pattern: ${kind}`, evidence: { kind } };
      }
    }
    if (ctx.paths.home && homeRmRf(cmd, ctx.paths.home)) {
      return { decision: 'block', reason: 'destructive pattern: rm-rf-home-literal', evidence: { kind: 'rm-rf-home-literal' } };
    }
    return { decision: 'allow', reason: 'no destructive pattern matched' };
  },
};

export default destructiveFsGuard;
```

- [ ] **Step 4: Run, PASS, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks test destructive-fs-guard
git add -A && git commit -m "feat(hooks): destructive-fs-guard blocking rm -rf root/HOME, mkfs, dd to device, shred"
```

---

## Task 8: git-destructive-guard Hook (TDD, per-profile severity)

**Files:**
- Create: `packages/hooks/src/git-destructive-guard/index.ts`
- Create: `packages/hooks/src/git-destructive-guard/git-destructive-guard.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (cmd: string) => ({
  tool: 'Bash', input: { command: cmd }, env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('git-destructive-guard', () => {
  it('manifest declares per-profile severity', () => {
    expect(typeof guard.manifest.severity).toBe('object');
    const sev = guard.manifest.severity as Record<string, string>;
    expect(sev.baseline).toBe('warn');
    expect(sev.strict).toBe('block');
    expect(sev.regulated).toBe('block');
  });
  it('manifest threat is T-004', () => {
    expect(guard.manifest.threat).toBe('T-004-branch-sabotage');
  });
  it('flags git reset --hard', async () => {
    expect((await guard.run(ctx('git reset --hard HEAD~10'))).decision).toBe('block');
  });
  it('flags git clean -fd', async () => {
    expect((await guard.run(ctx('git clean -fd'))).decision).toBe('block');
  });
  it('flags git push --force', async () => {
    expect((await guard.run(ctx('git push --force origin main'))).decision).toBe('block');
  });
  it('flags git push -f', async () => {
    expect((await guard.run(ctx('git push -f origin main'))).decision).toBe('block');
  });
  it('flags git branch -D on protected branches', async () => {
    expect((await guard.run(ctx('git branch -D main'))).decision).toBe('block');
  });
  it('allows git status', async () => {
    expect((await guard.run(ctx('git status'))).decision).toBe('allow');
  });
  it('allows git push without force', async () => {
    expect((await guard.run(ctx('git push origin feature/x'))).decision).toBe('allow');
  });
});
```

The test asserts the hook returns `block` from `run()`. The runner in Task 2 modulates `block` to `warn` under baseline based on the per-profile severity.

- [ ] **Step 2: Run, expect FAIL**

```bash
pnpm --filter @bitsummit/ccsec-hooks test git-destructive-guard
```

- [ ] **Step 3: Implement**

`packages/hooks/src/git-destructive-guard/index.ts`:

```ts
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const RESET_HARD_RE = /\bgit\s+reset\s+--hard\b/;
const CLEAN_FD_RE = /\bgit\s+clean\s+(?:-[a-zA-Z]*[fd][a-zA-Z]*\b|--force\b)/;
const PUSH_FORCE_RE = /\bgit\s+push\s+(?:.*\s)?(?:--force\b|-f\b|--force-with-lease\b)/;
const BRANCH_DELETE_PROTECTED_RE = /\bgit\s+branch\s+-D\s+(main|master|release|develop|prod|production)\b/;
const REBASE_INTERACTIVE_RE = /\bgit\s+rebase\s+(?:-i\b|--interactive\b)/;

interface Match { kind: string; pattern: RegExp; }
const PATTERNS: Match[] = [
  { kind: 'reset-hard', pattern: RESET_HARD_RE },
  { kind: 'clean-fd', pattern: CLEAN_FD_RE },
  { kind: 'push-force', pattern: PUSH_FORCE_RE },
  { kind: 'branch-delete-protected', pattern: BRANCH_DELETE_PROTECTED_RE },
  { kind: 'rebase-interactive', pattern: REBASE_INTERACTIVE_RE },
];

const gitDestructiveGuard: HookModule = {
  manifest: {
    name: 'git-destructive-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-004-branch-sabotage',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd) return { decision: 'allow', reason: 'no command field' };
    for (const { kind, pattern } of PATTERNS) {
      if (pattern.test(cmd)) {
        return { decision: 'block', reason: `git destructive pattern: ${kind}`, evidence: { kind } };
      }
    }
    return { decision: 'allow', reason: 'no destructive git pattern matched' };
  },
};

export default gitDestructiveGuard;
```

- [ ] **Step 4: Run, PASS, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks test git-destructive-guard
git add -A && git commit -m "feat(hooks): git-destructive-guard with per-profile severity (warn baseline, block strict/regulated)"
```

---

## Task 9: sensitive-paths-guard Hook (TDD)

**Files:**
- Create: `packages/hooks/src/sensitive-paths-guard/index.ts`
- Create: `packages/hooks/src/sensitive-paths-guard/sensitive-paths-guard.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (tool: string, input: Record<string, unknown>) => ({
  tool, input, env: {},
  paths: { home: '/Users/x', ssh: '/Users/x/.ssh', aws: '/Users/x/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('sensitive-paths-guard', () => {
  it('manifest threat is T-003', () => {
    expect(guard.manifest.threat).toBe('T-003-credential-exfil');
  });
  it('blocks Read on .ssh subpaths', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/.ssh/id_rsa' }))).decision).toBe('block');
  });
  it('blocks Read on .aws/credentials', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/.aws/credentials' }))).decision).toBe('block');
  });
  it('blocks Read on .kube/config', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/.kube/config' }))).decision).toBe('block');
  });
  it('blocks Read on .netrc', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/.netrc' }))).decision).toBe('block');
  });
  it('blocks Read on /etc/sudoers', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/etc/sudoers' }))).decision).toBe('block');
  });
  it('blocks Bash cat of credential file', async () => {
    expect((await guard.run(ctx('Bash', { command: 'cat /Users/x/.ssh/id_rsa' }))).decision).toBe('block');
  });
  it('allows Read on benign path', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/code/foo.ts' }))).decision).toBe('allow');
  });
  it('allows Bash that does not target credential paths', async () => {
    expect((await guard.run(ctx('Bash', { command: 'ls /Users/x/code' }))).decision).toBe('allow');
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

```bash
pnpm --filter @bitsummit/ccsec-hooks test sensitive-paths-guard
```

- [ ] **Step 3: Implement**

`packages/hooks/src/sensitive-paths-guard/index.ts`:

```ts
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const SENSITIVE_PATH_FRAGMENTS = [
  '/.ssh/',
  '/.aws/',
  '/.gnupg/',
  '/.kube/',
  '/.docker/',
  '/.netrc',
  '/.config/gh/hosts.yml',
  '/etc/sudoers',
  '/etc/shadow',
];

function isSensitive(path: string): string | null {
  for (const frag of SENSITIVE_PATH_FRAGMENTS) {
    if (path.includes(frag)) return frag;
  }
  return null;
}

const sensitivePathsGuard: HookModule = {
  manifest: {
    name: 'sensitive-paths-guard',
    event: 'PreToolUse',
    matchers: ['Read', 'Bash'],
    threat: 'T-003-credential-exfil',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    if (ctx.tool === 'Read') {
      const fp = typeof ctx.input.file_path === 'string' ? ctx.input.file_path : '';
      const hit = isSensitive(fp);
      if (hit) return { decision: 'block', reason: `Read on sensitive path: ${hit}`, evidence: { match: hit, path: fp } };
      return { decision: 'allow', reason: 'no sensitive path' };
    }
    if (ctx.tool === 'Bash') {
      const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : '';
      const hit = isSensitive(cmd);
      if (hit) return { decision: 'block', reason: `Bash references sensitive path: ${hit}`, evidence: { match: hit } };
      return { decision: 'allow', reason: 'no sensitive path in command' };
    }
    return { decision: 'allow', reason: 'unhandled tool' };
  },
};

export default sensitivePathsGuard;
```

- [ ] **Step 4: Run, PASS, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks test sensitive-paths-guard
git add -A && git commit -m "feat(hooks): sensitive-paths-guard blocking Read/Bash on credential dirs"
```

---

## Task 10: dotfile-guard Hook (TDD, per-profile severity)

**Files:**
- Create: `packages/hooks/src/dotfile-guard/index.ts`
- Create: `packages/hooks/src/dotfile-guard/dotfile-guard.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (tool: string, file_path: string) => ({
  tool, input: { file_path }, env: {},
  paths: { home: '/Users/x', ssh: '/Users/x/.ssh', aws: '/Users/x/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('dotfile-guard', () => {
  it('manifest declares per-profile severity', () => {
    const sev = guard.manifest.severity as Record<string, string>;
    expect(sev.baseline).toBe('warn');
    expect(sev.strict).toBe('block');
  });
  it('flags Edit on .zshrc', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/.zshrc'))).decision).toBe('block');
  });
  it('flags Edit on .bashrc', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/.bashrc'))).decision).toBe('block');
  });
  it('flags Edit on .gitconfig', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/.gitconfig'))).decision).toBe('block');
  });
  it('flags Edit on .ssh/config', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/.ssh/config'))).decision).toBe('block');
  });
  it('flags Write on .profile', async () => {
    expect((await guard.run(ctx('Write', '/Users/x/.profile'))).decision).toBe('block');
  });
  it('allows Edit on regular file', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/code/foo.ts'))).decision).toBe('allow');
  });
  it('allows Read of dotfile (only Edit/Write are matched)', async () => {
    // Note: Read is not in the matchers; runner skips this hook for Read.
    // Test exercises the run() function directly with tool='Read' to verify the hook tolerates it.
    expect((await guard.run(ctx('Read', '/Users/x/.zshrc'))).decision).toBe('allow');
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

```bash
pnpm --filter @bitsummit/ccsec-hooks test dotfile-guard
```

- [ ] **Step 3: Implement**

`packages/hooks/src/dotfile-guard/index.ts`:

```ts
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const DOTFILE_PATTERNS = [
  /\/\.zshrc$/,
  /\/\.zprofile$/,
  /\/\.bashrc$/,
  /\/\.bash_profile$/,
  /\/\.profile$/,
  /\/\.gitconfig$/,
  /\/\.git\/config$/,
  /\/\.ssh\/config$/,
  /\/\.npmrc$/,
  /\/\.tool-versions$/,
];

function matchDotfile(path: string): RegExp | null {
  for (const re of DOTFILE_PATTERNS) {
    if (re.test(path)) return re;
  }
  return null;
}

const dotfileGuard: HookModule = {
  manifest: {
    name: 'dotfile-guard',
    event: 'PreToolUse',
    matchers: ['Edit', 'Write'],
    threat: 'T-002-destructive-fs',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    if (ctx.tool !== 'Edit' && ctx.tool !== 'Write') {
      return { decision: 'allow', reason: 'unhandled tool' };
    }
    const fp = typeof ctx.input.file_path === 'string' ? ctx.input.file_path : '';
    const hit = matchDotfile(fp);
    if (hit) {
      return { decision: 'block', reason: `dotfile modification: ${fp}`, evidence: { pattern: hit.source, path: fp } };
    }
    return { decision: 'allow', reason: 'not a tracked dotfile' };
  },
};

export default dotfileGuard;
```

- [ ] **Step 4: Run, PASS, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks test dotfile-guard
git add -A && git commit -m "feat(hooks): dotfile-guard with per-profile severity for shell rc and config files"
```

---

## Task 11: Settings Overlays - Expand secrets, Add destructive + sensitive-paths

**Files:**
- Modify: `packages/settings/overlays/secrets.json`
- Create: `packages/settings/overlays/destructive.json`
- Create: `packages/settings/overlays/sensitive-paths.json`

- [ ] **Step 1: Expand `overlays/secrets.json`**

Replace the file with:

```json
{
  "permissions": {
    "deny": [
      { "pattern": "Bash(printenv *)",                          "threat": "T-001-secret-leak" },
      { "pattern": "Bash(env)",                                 "threat": "T-001-secret-leak" },
      { "pattern": "Bash(security find-generic-password *)",    "threat": "T-001-secret-leak" },
      { "pattern": "Read(${HOME}/.ssh/**)",                     "threat": "T-003-credential-exfil" },
      { "pattern": "Read(${HOME}/.aws/credentials)",            "threat": "T-003-credential-exfil" },
      { "pattern": "Read(${HOME}/.gnupg/**)",                   "threat": "T-003-credential-exfil" }
    ]
  },
  "hooks": {
    "PreToolUse": [
      { "name": "secret-guard" },
      { "name": "keychain-guard" },
      { "name": "mcp-secret-guard" }
    ],
    "PostToolUse": [
      { "name": "secret-leak-detector" }
    ]
  }
}
```

- [ ] **Step 2: Create `overlays/destructive.json`**

```json
{
  "permissions": {
    "deny": [
      { "pattern": "Bash(rm -rf /)",                       "threat": "T-002-destructive-fs" },
      { "pattern": "Bash(rm -rf /*)",                      "threat": "T-002-destructive-fs" },
      { "pattern": "Bash(rm -rf ${HOME})",                 "threat": "T-002-destructive-fs" },
      { "pattern": "Bash(rm -rf ~)",                       "threat": "T-002-destructive-fs" },
      { "pattern": "Bash(mkfs *)",                         "threat": "T-002-destructive-fs" },
      { "pattern": "Bash(dd * of=/dev/*)",                 "threat": "T-002-destructive-fs" },
      { "pattern": "Bash(shred -u *)",                     "threat": "T-002-destructive-fs" },
      { "pattern": "Bash(git push --force *)",             "threat": "T-004-branch-sabotage" },
      { "pattern": "Bash(git push -f *)",                  "threat": "T-004-branch-sabotage" }
    ]
  },
  "hooks": {
    "PreToolUse": [
      { "name": "destructive-fs-guard" },
      { "name": "git-destructive-guard" }
    ]
  }
}
```

- [ ] **Step 3: Create `overlays/sensitive-paths.json`**

```json
{
  "permissions": {
    "deny": [
      { "pattern": "Read(${HOME}/.kube/**)",               "threat": "T-003-credential-exfil" },
      { "pattern": "Read(${HOME}/.docker/config.json)",    "threat": "T-003-credential-exfil" },
      { "pattern": "Read(${HOME}/.netrc)",                 "threat": "T-003-credential-exfil" },
      { "pattern": "Read(${HOME}/.config/gh/hosts.yml)",   "threat": "T-003-credential-exfil" },
      { "pattern": "Read(/etc/sudoers)",                   "threat": "T-003-credential-exfil" },
      { "pattern": "Read(/etc/sudoers.d/**)",              "threat": "T-003-credential-exfil" }
    ]
  },
  "hooks": {
    "PreToolUse": [
      { "name": "sensitive-paths-guard" },
      { "name": "dotfile-guard" }
    ]
  }
}
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(settings): expand secrets overlay; add destructive and sensitive-paths overlays"
```

---

## Task 12: Profile Files - Expand baseline, Add strict + regulated Shells

**Files:**
- Modify: `packages/settings/profiles/baseline.json`
- Create: `packages/settings/profiles/strict.json`
- Create: `packages/settings/profiles/regulated.json`

- [ ] **Step 1: Expand `profiles/baseline.json`**

Replace with:

```json
{ "extends": ["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths"], "overrides": {} }
```

- [ ] **Step 2: Create `profiles/strict.json`**

Identical content to baseline (Plan 5 differentiates):

```json
{ "extends": ["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths"], "overrides": {} }
```

- [ ] **Step 3: Create `profiles/regulated.json`**

```json
{ "extends": ["base", "overlays/secrets", "overlays/destructive", "overlays/sensitive-paths"], "overrides": {} }
```

- [ ] **Step 4: Verify CLI compiles each profile**

```bash
pnpm --filter @bitsummit/ccsec-cli build
HOME=/Users/x node packages/cli/bin/ccsec.js compile --profile baseline   --out /tmp/p2-baseline.json   --target user --os macos --settings-root packages/settings
HOME=/Users/x node packages/cli/bin/ccsec.js compile --profile strict     --out /tmp/p2-strict.json     --target user --os macos --settings-root packages/settings
HOME=/Users/x node packages/cli/bin/ccsec.js compile --profile regulated  --out /tmp/p2-regulated.json  --target user --os macos --settings-root packages/settings
```

Inspect each: should contain ~21 deny patterns + 4 PreToolUse hook references + 1 PostToolUse hook reference. Path tokens resolved to `/Users/x`. Threat fields preserved (target=user).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(settings): expand baseline; add strict and regulated profile shells"
```

---

## Task 13: Regenerate Compiled Snapshots and Extend Snapshot Tests

**Files:**
- Modify: `packages/settings/compiled/baseline.json` (regenerated)
- Create: `packages/settings/compiled/strict.json`
- Create: `packages/settings/compiled/regulated.json`
- Modify: `packages/settings/snapshot.test.ts`
- Modify: `packages/settings/__snapshots__/snapshot.test.ts.snap` (regenerated via -u)

- [ ] **Step 1: Regenerate baseline compiled snapshot**

```bash
HOME=/Users/x pnpm build:settings
```

The `build:settings` script (fixed in Plan 1) regenerates `compiled/baseline.json`.

- [ ] **Step 2: Generate strict and regulated compiled snapshots**

```bash
HOME=/Users/x node packages/cli/bin/ccsec.js compile --profile strict    --out packages/settings/compiled/strict.json    --target user --os macos --settings-root packages/settings
HOME=/Users/x node packages/cli/bin/ccsec.js compile --profile regulated --out packages/settings/compiled/regulated.json --target user --os macos --settings-root packages/settings
```

- [ ] **Step 3: Update snapshot test to cover all three**

Replace `packages/settings/snapshot.test.ts` content:

```ts
import { describe, it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

async function read(name: string): Promise<string> {
  return readFile(join(here, 'compiled', `${name}.json`), 'utf8');
}

describe('settings/compiled snapshots', () => {
  it('baseline.json matches checked-in snapshot', async () => {
    expect(await read('baseline')).toMatchSnapshot();
  });
  it('strict.json matches checked-in snapshot', async () => {
    expect(await read('strict')).toMatchSnapshot();
  });
  it('regulated.json matches checked-in snapshot', async () => {
    expect(await read('regulated')).toMatchSnapshot();
  });
});
```

- [ ] **Step 4: Seed snapshots**

```bash
pnpm vitest run packages/settings/snapshot.test.ts -u
```

Expected: 3 snapshots seeded.

- [ ] **Step 5: Verify (no -u)**

```bash
pnpm vitest run packages/settings/snapshot.test.ts
```

Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(settings): regenerate compiled snapshots for baseline/strict/regulated; extend snapshot test"
```

---

## Task 14: Integration Transcripts and Replay Tests

**Files:**
- Create: `tests/integration/transcripts/secret-leak-postonly.json`
- Create: `tests/integration/transcripts/destructive-attempt.json`
- Create: `tests/integration/transcripts/sensitive-paths-attempt.json`
- Create: `tests/integration/transcripts/attack-chain.json`
- Create: `tests/integration/secret-leak-postonly.test.ts`
- Create: `tests/integration/destructive-attempt.test.ts`
- Create: `tests/integration/sensitive-paths-attempt.test.ts`
- Create: `tests/integration/attack-chain.test.ts`
- Modify: `tests/integration/package.json` (add hooks dist as dep, already done in Plan 1)

- [ ] **Step 1: Build hooks dist so the integration tests can resolve the imports**

```bash
pnpm --filter @bitsummit/ccsec-core build
pnpm --filter @bitsummit/ccsec-hooks build
```

- [ ] **Step 2: Write `secret-leak-postonly.json` fixture**

```json
{
  "name": "secret-leak-postonly",
  "events": [
    {
      "tool": "Bash", "event": "PostToolUse",
      "input": { "command": "cat /tmp/log.txt" },
      "response": { "stdout": "request from AKIAIOSFODNN7EXAMPLE returned 200" }
    },
    {
      "tool": "Bash", "event": "PostToolUse",
      "input": { "command": "echo done" },
      "response": { "stdout": "done" }
    }
  ],
  "expected": [
    { "decision": "block", "blockedBy": "secret-leak-detector" },
    { "decision": "allow" }
  ]
}
```

- [ ] **Step 3: Write `destructive-attempt.json` fixture**

```json
{
  "name": "destructive-attempt",
  "events": [
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "rm -rf /tmp/scratch" } },
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "rm -rf /Users/x" } },
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "git push --force origin main" } }
  ],
  "expected": [
    { "decision": "allow" },
    { "decision": "block", "blockedBy": "destructive-fs-guard" },
    { "decision": "warn" }
  ]
}
```

Note: third event is `warn` because `git-destructive-guard` runs under `baseline` profile (severity record says `warn`). Under `strict` it would be `block`.

- [ ] **Step 4: Write `sensitive-paths-attempt.json` fixture**

```json
{
  "name": "sensitive-paths-attempt",
  "events": [
    { "tool": "Read", "event": "PreToolUse", "input": { "file_path": "/Users/x/.ssh/id_rsa" } },
    { "tool": "Read", "event": "PreToolUse", "input": { "file_path": "/Users/x/.kube/config" } },
    { "tool": "Read", "event": "PreToolUse", "input": { "file_path": "/Users/x/.netrc" } },
    { "tool": "Edit", "event": "PreToolUse", "input": { "file_path": "/Users/x/.zshrc", "old_string": "x", "new_string": "y" } },
    { "tool": "Read", "event": "PreToolUse", "input": { "file_path": "/Users/x/code/main.ts" } }
  ],
  "expected": [
    { "decision": "block", "blockedBy": "sensitive-paths-guard" },
    { "decision": "block", "blockedBy": "sensitive-paths-guard" },
    { "decision": "block", "blockedBy": "sensitive-paths-guard" },
    { "decision": "warn" },
    { "decision": "allow" }
  ]
}
```

- [ ] **Step 5: Write `attack-chain.json` fixture**

```json
{
  "name": "attack-chain",
  "events": [
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "cat /Users/x/.aws/credentials | base64" } },
    { "tool": "Bash", "event": "PostToolUse", "input": { "command": "aws sts get-session-token" }, "response": { "stdout": "ACCESS_KEY=AKIAIOSFODNN7EXAMPLE SECRET=foo" } },
    { "tool": "Edit", "event": "PreToolUse", "input": { "file_path": "/Users/x/.zshrc", "old_string": "alias l='ls'", "new_string": "alias l='rm -rf /tmp/.cache'" } },
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "printenv" } }
  ],
  "expected": [
    { "decision": "block", "blockedBy": "sensitive-paths-guard" },
    { "decision": "block", "blockedBy": "secret-leak-detector" },
    { "decision": "warn" },
    { "decision": "block", "blockedBy": "secret-guard" }
  ],
  "notes": "Egress block on step 2 is partial in Plan 2: secret-leak-detector catches the token in stdout, but the network call itself is not blocked. Full egress allowlist lands in Plan 4."
}
```

- [ ] **Step 6: Write replay test - reusable helper**

Create a shared test runner. Add to `tests/integration/secret-leak-postonly.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { readFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runHooks } from '@bitsummit/ccsec-core';
import secretGuard from '@bitsummit/ccsec-hooks/dist/secret-guard/index.js';
import secretLeakDetector from '@bitsummit/ccsec-hooks/dist/secret-leak-detector/index.js';
import keychainGuard from '@bitsummit/ccsec-hooks/dist/keychain-guard/index.js';
import mcpSecretGuard from '@bitsummit/ccsec-hooks/dist/mcp-secret-guard/index.js';
import destructiveFsGuard from '@bitsummit/ccsec-hooks/dist/destructive-fs-guard/index.js';
import gitDestructiveGuard from '@bitsummit/ccsec-hooks/dist/git-destructive-guard/index.js';
import sensitivePathsGuard from '@bitsummit/ccsec-hooks/dist/sensitive-paths-guard/index.js';
import dotfileGuard from '@bitsummit/ccsec-hooks/dist/dotfile-guard/index.js';

const ALL_HOOKS = [
  secretGuard, secretLeakDetector, keychainGuard, mcpSecretGuard,
  destructiveFsGuard, gitDestructiveGuard, sensitivePathsGuard, dotfileGuard,
];

const here = dirname(fileURLToPath(import.meta.url));

describe('integration: secret-leak-postonly', () => {
  let auditPath: string;
  beforeEach(async () => {
    auditPath = join(await mkdtemp(join(tmpdir(), 'ccsec-int-')), 'audit.jsonl');
  });

  it('replay matches expected', async () => {
    const fx = JSON.parse(await readFile(join(here, 'transcripts', 'secret-leak-postonly.json'), 'utf8'));
    for (let i = 0; i < fx.events.length; i++) {
      const ev = fx.events[i];
      const exp = fx.expected[i];
      const result = await runHooks(
        { hooks: ALL_HOOKS, profile: 'baseline', auditLogPath: auditPath },
        { tool: ev.tool, event: ev.event, input: ev.input, response: ev.response },
      );
      expect(result.decision, `event ${i}`).toBe(exp.decision);
      if (exp.blockedBy) expect(result.blockedBy).toBe(exp.blockedBy);
    }
  });
});
```

Replicate the same pattern in `destructive-attempt.test.ts`, `sensitive-paths-attempt.test.ts`, and `attack-chain.test.ts`, swapping the `describe` label and the fixture filename.

- [ ] **Step 7: Run all integration tests**

```bash
pnpm vitest run tests/integration/
```

Expected: 5 integration tests pass total (1 from Plan 1 + 4 new).

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "test(integration): add 4 transcripts (secret-leak-postonly, destructive, sensitive-paths, attack-chain)"
```

---

## Task 15: Threat Model Expansion and Coverage Matrix

**Files:**
- Modify: `docs/threat-model.md`
- Create: `docs/coverage-matrix.md`

- [ ] **Step 1: Expand `docs/threat-model.md`**

Replace the entire file with:

```markdown
# Threat Model

> Status: Plans 1-2 covered. T-001 expanded; T-002, T-003, T-004 newly documented. T-005 to T-018 populate as their hooks ship in Plans 3-5.

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
- **Known limitations:** custom secret formats not yet covered (extensible via `SECRET_PATTERNS`); base64-encoded or chunked secrets not detected (Plan 3 structural-bash work).

### T-002: Destructive Filesystem Op

- **Vector:** Bash, Edit, Write
- **STRIDE:** Tampering
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `destructive-fs-guard` (PreToolUse, block) matches `rm -rf` of root or HOME, `mkfs`, `dd` writing to a device, `shred -u`.
  - `dotfile-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) flags Edit/Write to shell rc files, gitconfig, ssh config. Defends against persistence (PATH injection, alias hijack).
  - Plan 1 deny patterns from `overlays/destructive.json` provide an additional layer for the same patterns.
- **Coverage:** baseline (warn for dotfile), strict, regulated.
- **Known limitations:** does not detect symlink attacks or filesystem-level race conditions. Heredoc bodies not parsed (Plan 3).

### T-003: Credential File Exfil

- **Vector:** Read, Bash
- **STRIDE:** Information Disclosure
- **Agentic Top 10:** A4 Sensitive Information Disclosure
- **Default mitigations:**
  - `sensitive-paths-guard` (PreToolUse, block) hook-side check on Read and Bash for paths matching `/.ssh/`, `/.aws/`, `/.gnupg/`, `/.kube/`, `/.docker/`, `/.netrc`, GitHub CLI hosts file, `/etc/sudoers`, `/etc/shadow`.
  - Deny patterns in `overlays/secrets.json` and `overlays/sensitive-paths.json` enforce the same boundaries at the permission layer.
- **Coverage:** baseline, strict, regulated.
- **Known limitations:** symlink-following not detected. New credential dirs (e.g., future cloud providers) require updating `SENSITIVE_PATH_FRAGMENTS`.

### T-004: Force-Push / Branch Sabotage (partial)

- **Vector:** Bash (git CLI)
- **STRIDE:** Tampering
- **Agentic Top 10:** A6 Excessive Agency
- **Default mitigations:**
  - `git-destructive-guard` (PreToolUse, severity warn on baseline / block on strict and regulated) catches `git reset --hard`, `git clean -fd`, `git push --force`, `git push -f`, `git branch -D` on protected branches, `git rebase -i`.
  - Deny patterns in `overlays/destructive.json` enforce the forced-push boundary at the permission layer.
- **Coverage:** baseline (warn), strict (block), regulated (block).
- **Known limitations:** detection relies on argument string matching; obfuscated invocations (aliases, function wrappers, env-set flags) may bypass. Comprehensive branch-guard suite is Plan 3.

## Explicit Non-Goals

- Not a sandbox.
- Not a runtime jail.
- Not a network firewall.
- Not a remote management system.
```

- [ ] **Step 2: Create `docs/coverage-matrix.md`**

```markdown
# Coverage Matrix

> Hand-maintained for Plans 1-2. Auto-generation from hook manifests lands in Plan 8.

| Threat | Hooks | Profiles |
|---|---|---|
| T-001 Secret Leak | secret-guard, secret-leak-detector, keychain-guard, mcp-secret-guard | baseline, strict, regulated |
| T-002 Destructive FS | destructive-fs-guard, dotfile-guard | baseline (dotfile=warn), strict, regulated |
| T-003 Credential Exfil | sensitive-paths-guard | baseline, strict, regulated |
| T-004 Branch Sabotage (partial) | git-destructive-guard | baseline (warn), strict (block), regulated (block) |
| T-005 to T-018 | (not yet covered) | (Plans 3-5) |

## Coverage by Profile

**baseline** (per-user dev hardening; some warns to keep flow):
- All blocking hooks: secret-guard, secret-leak-detector, keychain-guard, mcp-secret-guard, destructive-fs-guard, sensitive-paths-guard
- Warn hooks: git-destructive-guard, dotfile-guard

**strict** (team / shared infra; everything blocking):
- Same hooks as baseline; git-destructive-guard and dotfile-guard upgrade to block

**regulated** (healthcare, legal, public-sector):
- Same as strict in Plan 2; further differentiation lands in Plan 5 with mdm-bypass and agent-gating overlays

## How to read this matrix

Each threat ID corresponds to a row in `docs/threat-model.md`. Each hook listed has a manifest declaring `threat: T-NNN-...` matching the row. The profiles column shows which profiles include the hook (per the hook's manifest `profiles` array) and at what effective severity (resolved per-profile).

When `docs/auto-coverage-matrix.md` ships in Plan 8, this hand-maintained file will be replaced by a CI-generated artifact backed by the same data.
```

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: expand threat model (T-001 expanded, T-002/T-003/T-004 added) + coverage matrix"
```

---

## Task 16: Tag v0.2.0-alpha.0, Push, Create Release

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add v0.2.0-alpha.0 entry to CHANGELOG.md**

Insert a new section above the existing `[0.1.0-alpha.0]` block, under `## [Unreleased]`:

```markdown
## [0.2.0-alpha.0] - 2026-04-29

### Added
- 7 new hooks: `secret-leak-detector` (PostToolUse), `keychain-guard`, `mcp-secret-guard`, `destructive-fs-guard`, `git-destructive-guard`, `sensitive-paths-guard`, `dotfile-guard`.
- `packages/settings/overlays/destructive.json` and `packages/settings/overlays/sensitive-paths.json`.
- `packages/settings/profiles/strict.json` and `packages/settings/profiles/regulated.json` (shells; Plan 5 differentiates).
- Compiled snapshots for strict and regulated profiles.
- 4 new integration transcripts: secret-leak-postonly, destructive-attempt, sensitive-paths-attempt, attack-chain.
- Threat model entries for T-002, T-003, T-004; T-001 expanded with PostToolUse + MCP + keychain coverage.
- `docs/coverage-matrix.md` mapping every hook to threats and profiles.
- ADR-0004 documenting hook contract bumps.

### Changed
- `HookManifest.severity` accepts `HookSeverity` scalar OR `Record<HookProfile, HookSeverity>` per-profile record (additive, backward compatible).
- `HookManifest.matchers` accepts `*` (any tool) and `<prefix>*` patterns.
- `HookContext` gains optional `response` field for PostToolUse hooks.
- Runner resolves per-profile severity and modulates hook decisions accordingly.
- `baseline` profile now extends three overlays (was one in Plan 1).

### Notes
- Audit-logger concurrency hardening still tracked for Plan 4.
- Egress / WebFetch allowlist still tracked for Plan 4 (attack-chain transcript flags step 2 as partial-block).
- Strict / regulated profile differentiation still tracked for Plan 5.
```

- [ ] **Step 2: Commit CHANGELOG**

```bash
git add CHANGELOG.md
git commit -m "docs: changelog entry for v0.2.0-alpha.0"
```

- [ ] **Step 3: Final local checks**

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm build
pnpm test -- --coverage
bats installers/macos/tests/install.bats
```

All must exit zero. Coverage threshold maintained.

- [ ] **Step 4: Final smoke test**

```bash
TMPHOME=$(mktemp -d)
HOME=$TMPHOME ./installers/macos/install.sh --profile baseline --claude-dir "$TMPHOME/.claude"
HOME=$TMPHOME ./installers/macos/install.sh --profile strict --claude-dir "$TMPHOME/.claude" || true
HOME=$TMPHOME ./installers/macos/verify.sh --claude-dir "$TMPHOME/.claude"
rm -rf "$TMPHOME"
```

The strict-install attempt may fail because applying a different profile over an existing settings.json triggers the "user-modified file" guard from Plan 1's `applyCommand`. That is correct behavior. The verify call after baseline install must exit zero.

- [ ] **Step 5: Tag locally**

```bash
git tag -a v0.2.0-alpha.0 -m "v0.2.0-alpha.0: hooks for categories 1-3 (secrets, destructive, sensitive paths)"
git tag --list
```

- [ ] **Step 6: Push branch and tag**

```bash
git push origin main
git push origin v0.2.0-alpha.0
```

- [ ] **Step 7: Create GitHub release**

```bash
cat > /tmp/release-notes-v0.2.md << 'NOTES_EOF'
# v0.2.0-alpha.0 - Hooks Categories 1-3

Plan 2 of 10. Adds 7 hooks across secrets, destructive operations, and sensitive paths. Introduces strict and regulated profile shells (Plan 5 differentiates). Expands the threat model and integration test corpus.

## What's new

### Hooks
- `secret-leak-detector` (PostToolUse, block) scans tool stdout/stderr/output for secret patterns
- `keychain-guard` (PreToolUse, block) narrows the keychain CLI deny rule to value-printing flags
- `mcp-secret-guard` (PreToolUse, block) scans MCP tool inputs for secret literals
- `destructive-fs-guard` (PreToolUse, block) matches dangerous rm -rf, mkfs, dd to device, shred
- `git-destructive-guard` (PreToolUse, warn baseline / block strict and regulated) flags reset --hard, clean -fd, push --force, branch -D on protected, rebase -i
- `sensitive-paths-guard` (PreToolUse, block) blocks Read/Bash on credential dirs and /etc/sudoers
- `dotfile-guard` (PreToolUse, warn baseline / block strict and regulated) flags Edit/Write on shell rc, gitconfig, ssh config

### Settings
- New `overlays/destructive.json` and `overlays/sensitive-paths.json`
- New `profiles/strict.json` and `profiles/regulated.json` shells
- Compiled snapshots for all three profiles

### Tests
- 4 new integration transcripts including a multi-step attack chain
- Coverage stays >= 90 percent on packages/

### Docs
- Threat model expanded: T-002, T-003, T-004 documented; T-001 extended
- New coverage matrix doc
- ADR-0004 covering manifest contract bumps

## Contract bumps

- `HookManifest.severity` now accepts both scalar and per-profile record forms
- `HookManifest.matchers` supports `*` and `<prefix>*` wildcards
- `HookContext` gains optional `response` field for PostToolUse hooks

All bumps are additive; Plan 1 hooks continue to work unchanged.

## Known limitations rolling into Plan 4

- Audit-logger concurrency
- Egress / WebFetch allowlist (attack-chain transcript flags step 2 as partial-block)

## Roadmap

Plan 3 (categories 4-5: bash structural + branch guards) is next. See parent spec for the 10-plan sequence to v1.0.0.

## Security

Report vulnerabilities to security@bitsummit.com. See SECURITY.md.
NOTES_EOF
gh release create v0.2.0-alpha.0 --repo Bitsummit-Corp/claude-code-security \
  --title "v0.2.0-alpha.0 - Hooks Categories 1-3" \
  --notes-file /tmp/release-notes-v0.2.md \
  --prerelease
rm /tmp/release-notes-v0.2.md
```

- [ ] **Step 8: Verify release**

```bash
gh release view v0.2.0-alpha.0 --repo Bitsummit-Corp/claude-code-security 2>&1 | head -10
```

Plan 2 sealed.

---

## Self-Review

**Spec coverage check:**

| Spec section | Plan task |
|---|---|
| 1 Purpose & Scope | Reflected in Plan 2 sequence position banner |
| 2 Hook list | Tasks 4-10 (one task per hook) |
| 2.1 Behavioral notes | Embedded in each hook task |
| 2.2 Per-profile severity contract | Task 1 (validator) + Task 2 (runner) |
| 2.3 Matcher wildcard convention | Task 1 (matchers helper) + Task 2 (runner uses matchesAny) |
| 3.1-3.4 Settings overlays + profiles | Tasks 11, 12 |
| 3.5 Compiled snapshots | Task 13 |
| 4 Test corpus | Task 14 |
| 5 Threat model expansion | Task 15 |
| 6 Coverage matrix | Task 15 |
| 7 ADR-0004 | Task 3 |
| 8 Plan 2 risks | Mitigations woven through implementation tasks; final smoke test in Task 16 confirms no regressions |
| 9 Success criteria | Task 16 verifies all checks before tagging |

**Placeholder scan:** No TBD/TODO/placeholder text. Cross-plan references to Plans 3-5 are explicit roadmap pointers, not placeholders.

**Type consistency:** `HookManifest`, `HookContext`, `ProfileSeverity`, `HookSeverity` defined in Task 1 and used unchanged through Tasks 4-10. `RunInput.response` added in Task 2 and consumed in Task 4 + Task 14. `matchesAny` defined in Task 1 and consumed in Task 2.

---

## Plan 2 Complete

This plan ships `v0.2.0-alpha.0`. Plan 3 (categories 4-5: bash structural + branch guards) is the next ship.

**Two execution options:**

**1. Subagent-Driven (recommended)** - Fresh subagent per task with two-stage review. Best fit for a 16-task plan.

**2. Inline Execution** - Run tasks in this session via the executing-plans skill, with checkpoints.

Which approach?
