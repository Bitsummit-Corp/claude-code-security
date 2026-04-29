# Phase 1 / Plan 1: Foundation Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundation of `claude-code-security` end-to-end on macOS: monorepo, full `packages/core/` library, one canary hook (`secret-guard`), one settings overlay + profile, a minimal `ccsec` CLI (`apply | compile | doctor`), a macOS installer that wires everything into `~/.claude/`, and a CI pipeline that gates the lot. Result is a working `v0.1.0-alpha` that proves the architecture before scaling out hooks, distribution channels, and docs in subsequent plans.

**Architecture:** TypeScript monorepo with pnpm workspaces. `packages/core/` is the platform-portable runtime (manifest validator, path-token resolver, structural-bash parser, secret patterns, JSONL audit logger, hook runner). `packages/hooks/` ships individual hook modules each declaring a manifest and a `run(ctx)` function. `packages/settings/` ships layered JSON (base + overlays + profiles). `packages/cli/` is a Commander-based CLI that compiles profiles and applies them to `~/.claude/`. `installers/macos/` is bash that wraps the CLI for MDM admins. Every component is test-first (vitest), with hook integration tested via a synthetic Claude Code transcript replay.

**Tech Stack:** Node.js >=20.10, TypeScript 5.x, pnpm workspaces, vitest, commander, zod (manifest validation), tsx (dev runner), tsup (build), ESLint + Prettier, bats (bash installer tests), GitHub Actions.

---

## Phase 1 Plan Sequence (this plan is #1)

Phase 1 of the spec ships as 10 sequential plans. Each produces working, tagged software:

| # | Plan | Outcome | Tag |
|---|---|---|---|
| 1 | **Foundation walking skeleton** *(this plan)* | Core lib, 1 hook, 1 profile, CLI, macOS installer, CI | `v0.1.0-alpha` |
| 2 | Hooks: categories 1-3 (secrets, destructive, sensitive paths) | +7 hooks, expanded overlays, expanded test corpora | `v0.2.0-alpha` |
| 3 | Hooks: categories 4-5 (bash structural, branch guards) | +6 hooks, fuzzer for bash parser | `v0.3.0-alpha` |
| 4 | Hooks: categories 6-7 (network egress, audit) | +4 hooks, hash-chain audit log, deny-by-default WebFetch | `v0.4.0-alpha` |
| 5 | Hooks: categories 8-10 (behavioral, MDM bypass, agent gating) | +8 hooks, CLAUDE.md rule templates, all profiles complete | `v0.5.0-beta` |
| 6 | Plugin + npm distribution channels | `/plugin install` + `npm i -g`, lockfile, dry-run | `v0.6.0-beta` |
| 7 | Jamf integration + tamper detection | Config profile, `verify.sh`, `chflags uchg`, manifest hashing | `v0.7.0-beta` |
| 8 | Full docs (Track 1-5) + auto-generation pipeline | Hooks docs autogen, coverage matrix, ADRs, deployment guides | `v0.8.0-rc` |
| 9 | Release engineering: signing, SBOM, GHSA, Node SEA binaries | SLSA L3, CycloneDX, signed artifacts, security advisory pipeline | `v0.9.0-rc` |
| 10 | Pilot validation + external security review | One BITSUMMIT pilot client, paid external reviewer sign-off | `v1.0.0` |

This document covers Plan 1 only. Each subsequent plan starts with a fresh brainstorm/spec/plan cycle once the prior plan ships.

---

## File Structure (Plan 1 only)

See repo tree appended in part 2.

## Conventions Used Throughout This Plan

- **Working directory** for all commands unless stated otherwise: `/Users/haseebminhas/Projects.DEV/Claude-Code-Security/`
- **All TypeScript files** use ES Modules (`"type": "module"` in each package.json)
- **Test runner** is vitest, invoked via `pnpm test` from repo root or `pnpm --filter <pkg> test` per package
- **Commit style**: short, imperative, no Claude footers (per global rules)
- **Brand rule**: never em dashes, use hyphens only
- **No `git push` in any task**, pushing is a user-approved gate captured at the end

---

## File Structure (Plan 1 only)

```
claude-code-security/
├── .github/workflows/ci.yml
├── .gitignore
├── .npmrc
├── .prettierrc.json
├── .eslintrc.cjs
├── package.json
├── pnpm-workspace.yaml
├── tsconfig.base.json
├── vitest.config.ts
├── packages/
│   ├── core/
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── types.ts
│   │   │   ├── manifest-validator.ts
│   │   │   ├── path-tokens.ts
│   │   │   ├── secret-patterns.ts
│   │   │   ├── bash-parser.ts
│   │   │   ├── audit-logger.ts
│   │   │   └── runner.ts
│   │   └── tests/
│   │       ├── manifest-validator.test.ts
│   │       ├── path-tokens.test.ts
│   │       ├── secret-patterns.test.ts
│   │       ├── bash-parser.test.ts
│   │       ├── audit-logger.test.ts
│   │       └── runner.test.ts
│   ├── hooks/
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── src/
│   │       └── secret-guard/
│   │           ├── index.ts
│   │           └── secret-guard.test.ts
│   ├── settings/
│   │   ├── package.json
│   │   ├── base.json
│   │   ├── overlays/secrets.json
│   │   ├── profiles/baseline.json
│   │   └── compiled/baseline.json
│   └── cli/
│       ├── package.json
│       ├── tsconfig.json
│       ├── bin/ccsec.js
│       ├── src/
│       │   ├── index.ts
│       │   ├── compiler.ts
│       │   └── commands/
│       │       ├── compile.ts
│       │       ├── apply.ts
│       │       └── doctor.ts
│       └── tests/
│           ├── compiler.test.ts
│           ├── compile-cmd.test.ts
│           ├── apply.test.ts
│           └── doctor.test.ts
├── installers/
│   ├── macos/{install.sh, verify.sh, tests/install.bats}
│   ├── windows/README.md
│   └── linux/README.md
├── tests/integration/
│   ├── transcripts/secret-leak-attempt.json
│   └── secret-leak-attempt.test.ts
├── docs/
│   ├── threat-model.md
│   └── adr/{0001-node-implementation.md, 0002-monorepo-layout.md, 0003-passive-only-posture.md}
├── CHANGELOG.md
├── README.md
├── SECURITY.md
├── LICENSE
└── CODE_OF_CONDUCT.md
```

**Boundary note:** every file has a single responsibility. `core/` is logic; `hooks/` is policy; `settings/` is config; `cli/` is user interface; `installers/` is OS glue; `tests/integration/` exercises everything together.

---

## Task 1: Initialize Repo and Monorepo Tooling

**Files:** `.gitignore`, `.npmrc`, `package.json`, `pnpm-workspace.yaml`, `tsconfig.base.json`, `vitest.config.ts`, `.prettierrc.json`, `.eslintrc.cjs`, `LICENSE`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `README.md`

- [ ] **Step 1: Initialize git and write `.gitignore`**

```bash
cd /Users/haseebminhas/Projects.DEV/Claude-Code-Security
git init -b main
```

`.gitignore`:
```
node_modules/
dist/
coverage/
*.log
.DS_Store
.env
.env.*
!.env.example
.vscode/
.idea/
*.tsbuildinfo
.pnpm-store/
```

- [ ] **Step 2: `.npmrc`**

```
strict-peer-dependencies=false
auto-install-peers=true
shamefully-hoist=false
```

- [ ] **Step 3: Root `package.json`**

```json
{
  "name": "claude-code-security",
  "version": "0.1.0-alpha.0",
  "private": true,
  "type": "module",
  "packageManager": "pnpm@9.12.0",
  "engines": { "node": ">=20.10.0" },
  "scripts": {
    "build": "pnpm -r --parallel build",
    "test": "vitest run",
    "lint": "eslint . --ext .ts,.tsx,.js,.cjs,.mjs",
    "format": "prettier --write .",
    "typecheck": "pnpm -r --parallel typecheck",
    "build:settings": "pnpm --filter @bitsummit/ccsec-cli build && node packages/cli/dist/index.js compile --profile baseline --out packages/settings/compiled/baseline.json"
  },
  "devDependencies": {
    "@types/node": "^20.12.0",
    "@typescript-eslint/eslint-plugin": "^7.5.0",
    "@typescript-eslint/parser": "^7.5.0",
    "eslint": "^8.57.0",
    "prettier": "^3.2.5",
    "tsx": "^4.7.2",
    "typescript": "^5.4.5",
    "vitest": "^1.5.0"
  }
}
```

- [ ] **Step 4: `pnpm-workspace.yaml`**

```yaml
packages:
  - "packages/*"
```

- [ ] **Step 5: `tsconfig.base.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitOverride": true,
    "exactOptionalPropertyTypes": true
  }
}
```

`vitest.config.ts`:
```ts
import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      thresholds: { lines: 90, functions: 90, branches: 85, statements: 90 },
      include: ['packages/*/src/**/*.ts'],
      exclude: ['**/dist/**', '**/*.test.ts', '**/types.ts'],
    },
    include: ['packages/**/*.test.ts', 'tests/**/*.test.ts'],
  },
});
```

- [ ] **Step 6: `.prettierrc.json` + `.eslintrc.cjs`**

`.prettierrc.json`:
```json
{ "singleQuote": true, "trailingComma": "all", "printWidth": 100, "tabWidth": 2, "semi": true }
```

`.eslintrc.cjs`:
```js
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  ignorePatterns: ['dist', 'node_modules', 'coverage'],
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/explicit-function-return-type': 'off',
  },
};
```

- [ ] **Step 7: `LICENSE` (MIT, copyright `2026 BITSUMMIT`), `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1 from `https://www.contributor-covenant.org/version/2/1/code_of_conduct.txt`), `CHANGELOG.md`, `README.md` skeleton (status alpha, license MIT, security email).**

- [ ] **Step 8: Install + commit**

```bash
pnpm install
git add -A
git commit -m "chore: bootstrap monorepo with pnpm workspaces, typescript, vitest, eslint, prettier"
```

Expected: commit succeeds; `pnpm-lock.yaml` created.

---

## Task 2: Scaffold `packages/core/` and Define Public Types

**Files:** `packages/core/package.json`, `packages/core/tsconfig.json`, `packages/core/src/index.ts`, `packages/core/src/types.ts`

- [ ] **Step 1: `packages/core/package.json`**

```json
{
  "name": "@bitsummit/ccsec-core",
  "version": "0.1.0-alpha.0",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": { ".": { "import": "./dist/index.js", "types": "./dist/index.d.ts" } },
  "files": ["dist", "README.md"],
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "test": "vitest run"
  },
  "dependencies": { "zod": "^3.23.0" }
}
```

- [ ] **Step 2: `packages/core/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "outDir": "./dist", "rootDir": "./src", "composite": true },
  "include": ["src/**/*.ts"],
  "exclude": ["**/*.test.ts", "tests/**"]
}
```

- [ ] **Step 3: `packages/core/src/types.ts`**

```ts
export type HookEvent =
  | 'PreToolUse' | 'PostToolUse' | 'UserPromptSubmit'
  | 'SessionStart' | 'SubagentStart' | 'SubagentStop';

export type HookSeverity = 'block' | 'warn' | 'log';
export type HookProfile = 'baseline' | 'strict' | 'regulated';
export type HookDecisionKind = 'allow' | 'block' | 'warn';

export interface HookManifest {
  name: string;
  event: HookEvent;
  matchers: string[];
  threat: string;
  profiles: HookProfile[];
  severity: HookSeverity;
  timeout_ms: number;
}

export interface HookContext {
  tool: string;
  input: Record<string, unknown>;
  env: Readonly<Record<string, string>>;
  paths: { home: string; ssh: string; aws: string; tmp: string };
  log: (msg: string) => void;
  abort: AbortSignal;
}

export interface HookDecision {
  decision: HookDecisionKind;
  reason: string;
  evidence?: Record<string, unknown>;
}

export interface HookModule {
  manifest: HookManifest;
  run: (ctx: HookContext) => Promise<HookDecision>;
}

export interface AuditRecord {
  ts: string;
  hook: string;
  tool: string;
  decision: HookDecisionKind | 'timeout' | 'error';
  reason: string;
  duration_ms: number;
  prev_hash?: string;
  hash: string;
}
```

- [ ] **Step 4: `packages/core/src/index.ts`**

```ts
export * from './types.js';
```

- [ ] **Step 5: Verify + commit**

```bash
pnpm --filter @bitsummit/ccsec-core typecheck
git add -A
git commit -m "feat(core): scaffold package and define hook contract types"
```

Expected: typecheck succeeds.

---

## Task 3: `manifest-validator.ts` (TDD)

**Files:** `packages/core/src/manifest-validator.ts`, `packages/core/tests/manifest-validator.test.ts`

- [ ] **Step 1: Failing test**

`packages/core/tests/manifest-validator.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { validateManifest, ManifestError } from '../src/manifest-validator.js';

describe('validateManifest', () => {
  const valid = {
    name: 'secret-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  };

  it('accepts a valid manifest', () => {
    expect(() => validateManifest(valid)).not.toThrow();
  });

  it('rejects missing required fields', () => {
    const m = { ...valid } as Record<string, unknown>;
    delete m.threat;
    expect(() => validateManifest(m)).toThrow(ManifestError);
  });

  it('rejects unknown event types', () => {
    expect(() => validateManifest({ ...valid, event: 'AfterDinner' })).toThrow(ManifestError);
  });

  it('rejects timeout_ms below 100 or above 30000', () => {
    expect(() => validateManifest({ ...valid, timeout_ms: 50 })).toThrow(ManifestError);
    expect(() => validateManifest({ ...valid, timeout_ms: 60000 })).toThrow(ManifestError);
  });

  it('rejects empty matchers', () => {
    expect(() => validateManifest({ ...valid, matchers: [] })).toThrow(ManifestError);
  });

  it('rejects threat IDs not matching T-NNN pattern', () => {
    expect(() => validateManifest({ ...valid, threat: 'something' })).toThrow(ManifestError);
  });
});
```

- [ ] **Step 2: Run, expect FAIL**: `pnpm --filter @bitsummit/ccsec-core test`

- [ ] **Step 3: Implement**

`packages/core/src/manifest-validator.ts`:
```ts
import { z } from 'zod';
import type { HookManifest } from './types.js';

export class ManifestError extends Error {
  constructor(message: string) { super(message); this.name = 'ManifestError'; }
}

const ManifestSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]*$/),
  event: z.enum(['PreToolUse','PostToolUse','UserPromptSubmit','SessionStart','SubagentStart','SubagentStop']),
  matchers: z.array(z.string().min(1)).min(1),
  threat: z.string().regex(/^T-\d{3}-[a-z0-9-]+$/),
  profiles: z.array(z.enum(['baseline','strict','regulated'])).min(1),
  severity: z.enum(['block','warn','log']),
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

- [ ] **Step 4: Update `index.ts`**

```ts
export * from './types.js';
export { validateManifest, ManifestError } from './manifest-validator.js';
```

- [ ] **Step 5: Run, expect PASS, commit**

```bash
pnpm --filter @bitsummit/ccsec-core test
git add -A && git commit -m "feat(core): manifest validator with zod schema"
```

---

## Task 4: `path-tokens.ts` (TDD)

**Files:** `packages/core/src/path-tokens.ts`, `packages/core/tests/path-tokens.test.ts`

- [ ] **Step 1: Failing test**

`packages/core/tests/path-tokens.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { resolveTokens } from '../src/path-tokens.js';

const env = (home: string) => ({ HOME: home, USERPROFILE: home });

describe('resolveTokens', () => {
  it('expands HOME on macOS', () => {
    expect(resolveTokens('${HOME}/.config', 'macos', env('/Users/x'))).toBe('/Users/x/.config');
  });
  it('expands HOME on linux', () => {
    expect(resolveTokens('${HOME}/.config', 'linux', env('/home/x'))).toBe('/home/x/.config');
  });
  it('expands HOME on windows', () => {
    expect(resolveTokens('${HOME}/.config', 'windows', env('C:\\Users\\x'))).toBe('C:\\Users\\x/.config');
  });
  it('expands SSH', () => {
    expect(resolveTokens('${SSH}/id_rsa', 'macos', env('/Users/x'))).toBe('/Users/x/.ssh/id_rsa');
  });
  it('expands AWS', () => {
    expect(resolveTokens('${AWS}/credentials', 'linux', env('/home/x'))).toBe('/home/x/.aws/credentials');
  });
  it('expands TMP per-OS', () => {
    expect(resolveTokens('${TMP}/x', 'macos', env('/Users/x'))).toBe('/tmp/x');
    expect(resolveTokens('${TMP}/x', 'linux', env('/home/x'))).toBe('/tmp/x');
  });
  it('expands KEYS', () => {
    const out = resolveTokens('${KEYS}', 'macos', env('/Users/x'));
    expect(out).toContain('/Users/x/.ssh');
    expect(out.split('|').length).toBeGreaterThanOrEqual(3);
  });
  it('leaves unknown tokens intact', () => {
    expect(resolveTokens('${UNKNOWN}/x', 'macos', env('/Users/x'))).toBe('${UNKNOWN}/x');
  });
  it('throws on missing HOME', () => {
    expect(() => resolveTokens('${HOME}', 'macos', {})).toThrow(/HOME/);
  });
});
```

- [ ] **Step 2: Implement**

`packages/core/src/path-tokens.ts`:
```ts
export type TargetOS = 'macos' | 'linux' | 'windows';

export function resolveTokens(
  input: string,
  os: TargetOS,
  env: Readonly<Record<string, string | undefined>>,
): string {
  const home = os === 'windows' ? env.USERPROFILE : env.HOME;
  if (!home && /\$\{(HOME|SSH|AWS|KEYS)\}/.test(input)) {
    throw new Error(`HOME not set in environment for OS=${os}`);
  }
  const tmp = os === 'windows' ? (env.TEMP ?? `${home}\\AppData\\Local\\Temp`) : '/tmp';
  const keysList = [`${home}/.ssh`, `${home}/.aws`, `${home}/.gnupg`, `${home}/.kube`, `${home}/.docker`].join('|');

  return input.replace(/\$\{([A-Z_]+)\}/g, (_match, name: string) => {
    switch (name) {
      case 'HOME': return home ?? '${HOME}';
      case 'SSH':  return `${home}/.ssh`;
      case 'AWS':  return `${home}/.aws`;
      case 'TMP':  return tmp;
      case 'KEYS': return keysList;
      default:     return `\${${name}}`;
    }
  });
}
```

- [ ] **Step 3: Update index, run, commit**

Add to `index.ts`:
```ts
export { resolveTokens } from './path-tokens.js';
export type { TargetOS } from './path-tokens.js';
```

```bash
pnpm --filter @bitsummit/ccsec-core test
git add -A && git commit -m "feat(core): path-token resolver for HOME/SSH/AWS/TMP/KEYS"
```

---

## Task 5: `secret-patterns.ts` (TDD)

**Files:** `packages/core/src/secret-patterns.ts`, `packages/core/tests/secret-patterns.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest';
import { detectSecrets, SECRET_PATTERNS } from '../src/secret-patterns.js';

describe('detectSecrets', () => {
  it('detects AWS access key id', () => {
    const hits = detectSecrets('AKIAIOSFODNN7EXAMPLE');
    expect(hits[0]?.label).toBe('aws_access_key_id');
  });
  it('detects GitHub PAT (classic)', () => {
    expect(detectSecrets('ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789')[0]?.label).toBe('github_pat');
  });
  it('detects Stripe live key', () => {
    expect(detectSecrets('sk_live_' + 'a'.repeat(24))[0]?.label).toBe('stripe_secret_key');
  });
  it('detects PEM private key blocks', () => {
    expect(detectSecrets('-----BEGIN RSA PRIVATE KEY-----\nM\n-----END RSA PRIVATE KEY-----')[0]?.label).toBe('private_key_block');
  });
  it('detects Slack tokens', () => {
    expect(detectSecrets('xoxb-1234567890-1234567890-abcdefghij')[0]?.label).toBe('slack_token');
  });
  it('returns empty for benign text', () => {
    expect(detectSecrets('hello world')).toEqual([]);
  });
  it('redacts the matched value', () => {
    expect(detectSecrets('AKIAIOSFODNN7EXAMPLE')[0]?.redacted).toBe('AKIA****************');
  });
  it('exports a non-empty SECRET_PATTERNS list', () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(6);
  });
});
```

- [ ] **Step 2: Implement**

```ts
export interface SecretPattern { label: string; regex: RegExp; }
export interface SecretHit { label: string; redacted: string; index: number; }

export const SECRET_PATTERNS: SecretPattern[] = [
  { label: 'aws_access_key_id', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: 'github_pat', regex: /\bghp_[A-Za-z0-9]{36}\b/g },
  { label: 'github_pat_finegrained', regex: /\bgithub_pat_[A-Za-z0-9_]{70,}\b/g },
  { label: 'stripe_secret_key', regex: /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/g },
  { label: 'private_key_block', regex: /-----BEGIN [A-Z ]+PRIVATE KEY-----/g },
  { label: 'slack_token', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { label: 'google_api_key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];

function redact(v: string): string {
  if (v.length <= 4) return '*'.repeat(v.length);
  return v.slice(0, 4) + '*'.repeat(v.length - 4);
}

export function detectSecrets(input: string): SecretHit[] {
  const hits: SecretHit[] = [];
  for (const { label, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(input)) !== null) {
      hits.push({ label, redacted: redact(m[0]), index: m.index });
    }
  }
  return hits.sort((a, b) => a.index - b.index);
}
```

- [ ] **Step 3: Update index, run, commit**

```ts
export { detectSecrets, SECRET_PATTERNS } from './secret-patterns.js';
export type { SecretHit, SecretPattern } from './secret-patterns.js';
```

```bash
pnpm --filter @bitsummit/ccsec-core test
git add -A && git commit -m "feat(core): secret pattern library covering AWS, GitHub, Stripe, PEM, Slack, Google"
```

---

## Task 6: `bash-parser.ts` (TDD)

**Files:** `packages/core/src/bash-parser.ts`, `packages/core/tests/bash-parser.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest';
import { detectStructuralRisks } from '../src/bash-parser.js';

describe('detectStructuralRisks', () => {
  it('returns empty for plain command', () => {
    expect(detectStructuralRisks('ls -la')).toEqual([]);
  });
  it('flags && chaining', () => {
    expect(detectStructuralRisks('cd /tmp && rm -rf foo').map(r=>r.kind)).toContain('chained_and');
  });
  it('flags || chaining', () => {
    expect(detectStructuralRisks('false || rm x').map(r=>r.kind)).toContain('chained_or');
  });
  it('flags ; outside strings', () => {
    expect(detectStructuralRisks('echo a; rm b').map(r=>r.kind)).toContain('chained_semicolon');
  });
  it('does NOT flag ; inside single quotes', () => {
    expect(detectStructuralRisks("echo 'a;b'")).toEqual([]);
  });
  it('flags pipe-to-shell', () => {
    expect(detectStructuralRisks('curl x | sh').map(r=>r.kind)).toContain('pipe_to_shell');
    expect(detectStructuralRisks('wget -O- x | bash').map(r=>r.kind)).toContain('pipe_to_shell');
  });
  it('flags command substitution $()', () => {
    expect(detectStructuralRisks('echo $(whoami)').map(r=>r.kind)).toContain('command_substitution');
  });
  it('flags backtick substitution', () => {
    expect(detectStructuralRisks('echo `whoami`').map(r=>r.kind)).toContain('command_substitution');
  });
  it('flags process substitution', () => {
    expect(detectStructuralRisks('diff <(ls a) <(ls b)').map(r=>r.kind)).toContain('process_substitution');
  });
  it('flags leading cd', () => {
    expect(detectStructuralRisks('cd /etc && cat passwd').map(r=>r.kind)).toContain('leading_cd');
  });
  it('catches Unicode lookalike semicolon', () => {
    expect(detectStructuralRisks('echo a；rm b').map(r=>r.kind)).toContain('unicode_lookalike');
  });
});
```

- [ ] **Step 2: Implement**

```ts
export type StructuralRiskKind =
  | 'chained_and' | 'chained_or' | 'chained_semicolon'
  | 'pipe_to_shell' | 'command_substitution' | 'process_substitution'
  | 'leading_cd' | 'unicode_lookalike';

export interface StructuralRisk { kind: StructuralRiskKind; offset: number; excerpt: string; }

const UNICODE_LOOKALIKES = new Set(['；', '＆']);

function maskQuotedRegions(cmd: string): string {
  const out: string[] = [];
  let inSingle = false, inDouble = false;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i] as string;
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    out.push(inSingle || inDouble ? ' ' : ch);
  }
  return out.join('');
}

export function detectStructuralRisks(cmd: string): StructuralRisk[] {
  const risks: StructuralRisk[] = [];
  const masked = maskQuotedRegions(cmd);

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i] as string;
    if (UNICODE_LOOKALIKES.has(ch)) {
      risks.push({ kind: 'unicode_lookalike', offset: i, excerpt: cmd.slice(Math.max(0, i - 5), i + 5) });
    }
  }

  const scan = (re: RegExp, kind: StructuralRiskKind) => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(masked)) !== null) {
      risks.push({ kind, offset: m.index, excerpt: cmd.slice(m.index, m.index + m[0].length) });
    }
  };

  scan(/&&/g, 'chained_and');
  scan(/\|\|/g, 'chained_or');
  scan(/;/g, 'chained_semicolon');
  scan(/\|\s*(?:sh|bash|zsh|fish|ksh)\b/g, 'pipe_to_shell');
  scan(/\$\([^)]*\)/g, 'command_substitution');
  scan(/`[^`]*`/g, 'command_substitution');
  scan(/[<>]\([^)]*\)/g, 'process_substitution');

  if (/^\s*cd\s+\S+/.test(cmd)) {
    risks.push({ kind: 'leading_cd', offset: 0, excerpt: cmd.split(/\s+/).slice(0, 2).join(' ') });
  }

  return risks.sort((a, b) => a.offset - b.offset);
}
```

- [ ] **Step 3: Update index, run, commit**

```ts
export { detectStructuralRisks } from './bash-parser.js';
export type { StructuralRisk, StructuralRiskKind } from './bash-parser.js';
```

```bash
pnpm --filter @bitsummit/ccsec-core test
git add -A && git commit -m "feat(core): structural-bash parser for chaining/substitution/pipe-to-shell/unicode lookalikes"
```

---

## Task 7: `audit-logger.ts` (TDD, append-only JSONL with hash chain)

**Files:** `packages/core/src/audit-logger.ts`, `packages/core/tests/audit-logger.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLogger } from '../src/audit-logger.js';

describe('AuditLogger', () => {
  let path: string;
  beforeEach(async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ccsec-audit-'));
    path = join(dir, 'audit.jsonl');
  });

  it('appends one JSONL record per write', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'block', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'b', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    expect(lines).toHaveLength(2);
  });

  it('chains records via hash + prev_hash', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'b', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    const r1 = JSON.parse(lines[0]!), r2 = JSON.parse(lines[1]!);
    expect(r2.prev_hash).toBe(r1.hash);
    expect(r1.prev_hash).toBeUndefined();
  });

  it('verifies an intact log', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'b', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    expect(await AuditLogger.verify(path)).toEqual({ ok: true, records: 2 });
  });

  it('detects tampering on verify', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'b', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const tampered = (await readFile(path, 'utf8')).replace('"reason":"r"', '"reason":"X"');
    await writeFile(path, tampered);
    expect((await AuditLogger.verify(path)).ok).toBe(false);
  });
});
```

- [ ] **Step 2: Implement**

```ts
import { appendFile, readFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';

export interface AuditInput {
  hook: string; tool: string; decision: string; reason: string;
  duration_ms: number; evidence_digest?: string; _ts?: string;
}

export interface AuditRecord extends AuditInput {
  ts: string; prev_hash?: string; hash: string;
}

function hashRecord(record: Omit<AuditRecord, 'hash'>): string {
  return createHash('sha256').update(JSON.stringify(record)).digest('hex');
}

export class AuditLogger {
  private prevHash: string | undefined;
  constructor(private readonly path: string) {}

  async write(input: AuditInput): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    if (this.prevHash === undefined) this.prevHash = await this.loadLastHash();
    const ts = input._ts ?? new Date().toISOString();
    const { _ts, ...rest } = input;
    const base: Omit<AuditRecord, 'hash'> = {
      ...rest, ts,
      ...(this.prevHash !== undefined ? { prev_hash: this.prevHash } : {}),
    };
    const hash = hashRecord(base);
    this.prevHash = hash;
    await appendFile(this.path, JSON.stringify({ ...base, hash }) + '\n', 'utf8');
  }

  private async loadLastHash(): Promise<string | undefined> {
    try {
      const lines = (await readFile(this.path, 'utf8')).trim().split('\n').filter(Boolean);
      const last = lines[lines.length - 1];
      return last ? JSON.parse(last).hash : undefined;
    } catch {
      return undefined;
    }
  }

  static async verify(path: string): Promise<{ ok: boolean; records: number; brokenAt?: number }> {
    const lines = (await readFile(path, 'utf8')).trim().split('\n').filter(Boolean);
    let prev: string | undefined;
    for (let i = 0; i < lines.length; i++) {
      const r = JSON.parse(lines[i]!) as AuditRecord;
      if (r.prev_hash !== prev) return { ok: false, records: lines.length, brokenAt: i };
      const { hash, ...rest } = r;
      if (hashRecord(rest) !== hash) return { ok: false, records: lines.length, brokenAt: i };
      prev = hash;
    }
    return { ok: true, records: lines.length };
  }
}
```

- [ ] **Step 3: Update index, run, commit**

```ts
export { AuditLogger } from './audit-logger.js';
export type { AuditInput, AuditRecord } from './audit-logger.js';
```

```bash
pnpm --filter @bitsummit/ccsec-core test
git add -A && git commit -m "feat(core): JSONL audit logger with sha256 hash chain and verify()"
```

---

## Task 8: `runner.ts` (TDD, hook orchestration with timeout)

**Files:** `packages/core/src/runner.ts`, `packages/core/tests/runner.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runHooks } from '../src/runner.js';
import type { HookModule } from '../src/types.js';

const allowHook: HookModule = {
  manifest: { name: 'allow-all', event: 'PreToolUse', matchers: ['Bash'], threat: 'T-999-test', profiles: ['baseline'], severity: 'log', timeout_ms: 1000 },
  run: async () => ({ decision: 'allow', reason: 'ok' }),
};
const blockHook: HookModule = {
  manifest: { name: 'block-all', event: 'PreToolUse', matchers: ['Bash'], threat: 'T-001-secret-leak', profiles: ['baseline'], severity: 'block', timeout_ms: 1000 },
  run: async () => ({ decision: 'block', reason: 'denied' }),
};
const slowHook: HookModule = {
  manifest: { name: 'slow', event: 'PreToolUse', matchers: ['Bash'], threat: 'T-016-hook-dos', profiles: ['baseline'], severity: 'log', timeout_ms: 100 },
  run: () => new Promise(r => setTimeout(() => r({ decision: 'allow', reason: 'ok' }), 500)),
};
const wrongMatcher: HookModule = { ...allowHook, manifest: { ...allowHook.manifest, name: 'edit-only', matchers: ['Edit'] } };

let auditPath: string;
beforeEach(async () => {
  auditPath = join(await mkdtemp(join(tmpdir(), 'ccsec-runner-')), 'audit.jsonl');
});

describe('runHooks', () => {
  it('aggregate allow when all hooks allow', async () => {
    const r = await runHooks({ hooks: [allowHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.decision).toBe('allow');
  });
  it('block if any hook blocks', async () => {
    const r = await runHooks({ hooks: [allowHook, blockHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.decision).toBe('block');
    expect(r.blockedBy).toBe('block-all');
  });
  it('skips hooks whose matcher does not match', async () => {
    const r = await runHooks({ hooks: [wrongMatcher], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.invocations).toHaveLength(0);
  });
  it('skips hooks not in active profile', async () => {
    const r = await runHooks({ hooks: [blockHook], profile: 'strict', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.decision).toBe('allow');
  });
  it('aborts hook that exceeds timeout_ms', async () => {
    const r = await runHooks({ hooks: [slowHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.invocations[0]?.outcome).toBe('timeout');
  });
  it('writes one audit record per invocation', async () => {
    await runHooks({ hooks: [allowHook, blockHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    const lines = (await readFile(auditPath, 'utf8')).trim().split('\n');
    expect(lines).toHaveLength(2);
  });
  it('continues running remaining hooks after a block', async () => {
    const r = await runHooks({ hooks: [blockHook, allowHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.invocations).toHaveLength(2);
  });
});
```

- [ ] **Step 2: Implement**

```ts
import type { HookEvent, HookModule, HookProfile } from './types.js';
import { AuditLogger } from './audit-logger.js';

export interface RunInput {
  tool: string;
  input: Record<string, unknown>;
  event: HookEvent;
  env?: Readonly<Record<string, string>>;
}
export interface RunOptions {
  hooks: HookModule[];
  profile: HookProfile;
  auditLogPath: string;
  defaultTimeoutMs?: number;
}
export interface HookInvocation {
  hook: string;
  outcome: 'allow' | 'block' | 'warn' | 'timeout' | 'error';
  reason: string;
  duration_ms: number;
}
export interface RunResult {
  decision: 'allow' | 'block' | 'warn';
  blockedBy?: string;
  invocations: HookInvocation[];
}

export async function runHooks(opts: RunOptions, run: RunInput): Promise<RunResult> {
  const logger = new AuditLogger(opts.auditLogPath);
  const invocations: HookInvocation[] = [];
  let aggregate: 'allow' | 'block' | 'warn' = 'allow';
  let blockedBy: string | undefined;

  for (const hook of opts.hooks) {
    if (hook.manifest.event !== run.event) continue;
    if (!hook.manifest.matchers.includes(run.tool)) continue;
    if (!hook.manifest.profiles.includes(opts.profile)) continue;

    const start = Date.now();
    const controller = new AbortController();
    const timeoutMs = hook.manifest.timeout_ms ?? opts.defaultTimeoutMs ?? 1500;
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let outcome: HookInvocation['outcome'] = 'allow';
    let reason = '';

    try {
      const decision = await Promise.race([
        hook.run({
          tool: run.tool,
          input: run.input,
          env: run.env ?? {},
          paths: { home: process.env.HOME ?? '', ssh: `${process.env.HOME}/.ssh`, aws: `${process.env.HOME}/.aws`, tmp: '/tmp' },
          log: () => undefined,
          abort: controller.signal,
        }),
        new Promise<never>((_, reject) => {
          controller.signal.addEventListener('abort', () => reject(new Error('aborted')));
        }),
      ]);
      outcome = decision.decision;
      reason = decision.reason;
    } catch (e) {
      outcome = controller.signal.aborted ? 'timeout' : 'error';
      reason = (e as Error).message;
    } finally {
      clearTimeout(timer);
    }

    const duration_ms = Date.now() - start;
    invocations.push({ hook: hook.manifest.name, outcome, reason, duration_ms });
    await logger.write({ hook: hook.manifest.name, tool: run.tool, decision: outcome, reason, duration_ms });

    if (outcome === 'block' && aggregate !== 'block') {
      aggregate = 'block';
      blockedBy = hook.manifest.name;
    } else if (outcome === 'warn' && aggregate === 'allow') {
      aggregate = 'warn';
    }
  }
  return { decision: aggregate, ...(blockedBy ? { blockedBy } : {}), invocations };
}
```

- [ ] **Step 3: Update index, run, commit**

```ts
export { runHooks } from './runner.js';
export type { RunInput, RunOptions, RunResult, HookInvocation } from './runner.js';
```

```bash
pnpm --filter @bitsummit/ccsec-core test --coverage
git add -A && git commit -m "feat(core): hook runner with profile/matcher gating, timeout enforcement, audit emission"
```

Expected: coverage ≥90% on `packages/core/src/`.

---

## Task 9: `secret-guard` Hook (TDD, canary)

**Files:** `packages/hooks/package.json`, `packages/hooks/tsconfig.json`, `packages/hooks/src/secret-guard/index.ts`, `packages/hooks/src/secret-guard/secret-guard.test.ts`

- [ ] **Step 1: Scaffold hooks package**

`packages/hooks/package.json`:
```json
{
  "name": "@bitsummit/ccsec-hooks",
  "version": "0.1.0-alpha.0",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "files": ["dist"],
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "test": "vitest run"
  },
  "dependencies": { "@bitsummit/ccsec-core": "workspace:*" }
}
```

`packages/hooks/tsconfig.json`:
```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "outDir": "./dist", "rootDir": "./src", "composite": true },
  "references": [{ "path": "../core" }],
  "include": ["src/**/*.ts"],
  "exclude": ["**/*.test.ts"]
}
```

```bash
pnpm install
```

- [ ] **Step 2: Failing test**

`packages/hooks/src/secret-guard/secret-guard.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import secretGuard from './index.js';

const ctx = (input: Record<string, unknown>) => ({
  tool: 'Bash', input, env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('secret-guard hook', () => {
  it('declares a valid manifest', () => {
    expect(secretGuard.manifest.name).toBe('secret-guard');
    expect(secretGuard.manifest.threat).toMatch(/^T-001-/);
  });
  it('allows benign Bash commands', async () => {
    expect((await secretGuard.run(ctx({ command: 'ls -la' }))).decision).toBe('allow');
  });
  it('blocks AWS key in command', async () => {
    const r = await secretGuard.run(ctx({ command: 'echo AKIAIOSFODNN7EXAMPLE' }));
    expect(r.decision).toBe('block');
    expect(r.reason).toMatch(/aws_access_key_id/);
  });
  it('blocks GitHub PAT', async () => {
    const r = await secretGuard.run(ctx({ command: 'curl -H "Authorization: token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"' }));
    expect(r.decision).toBe('block');
  });
  it('redacts secret in evidence', async () => {
    const r = await secretGuard.run(ctx({ command: 'echo AKIAIOSFODNN7EXAMPLE' }));
    expect(JSON.stringify(r.evidence)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(JSON.stringify(r.evidence)).toContain('AKIA');
  });
  it('blocks env-dump of secret-bearing variable', async () => {
    const r = await secretGuard.run(ctx({ command: 'printenv AWS_SECRET_ACCESS_KEY' }));
    expect(r.decision).toBe('block');
  });
  it('handles non-string input gracefully', async () => {
    expect((await secretGuard.run(ctx({ command: 12345 as never }))).decision).toBe('allow');
  });
});
```

- [ ] **Step 3: Implement**

`packages/hooks/src/secret-guard/index.ts`:
```ts
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';
import { detectSecrets } from '@bitsummit/ccsec-core';

const ENV_DUMP_RE = /\b(?:printenv|env)\b\s+([A-Z_][A-Z0-9_]*)?/;
const SECRET_ENV_NAMES = /(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL)/;
const ECHO_VAR_RE = /\becho\s+["']?\$\{?([A-Z_][A-Z0-9_]*)/;

const secretGuard: HookModule = {
  manifest: {
    name: 'secret-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const command = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!command) return { decision: 'allow', reason: 'no command field' };

    const hits = detectSecrets(command);
    if (hits.length > 0) {
      return {
        decision: 'block',
        reason: `secret literal in command: ${hits.map(h => h.label).join(', ')}`,
        evidence: { hits: hits.map(h => ({ label: h.label, redacted: h.redacted })) },
      };
    }

    const envDump = command.match(ENV_DUMP_RE);
    if (envDump) {
      const target = envDump[1] ?? '';
      if (!target || SECRET_ENV_NAMES.test(target)) {
        return { decision: 'block', reason: `env-dump of secret variable: ${target || '(all)'}`, evidence: { kind: 'env-dump', target } };
      }
    }

    const echoVar = command.match(ECHO_VAR_RE);
    if (echoVar && SECRET_ENV_NAMES.test(echoVar[1] ?? '')) {
      return { decision: 'block', reason: `echo of secret variable: ${echoVar[1]}`, evidence: { kind: 'secret-env', target: echoVar[1] } };
    }

    return { decision: 'allow', reason: 'no secret patterns detected' };
  },
};

export default secretGuard;
```

- [ ] **Step 4: Run, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks test
git add -A && git commit -m "feat(hooks): secret-guard canary hook blocking secret literals and env-dump patterns"
```

---

## Task 10: Settings Layer Compiler in `packages/cli/`

**Files:** `packages/cli/package.json`, `packages/cli/tsconfig.json`, `packages/cli/bin/ccsec.js`, `packages/cli/src/index.ts` (placeholder), `packages/cli/src/compiler.ts`, `packages/cli/tests/compiler.test.ts`

- [ ] **Step 1: Scaffold cli package**

`packages/cli/package.json`:
```json
{
  "name": "@bitsummit/ccsec-cli",
  "version": "0.1.0-alpha.0",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "bin": { "ccsec": "./bin/ccsec.js" },
  "files": ["dist", "bin"],
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "test": "vitest run"
  },
  "dependencies": {
    "@bitsummit/ccsec-core": "workspace:*",
    "@bitsummit/ccsec-hooks": "workspace:*",
    "commander": "^12.0.0"
  }
}
```

`packages/cli/tsconfig.json`:
```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "outDir": "./dist", "rootDir": "./src", "composite": true },
  "references": [{ "path": "../core" }, { "path": "../hooks" }],
  "include": ["src/**/*.ts"],
  "exclude": ["**/*.test.ts"]
}
```

`packages/cli/bin/ccsec.js`:
```js
#!/usr/bin/env node
import('../dist/index.js').then((m) => m.main(process.argv));
```

`packages/cli/src/index.ts` (placeholder, replaced in Task 12):
```ts
export async function main(_argv: string[]): Promise<void> {
  console.log('ccsec - placeholder, replaced in Task 12');
}
```

```bash
pnpm install
chmod +x packages/cli/bin/ccsec.js
```

- [ ] **Step 2: Failing test**

`packages/cli/tests/compiler.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileProfile } from '../src/compiler.js';

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'ccsec-comp-'));
  await mkdir(join(root, 'overlays'), { recursive: true });
  await mkdir(join(root, 'profiles'), { recursive: true });
  await writeFile(join(root, 'base.json'), JSON.stringify({ schema: 1, permissions: { deny: [] }, hooks: {} }));
  await writeFile(join(root, 'overlays', 'secrets.json'), JSON.stringify({
    permissions: { deny: [{ pattern: 'Bash(printenv *)', threat: 'T-001-secret-leak' }] },
    hooks: { PreToolUse: [{ name: 'secret-guard' }] },
  }));
  await writeFile(join(root, 'profiles', 'baseline.json'), JSON.stringify({ extends: ['base', 'overlays/secrets'], overrides: {} }));
});

describe('compileProfile', () => {
  it('produces a flat settings.json from base + overlay', async () => {
    const out = await compileProfile({ settingsRoot: root, profile: 'baseline', os: 'macos' });
    expect(out.permissions.deny).toHaveLength(1);
    expect(out.hooks.PreToolUse[0].name).toBe('secret-guard');
  });
  it('strips threat field when stripThreatField=true', async () => {
    const out = await compileProfile({ settingsRoot: root, profile: 'baseline', os: 'macos', stripThreatField: true });
    expect(out.permissions.deny[0].threat).toBeUndefined();
  });
  it('resolves path tokens against target OS', async () => {
    await writeFile(join(root, 'overlays', 'paths.json'), JSON.stringify({
      permissions: { deny: [{ pattern: 'Read(${HOME}/.ssh/**)', threat: 'T-003-credential-exfil' }] },
      hooks: {},
    }));
    await writeFile(join(root, 'profiles', 'baseline.json'), JSON.stringify({ extends: ['base', 'overlays/secrets', 'overlays/paths'], overrides: {} }));
    const out = await compileProfile({ settingsRoot: root, profile: 'baseline', os: 'macos', env: { HOME: '/Users/x' } });
    expect(out.permissions.deny.find((d: { pattern: string }) => d.pattern.includes('/Users/x/.ssh'))).toBeTruthy();
  });
  it('throws on unknown profile', async () => {
    await expect(compileProfile({ settingsRoot: root, profile: 'nonexistent' as never, os: 'macos' })).rejects.toThrow();
  });
  it('respects overrides block', async () => {
    await writeFile(join(root, 'profiles', 'baseline.json'), JSON.stringify({
      extends: ['base', 'overlays/secrets'],
      overrides: { permissions: { allow: ['Bash(ls *)'] } },
    }));
    const out = await compileProfile({ settingsRoot: root, profile: 'baseline', os: 'macos' });
    expect(out.permissions.allow).toContain('Bash(ls *)');
  });
});
```

Run: `pnpm --filter @bitsummit/ccsec-cli test compiler` -> FAIL with module-not-found.

- [ ] **Step 3: Implement `compiler.ts`**

`packages/cli/src/compiler.ts`:
```ts
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { resolveTokens, type TargetOS } from '@bitsummit/ccsec-core';

export interface CompileOptions {
  settingsRoot: string;
  profile: 'baseline' | 'strict' | 'regulated';
  os: TargetOS;
  env?: Readonly<Record<string, string>>;
  stripThreatField?: boolean;
}

interface ProfileFile { extends: string[]; overrides: Record<string, unknown>; }
interface SettingsFragment {
  permissions?: { deny?: Array<{ pattern: string; threat?: string }>; allow?: string[] };
  hooks?: Record<string, Array<{ name: string }>>;
  [k: string]: unknown;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

function mergeFragments(target: SettingsFragment, source: SettingsFragment): void {
  if (source.permissions?.deny) {
    target.permissions ??= {};
    target.permissions.deny ??= [];
    target.permissions.deny.push(...source.permissions.deny);
  }
  if (source.permissions?.allow) {
    target.permissions ??= {};
    target.permissions.allow ??= [];
    target.permissions.allow.push(...source.permissions.allow);
  }
  if (source.hooks) {
    target.hooks ??= {};
    for (const [event, list] of Object.entries(source.hooks)) {
      target.hooks[event] = (target.hooks[event] ?? []).concat(list);
    }
  }
  for (const k of Object.keys(source)) {
    if (k !== 'permissions' && k !== 'hooks' && !(k in target)) target[k] = source[k];
  }
}

export async function compileProfile(opts: CompileOptions): Promise<SettingsFragment> {
  const profilePath = join(opts.settingsRoot, 'profiles', `${opts.profile}.json`);
  let profile: ProfileFile;
  try { profile = await readJson<ProfileFile>(profilePath); }
  catch { throw new Error(`profile not found: ${opts.profile} at ${profilePath}`); }

  const merged: SettingsFragment = {};
  for (const ref of profile.extends) {
    const frag = await readJson<SettingsFragment>(join(opts.settingsRoot, `${ref}.json`));
    mergeFragments(merged, frag);
  }
  if (profile.overrides) mergeFragments(merged, profile.overrides as SettingsFragment);

  const env = opts.env ?? (process.env as Record<string, string>);
  if (merged.permissions?.deny) {
    merged.permissions.deny = merged.permissions.deny.map(d => ({ ...d, pattern: resolveTokens(d.pattern, opts.os, env) }));
  }
  if (merged.permissions?.allow) {
    merged.permissions.allow = merged.permissions.allow.map(p => resolveTokens(p, opts.os, env));
  }
  if (opts.stripThreatField && merged.permissions?.deny) {
    merged.permissions.deny = merged.permissions.deny.map(({ threat: _t, ...rest }) => rest);
  }
  return merged;
}
```

- [ ] **Step 4: Run, commit**

```bash
pnpm --filter @bitsummit/ccsec-cli test compiler
git add -A && git commit -m "feat(cli): settings-layer compiler resolving extends + overrides + path tokens"
```

Expected: PASS, 5/5 tests.


---

## Task 11: Author Settings Files

**Files:** `packages/settings/package.json`, `packages/settings/base.json`, `packages/settings/overlays/secrets.json`, `packages/settings/profiles/baseline.json`

- [ ] **Step 1: `packages/settings/package.json`**

```json
{
  "name": "@bitsummit/ccsec-settings",
  "version": "0.1.0-alpha.0",
  "type": "module",
  "files": ["base.json", "overlays", "profiles", "compiled"],
  "scripts": { "typecheck": "echo no ts in this package" }
}
```

- [ ] **Step 2: `base.json`**

```json
{
  "schema": 1,
  "ccsec_version": "0.1.0-alpha.0",
  "audit": { "log_path": "${HOME}/.claude/ccsec-audit.jsonl" },
  "permissions": { "deny": [], "allow": [] },
  "hooks": { "PreToolUse": [], "PostToolUse": [], "UserPromptSubmit": [], "SessionStart": [] }
}
```

- [ ] **Step 3: `overlays/secrets.json`**

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
  "hooks": { "PreToolUse": [{ "name": "secret-guard" }] }
}
```

Plan 2 will add a finer-grained block that distinguishes value-printing keychain flags from existence-check invocations. For Plan 1 the broad block is the safe default.

- [ ] **Step 4: `profiles/baseline.json`**

```json
{ "extends": ["base", "overlays/secrets"], "overrides": {} }
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(settings): base config, secrets overlay, baseline profile"
```

---

## Task 12: CLI Commands `compile`, `apply`, `doctor` (TDD)

**Files:** `packages/cli/src/index.ts` (replaces placeholder), `packages/cli/src/commands/compile.ts`, `packages/cli/src/commands/apply.ts`, `packages/cli/src/commands/doctor.ts`, three test files

- [ ] **Step 1: Failing test for compile command**

`packages/cli/tests/compile-cmd.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileCommand } from '../src/commands/compile.js';

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'ccsec-cli-comp-'));
  await mkdir(join(root, 'settings/overlays'), { recursive: true });
  await mkdir(join(root, 'settings/profiles'), { recursive: true });
  await writeFile(join(root, 'settings/base.json'), JSON.stringify({ schema: 1, permissions: { deny: [] }, hooks: {} }));
  await writeFile(join(root, 'settings/overlays/secrets.json'), JSON.stringify({
    permissions: { deny: [{ pattern: 'Bash(env)', threat: 'T-001-secret-leak' }] },
    hooks: { PreToolUse: [{ name: 'secret-guard' }] },
  }));
  await writeFile(join(root, 'settings/profiles/baseline.json'), JSON.stringify({ extends: ['base', 'overlays/secrets'], overrides: {} }));
});

describe('compile command', () => {
  it('writes compiled settings.json to --out', async () => {
    const outPath = join(root, 'compiled.json');
    await compileCommand({ settingsRoot: join(root, 'settings'), profile: 'baseline', out: outPath, target: 'managed', os: 'macos', env: { HOME: '/Users/x' } });
    const compiled = JSON.parse(await readFile(outPath, 'utf8'));
    expect(compiled.permissions.deny[0].pattern).toBe('Bash(env)');
    expect(compiled.permissions.deny[0].threat).toBeUndefined();
  });
  it('keeps threat field when --target user', async () => {
    const outPath = join(root, 'compiled-user.json');
    await compileCommand({ settingsRoot: join(root, 'settings'), profile: 'baseline', out: outPath, target: 'user', os: 'macos', env: { HOME: '/Users/x' } });
    const compiled = JSON.parse(await readFile(outPath, 'utf8'));
    expect(compiled.permissions.deny[0].threat).toBe('T-001-secret-leak');
  });
});
```

- [ ] **Step 2: Implement `commands/compile.ts`**

```ts
import { writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { TargetOS } from '@bitsummit/ccsec-core';
import { compileProfile } from '../compiler.js';

export interface CompileCommandArgs {
  settingsRoot: string;
  profile: 'baseline' | 'strict' | 'regulated';
  out: string;
  target: 'managed' | 'user';
  os: TargetOS;
  env?: Readonly<Record<string, string>>;
}

export async function compileCommand(args: CompileCommandArgs): Promise<void> {
  const compiled = await compileProfile({
    settingsRoot: args.settingsRoot,
    profile: args.profile,
    os: args.os,
    ...(args.env !== undefined ? { env: args.env } : {}),
    stripThreatField: args.target === 'managed',
  });
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, JSON.stringify(compiled, null, 2) + '\n', 'utf8');
}
```

Run: `pnpm --filter @bitsummit/ccsec-cli test compile-cmd` -> PASS, 2/2.

- [ ] **Step 3: Failing test for apply command**

`packages/cli/tests/apply.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyCommand } from '../src/commands/apply.js';

let root: string;
let claudeDir: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'ccsec-cli-apply-'));
  claudeDir = join(root, '.claude');
  await mkdir(join(root, 'settings/overlays'), { recursive: true });
  await mkdir(join(root, 'settings/profiles'), { recursive: true });
  await writeFile(join(root, 'settings/base.json'), JSON.stringify({ schema: 1, permissions: { deny: [] }, hooks: {} }));
  await writeFile(join(root, 'settings/overlays/secrets.json'), JSON.stringify({
    permissions: { deny: [{ pattern: 'Bash(env)', threat: 'T-001-secret-leak' }] }, hooks: {},
  }));
  await writeFile(join(root, 'settings/profiles/baseline.json'), JSON.stringify({ extends: ['base', 'overlays/secrets'], overrides: {} }));
});

describe('apply command', () => {
  it('writes settings.json + lockfile', async () => {
    await applyCommand({ settingsRoot: join(root, 'settings'), profile: 'baseline', claudeDir, os: 'macos', env: { HOME: '/Users/x' }, dryRun: false });
    const settings = JSON.parse(await readFile(join(claudeDir, 'settings.json'), 'utf8'));
    const lock = JSON.parse(await readFile(join(claudeDir, '.ccsec-lock.json'), 'utf8'));
    expect(settings.permissions.deny[0].pattern).toBe('Bash(env)');
    expect(lock.profile).toBe('baseline');
  });
  it('does not write when dryRun=true', async () => {
    await applyCommand({ settingsRoot: join(root, 'settings'), profile: 'baseline', claudeDir, os: 'macos', env: { HOME: '/Users/x' }, dryRun: true });
    await expect(stat(join(claudeDir, 'settings.json'))).rejects.toThrow();
  });
  it('refuses to clobber a user-modified settings.json', async () => {
    await applyCommand({ settingsRoot: join(root, 'settings'), profile: 'baseline', claudeDir, os: 'macos', env: { HOME: '/Users/x' }, dryRun: false });
    await writeFile(join(claudeDir, 'settings.json'), '{ "permissions": { "deny": [] } }');
    await expect(applyCommand({ settingsRoot: join(root, 'settings'), profile: 'baseline', claudeDir, os: 'macos', env: { HOME: '/Users/x' }, dryRun: false })).rejects.toThrow(/modified/);
  });
});
```

- [ ] **Step 4: Implement `commands/apply.ts`**

```ts
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { TargetOS } from '@bitsummit/ccsec-core';
import { compileProfile } from '../compiler.js';

export interface ApplyCommandArgs {
  settingsRoot: string;
  profile: 'baseline' | 'strict' | 'regulated';
  claudeDir: string;
  os: TargetOS;
  env?: Readonly<Record<string, string>>;
  dryRun: boolean;
}

interface Lockfile { profile: string; ccsec_version: string; applied_at: string; settings_sha256: string; }

const VERSION = '0.1.0-alpha.0';
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

export async function applyCommand(args: ApplyCommandArgs): Promise<{ wrote: boolean }> {
  const compiled = await compileProfile({
    settingsRoot: args.settingsRoot,
    profile: args.profile,
    os: args.os,
    ...(args.env !== undefined ? { env: args.env } : {}),
    stripThreatField: false,
  });
  const settingsPath = join(args.claudeDir, 'settings.json');
  const lockPath = join(args.claudeDir, '.ccsec-lock.json');

  try {
    const lock = JSON.parse(await readFile(lockPath, 'utf8')) as Lockfile;
    const existing = await readFile(settingsPath, 'utf8');
    if (sha256(existing) !== lock.settings_sha256) {
      throw new Error(`existing ${settingsPath} has been modified since last apply; refusing to clobber.`);
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }

  if (args.dryRun) return { wrote: false };

  await mkdir(args.claudeDir, { recursive: true });
  const body = JSON.stringify(compiled, null, 2) + '\n';
  await writeFile(settingsPath, body, 'utf8');
  const lock: Lockfile = {
    profile: args.profile, ccsec_version: VERSION,
    applied_at: new Date().toISOString(), settings_sha256: sha256(body),
  };
  await writeFile(lockPath, JSON.stringify(lock, null, 2) + '\n', 'utf8');
  return { wrote: true };
}
```

Run: `pnpm --filter @bitsummit/ccsec-cli test apply` -> PASS, 3/3.

- [ ] **Step 5: Failing test for doctor command**

`packages/cli/tests/doctor.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { doctorCommand } from '../src/commands/doctor.js';

let claudeDir: string;
beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), 'ccsec-doctor-'));
  claudeDir = join(root, '.claude');
  await mkdir(claudeDir, { recursive: true });
});

describe('doctor command', () => {
  it('reports missing settings.json', async () => {
    const r = await doctorCommand({ claudeDir });
    expect(r.findings.some(f => f.code === 'missing_settings')).toBe(true);
  });
  it('reports stale lockfile when settings.json hash drifts', async () => {
    await writeFile(join(claudeDir, 'settings.json'), '{}');
    await writeFile(join(claudeDir, '.ccsec-lock.json'), JSON.stringify({
      profile: 'baseline', ccsec_version: '0.1.0-alpha.0',
      applied_at: '2026-01-01T00:00:00Z', settings_sha256: 'deadbeef',
    }));
    const r = await doctorCommand({ claudeDir });
    expect(r.findings.some(f => f.code === 'lockfile_drift')).toBe(true);
  });
  it('returns ok=true when matched', async () => {
    const settings = '{}\n';
    const { createHash } = await import('node:crypto');
    const sha = createHash('sha256').update(settings).digest('hex');
    await writeFile(join(claudeDir, 'settings.json'), settings);
    await writeFile(join(claudeDir, '.ccsec-lock.json'), JSON.stringify({
      profile: 'baseline', ccsec_version: '0.1.0-alpha.0',
      applied_at: '2026-01-01T00:00:00Z', settings_sha256: sha,
    }));
    const r = await doctorCommand({ claudeDir });
    expect(r.ok).toBe(true);
  });
});
```

- [ ] **Step 6: Implement `commands/doctor.ts`**

```ts
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

export interface DoctorArgs { claudeDir: string; }
export interface DoctorFinding {
  code: 'missing_settings' | 'missing_lockfile' | 'lockfile_drift' | 'invalid_lockfile';
  message: string;
}
export interface DoctorResult { ok: boolean; findings: DoctorFinding[]; }

export async function doctorCommand(args: DoctorArgs): Promise<DoctorResult> {
  const findings: DoctorFinding[] = [];
  const settingsPath = join(args.claudeDir, 'settings.json');
  const lockPath = join(args.claudeDir, '.ccsec-lock.json');

  let settingsBody: string | null = null;
  try { settingsBody = await readFile(settingsPath, 'utf8'); }
  catch { findings.push({ code: 'missing_settings', message: `${settingsPath} not found` }); }

  let lockBody: string | null = null;
  try { lockBody = await readFile(lockPath, 'utf8'); }
  catch { if (settingsBody) findings.push({ code: 'missing_lockfile', message: `${lockPath} not found` }); }

  if (settingsBody && lockBody) {
    try {
      const lock = JSON.parse(lockBody) as { settings_sha256: string };
      const sha = createHash('sha256').update(settingsBody).digest('hex');
      if (sha !== lock.settings_sha256) {
        findings.push({ code: 'lockfile_drift', message: 'settings.json hash differs from lockfile' });
      }
    } catch {
      findings.push({ code: 'invalid_lockfile', message: `${lockPath} is not valid JSON` });
    }
  }
  return { ok: findings.length === 0, findings };
}
```

Run: `pnpm --filter @bitsummit/ccsec-cli test doctor` -> PASS, 3/3.

- [ ] **Step 7: Replace placeholder `index.ts` with the real Commander entry**

`packages/cli/src/index.ts`:
```ts
import { Command } from 'commander';
import { compileCommand } from './commands/compile.js';
import { applyCommand } from './commands/apply.js';
import { doctorCommand } from './commands/doctor.js';

const PKG_VERSION = '0.1.0-alpha.0';
const SETTINGS_ROOT_DEFAULT = new URL('../../settings', import.meta.url).pathname;
const detectOs = (): 'macos' | 'linux' | 'windows' =>
  process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'linux';

export async function main(argv: string[]): Promise<void> {
  const program = new Command();
  program.name('ccsec').description('Claude Code Security CLI').version(PKG_VERSION);

  program.command('compile')
    .requiredOption('--profile <name>')
    .requiredOption('--out <path>')
    .option('--target <kind>', 'managed | user', 'user')
    .option('--os <os>', 'macos | linux | windows', detectOs())
    .option('--settings-root <path>', SETTINGS_ROOT_DEFAULT)
    .action(async (opts) => {
      await compileCommand({ settingsRoot: opts.settingsRoot, profile: opts.profile, out: opts.out, target: opts.target, os: opts.os });
      console.log(`compiled ${opts.profile} -> ${opts.out}`);
    });

  program.command('apply')
    .requiredOption('--profile <name>')
    .option('--claude-dir <path>', `${process.env.HOME}/.claude`)
    .option('--os <os>', detectOs())
    .option('--settings-root <path>', SETTINGS_ROOT_DEFAULT)
    .option('--dry-run', '', false)
    .action(async (opts) => {
      const r = await applyCommand({ settingsRoot: opts.settingsRoot, profile: opts.profile, claudeDir: opts.claudeDir, os: opts.os, dryRun: !!opts.dryRun });
      console.log(r.wrote ? `applied ${opts.profile} -> ${opts.claudeDir}/settings.json` : 'dry-run, nothing written');
    });

  program.command('doctor')
    .option('--claude-dir <path>', `${process.env.HOME}/.claude`)
    .action(async (opts) => {
      const r = await doctorCommand({ claudeDir: opts.claudeDir });
      if (r.ok) { console.log('OK'); return; }
      for (const f of r.findings) console.error(`[${f.code}] ${f.message}`);
      process.exit(1);
    });

  await program.parseAsync(argv);
}
```

- [ ] **Step 8: Build + smoke test + commit**

```bash
pnpm --filter @bitsummit/ccsec-core build
pnpm --filter @bitsummit/ccsec-hooks build
pnpm --filter @bitsummit/ccsec-cli build
node packages/cli/bin/ccsec.js compile --profile baseline --out /tmp/ccsec-test.json --target managed --os macos --settings-root packages/settings
git add -A && git commit -m "feat(cli): add compile/apply/doctor commands and commander entry point"
```

Expected: smoke test produces a valid JSON with no `threat` fields.

---

## Task 13: Compile Baseline Profile and Snapshot

**Files:** `packages/settings/compiled/baseline.json`, `packages/settings/snapshot.test.ts`

- [ ] **Step 1: Generate snapshot**

```bash
HOME=/Users/x pnpm build:settings
```

Expected: `packages/settings/compiled/baseline.json` exists with deny patterns and `${HOME}` resolved to `/Users/x`.

- [ ] **Step 2: Snapshot test**

`packages/settings/snapshot.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

describe('settings/compiled snapshots', () => {
  it('baseline.json matches checked-in snapshot', async () => {
    const body = await readFile(join(here, 'compiled', 'baseline.json'), 'utf8');
    expect(body).toMatchSnapshot();
  });
});
```

- [ ] **Step 3: Seed snapshot, commit**

```bash
pnpm vitest run packages/settings/snapshot.test.ts -u
git add -A && git commit -m "feat(settings): commit compiled baseline snapshot and add drift-detection test"
```

---

## Task 14: Integration Test - Replay Synthetic Transcript

**Files:** `tests/integration/transcripts/secret-leak-attempt.json`, `tests/integration/secret-leak-attempt.test.ts`, `tests/integration/package.json`

- [ ] **Step 1: Package metadata**

`tests/integration/package.json`:
```json
{ "name": "ccsec-integration-tests", "version": "0.0.0", "private": true, "type": "module" }
```

- [ ] **Step 2: Transcript fixture**

`tests/integration/transcripts/secret-leak-attempt.json`:
```json
{
  "name": "secret-leak-attempt",
  "events": [
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "ls -la" } },
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "echo hello world" } },
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "echo AKIAIOSFODNN7EXAMPLE" } },
    { "tool": "Bash", "event": "PreToolUse", "input": { "command": "printenv AWS_SECRET_ACCESS_KEY" } }
  ],
  "expected": [
    { "decision": "allow" },
    { "decision": "allow" },
    { "decision": "block", "blockedBy": "secret-guard" },
    { "decision": "block", "blockedBy": "secret-guard" }
  ]
}
```

- [ ] **Step 3: Test**

`tests/integration/secret-leak-attempt.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { readFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runHooks } from '@bitsummit/ccsec-core';
import secretGuard from '@bitsummit/ccsec-hooks/dist/secret-guard/index.js';

const here = dirname(fileURLToPath(import.meta.url));

describe('integration: secret-leak-attempt transcript', () => {
  let auditPath: string;
  beforeEach(async () => {
    auditPath = join(await mkdtemp(join(tmpdir(), 'ccsec-int-')), 'audit.jsonl');
  });

  it('replay matches expected decisions', async () => {
    const fixture = JSON.parse(await readFile(join(here, 'transcripts', 'secret-leak-attempt.json'), 'utf8'));
    for (let i = 0; i < fixture.events.length; i++) {
      const ev = fixture.events[i];
      const exp = fixture.expected[i];
      const result = await runHooks(
        { hooks: [secretGuard], profile: 'baseline', auditLogPath: auditPath },
        { tool: ev.tool, event: ev.event, input: ev.input },
      );
      expect(result.decision, `event ${i}`).toBe(exp.decision);
      if (exp.blockedBy) expect(result.blockedBy).toBe(exp.blockedBy);
    }
  });
});
```

- [ ] **Step 4: Build hooks, run, commit**

```bash
pnpm --filter @bitsummit/ccsec-hooks build
pnpm vitest run tests/integration/secret-leak-attempt.test.ts
git add -A && git commit -m "test(integration): replay secret-leak-attempt transcript through runner+secret-guard"
```

Expected: PASS, 1/1 test, 4 transcript events.

---

## Task 15: macOS Installer

**Files:** `installers/macos/install.sh`, `installers/macos/verify.sh`, `installers/macos/tests/install.bats`, `installers/windows/README.md`, `installers/linux/README.md`

- [ ] **Step 1: `install.sh`**

`installers/macos/install.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

PROFILE="baseline"
CLAUDE_DIR="${HOME}/.claude"
DRY_RUN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)    PROFILE="$2"; shift 2 ;;
    --claude-dir) CLAUDE_DIR="$2"; shift 2 ;;
    --dry-run)    DRY_RUN="--dry-run"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "error: node not found in PATH; install Node >=20.10" >&2
  exit 3
fi

echo "ccsec macOS installer: profile=${PROFILE} claude_dir=${CLAUDE_DIR}"

if [[ ! -f "${REPO_ROOT}/packages/cli/dist/index.js" ]]; then
  echo "building ccsec from source..."
  (cd "${REPO_ROOT}" && pnpm install --frozen-lockfile && pnpm -r build)
fi

node "${REPO_ROOT}/packages/cli/bin/ccsec.js" apply \
  --profile "${PROFILE}" \
  --claude-dir "${CLAUDE_DIR}" \
  --os macos \
  --settings-root "${REPO_ROOT}/packages/settings" \
  ${DRY_RUN}

echo "done."
```

```bash
chmod +x installers/macos/install.sh
```

- [ ] **Step 2: `verify.sh`**

`installers/macos/verify.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
CLAUDE_DIR="${HOME}/.claude"
[[ "${1:-}" == "--claude-dir" ]] && CLAUDE_DIR="$2"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
node "${REPO_ROOT}/packages/cli/bin/ccsec.js" doctor --claude-dir "${CLAUDE_DIR}"
```

```bash
chmod +x installers/macos/verify.sh
```

- [ ] **Step 3: Bats tests**

`installers/macos/tests/install.bats`:
```bash
#!/usr/bin/env bats

setup() {
  TMPHOME="$(mktemp -d)"
  export FAKE_CLAUDE_DIR="${TMPHOME}/.claude"
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
  (cd "${REPO_ROOT}" && pnpm -r build >/dev/null 2>&1) || true
}
teardown() { rm -rf "${TMPHOME}"; }

@test "install.sh writes settings.json into target claude-dir" {
  run "${BATS_TEST_DIRNAME}/../install.sh" --profile baseline --claude-dir "${FAKE_CLAUDE_DIR}"
  [ "$status" -eq 0 ]
  [ -f "${FAKE_CLAUDE_DIR}/settings.json" ]
  [ -f "${FAKE_CLAUDE_DIR}/.ccsec-lock.json" ]
}

@test "install.sh --dry-run writes nothing" {
  run "${BATS_TEST_DIRNAME}/../install.sh" --profile baseline --claude-dir "${FAKE_CLAUDE_DIR}" --dry-run
  [ "$status" -eq 0 ]
  [ ! -f "${FAKE_CLAUDE_DIR}/settings.json" ]
}

@test "verify.sh reports OK after install" {
  "${BATS_TEST_DIRNAME}/../install.sh" --profile baseline --claude-dir "${FAKE_CLAUDE_DIR}"
  run "${BATS_TEST_DIRNAME}/../verify.sh" --claude-dir "${FAKE_CLAUDE_DIR}"
  [ "$status" -eq 0 ]
  [[ "${output}" == *"OK"* ]]
}

@test "verify.sh fails after settings.json is tampered" {
  "${BATS_TEST_DIRNAME}/../install.sh" --profile baseline --claude-dir "${FAKE_CLAUDE_DIR}"
  echo '{"permissions":{"deny":[]}}' > "${FAKE_CLAUDE_DIR}/settings.json"
  run "${BATS_TEST_DIRNAME}/../verify.sh" --claude-dir "${FAKE_CLAUDE_DIR}"
  [ "$status" -ne 0 ]
}
```

- [ ] **Step 4: Run bats**

```bash
brew install bats-core
bats installers/macos/tests/install.bats
```

Expected: PASS, 4/4.

- [ ] **Step 5: Stub READMEs**

`installers/windows/README.md`:
```markdown
# Windows Installer (planned for v1.1)

Will host the PowerShell installer, Intune ADMX template, and optional MSI in Phase 2 (Plan 7). Until then, Windows users can install via the npm distribution channel once it ships in Plan 6.
```

`installers/linux/README.md`:
```markdown
# Linux Installer (planned for v1.2)

Will host the shell installer, Ansible role, and `.deb`/`.rpm` packages in Phase 3. Until then, Linux users can install via the npm distribution channel once it ships in Plan 6.
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(installers): macOS install.sh + verify.sh with bats tests; Windows/Linux stubs"
```

---

## Task 16: Initial Threat Model and ADRs

**Files:** `SECURITY.md`, `docs/threat-model.md`, `docs/adr/0001-node-implementation.md`, `docs/adr/0002-monorepo-layout.md`, `docs/adr/0003-passive-only-posture.md`

- [ ] **Step 1: `SECURITY.md`**

```markdown
# Security Policy

## Reporting a Vulnerability

Email `security@bitsummit.ca` (PGP key fingerprint pending; generation tracked for Plan 9). Please do not file public GitHub issues for vulnerabilities.

We aim to acknowledge reports within 72 hours, triage within 14 days for HIGH severity, and 30 days for MEDIUM. Default disclosure window is 90 days.

## Scope

In scope: anything in `packages/`, `installers/`, or default profiles.
Out of scope: third-party hooks, downstream Claude Code itself, OS-level security.

## Security Carve-Out in SemVer

Fixes that *tighten* policy (close a bypass) ship in PATCH versions and are flagged in `CHANGELOG.md` under `### Security`.
```

- [ ] **Step 2: `docs/threat-model.md` (initial, T-001 only)**

```markdown
# Threat Model

> Status: Initial. Plan 1 covers T-001 only. T-002 to T-018 populate as their hooks ship in Plans 2-5.

## Trust Boundaries

1. User prompt to Claude Code process
2. Claude Code to tool invocations (Bash, Edit, Write, WebFetch, MCP)
3. Tool to host filesystem / network / credentials
4. Subagent and parent agent
5. Local settings and managed settings

## Threat Register (Plan 1 Coverage)

### T-001: Secret Leak via Tool Output

- **Vector:** Bash, Read tools
- **STRIDE:** Information Disclosure
- **Agentic Top 10:** A4 Sensitive Information Disclosure
- **Default mitigation:** `secret-guard` hook (PreToolUse, severity=block) detects secret literals (AWS, GitHub, Stripe, PEM, Slack, Google) and env-dump patterns (`printenv`, `env`, echo of secret-bearing variables).
- **Coverage:** baseline, strict, regulated profiles.
- **Known limitations:** custom secret formats not yet covered (extensible via `SECRET_PATTERNS` array). Secrets in stderr are caught only by Plan 4's `secret-leak-detector` (PostToolUse).

## Explicit Non-Goals

- Not a sandbox.
- Not a runtime jail.
- Not a network firewall.
- Not a remote management system.
```

- [ ] **Step 3: ADR-0001**

`docs/adr/0001-node-implementation.md`:
```markdown
# ADR-0001: Node.js as Hook Implementation Language

## Status
Accepted (2026-04-29).

## Context
Hooks must run on macOS, Windows, and Linux. Bash hooks (default in many existing public repos) do not run natively on Windows without WSL or PowerShell rewrites. Maintaining three implementations of the same hook is unsustainable.

## Decision
All hooks are Node.js modules. Cross-platform branching lives in `packages/core/`, never in individual hooks.

## Consequences
- Single hook codebase; per-OS variation handled centrally by `path-tokens.ts` and the runner ctx.
- Node is already a Claude Code dependency, so no new install requirement.
- Bash-fluent maintainers face a learning curve; mitigated by a clear hook contract and TDD.

## Alternatives Considered
- Bash + PowerShell: rejected, dual maintenance and drift risk.
- Python: rejected, introduces a new runtime dependency.
- Rust: rejected, build complexity disproportionate.
```

- [ ] **Step 4: ADR-0002**

`docs/adr/0002-monorepo-layout.md`:
```markdown
# ADR-0002: pnpm Monorepo Layout

## Status
Accepted (2026-04-29).

## Context
Repo ships a CLI, hooks library, settings library, and shared core. Three distribution channels (plugin, npm, raw repo) consume them.

## Decision
pnpm workspaces monorepo. Each package publishes independently but shares `tsconfig.base.json` and `vitest.config.ts`. Source-of-truth is the monorepo; npm packages and plugin tarball are CI build outputs.

## Consequences
- One place to fix a security bug.
- Workspace `workspace:*` references make local linking immediate.
- Publishing requires careful `package.json` `files` whitelisting.

## Alternatives Considered
- Multi-repo: rejected, PR coordination overhead and drift.
- npm workspaces: rejected, pnpm has stricter peer-dep enforcement.
- Bazel/Nx: rejected, overkill for current size.
```

- [ ] **Step 5: ADR-0003**

`docs/adr/0003-passive-only-posture.md`:
```markdown
# ADR-0003: Passive-Only Enforcement Posture (v1.x)

## Status
Accepted (2026-04-29). Revisitable in v2.

## Context
Three options for enforcement posture were considered: (A) passive defaults only, (B) active monitoring daemon, (C) active monitoring + auto-remediation. The user (BITSUMMIT) chose A.

## Decision
v1.x ships *no daemons*, *no auto-remediation*, and *no SIEM coupling code*. Everything is hooks + settings + behavioral rules. Tamper detection is admin-scheduled (`ccsec verify` via cron / Intune compliance script), not always-on.

## Consequences
- Repo positions as a *reference*, not a *product* with operational dependencies.
- Onboarding overhead is minimal; security teams can audit every line.
- Detection of issue-#26637 (`disableAllHooks` bypass) is best-effort: a hook on PreToolUse warns when a local override is detected; it does not block.
- Active tier is on the public backlog; clients who ask explicitly will get a v2 conversation.

## Alternatives Considered
- Active daemon: rejected for v1, invasive without paid support agreements.
- Auto-remediation: rejected for v1, kills active dev sessions on tamper, will burn trust.
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "docs: initial threat model (T-001 only) and three foundational ADRs"
```

---

## Task 17: GitHub Actions CI

**Files:** `.github/workflows/ci.yml`

- [ ] **Step 1: Workflow**

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v3
        with: { version: 9.12.0 }
      - uses: actions/setup-node@v4
        with: { node-version: 20.10.0, cache: pnpm }
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint
      - run: pnpm typecheck
      - run: pnpm build
      - run: pnpm test --coverage
      - name: bats
        run: |
          brew install bats-core
          bats installers/macos/tests/install.bats
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: coverage, path: coverage/ }
```

- [ ] **Step 2: Local final gate**

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm build
pnpm test --coverage
bats installers/macos/tests/install.bats
```

Expected: every step exits 0; coverage thresholds met (>=90% on `packages/core/`).

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "ci: macOS workflow running lint/typecheck/build/test/bats with coverage upload"
```

---

## Task 18: Tag and Hand Off

- [ ] **Step 1: Confirm CHANGELOG accuracy**

Open `CHANGELOG.md`, verify the `## [0.1.0-alpha.0] - 2026-04-29` block lists every change committed in Tasks 1-17. Update if needed.

- [ ] **Step 2: Final smoke test**

```bash
TMPHOME=$(mktemp -d)
HOME=$TMPHOME ./installers/macos/install.sh --profile baseline --claude-dir "$TMPHOME/.claude"
test -f "$TMPHOME/.claude/settings.json"
test -f "$TMPHOME/.claude/.ccsec-lock.json"
HOME=$TMPHOME ./installers/macos/verify.sh --claude-dir "$TMPHOME/.claude"
rm -rf "$TMPHOME"
```

Expected: install writes both files; verify prints `OK`.

- [ ] **Step 3: Tag release locally**

```bash
git tag -a v0.1.0-alpha.0 -m "v0.1.0-alpha.0: foundation walking skeleton"
```

- [ ] **Step 4: STOP for user approval before pushing**

Per the global git-workflow rule: never push to remote without explicit user approval. Present this status:

```
Locally complete:
- 18 tasks done
- v0.1.0-alpha.0 tag created
- All tests + bats green, coverage at-or-above 90 percent on core
- Ready to push branch and tag to origin

Please confirm before I push.
```

Do not run `git push` until the user types approval.

- [ ] **Step 5 (after approval only): Push**

```bash
git push origin main
git push origin v0.1.0-alpha.0
```

---

## Self-Review

**Spec coverage check** against `docs/superpowers/specs/2026-04-29-claude-code-security-repo-design.md`:

| Spec section | Plan coverage |
|---|---|
| 1 Purpose & Positioning | `README.md` skeleton (Task 1) |
| 2 Architectural Decisions | ADRs (Task 16) |
| 3 Repo Layout | Tasks 1-2, 9-15 create the in-scope subset; out-of-scope dirs deferred to later plans |
| 4 Hook Runtime & Contract | Tasks 2-8 implement and test the contract; Task 9 proves it with `secret-guard` |
| 5 Settings Templates & Profile Layering | Tasks 10-11, 13 implement the compiler, base + secrets overlay, baseline profile; strict/regulated profiles deferred to Plans 2-5 |
| 6 Distribution Channels | Plan 1 ships raw-repo install only (Task 15); plugin + npm in Plan 6 |
| 7 Threat Model | T-001 documented (Task 16); T-002 to T-018 deferred to Plans 2-5 |
| 8 Documentation Structure | README skeleton + threat-model + 3 ADRs + SECURITY (Tasks 1, 16); full Track 1-5 in Plan 8 |
| 9 Testing Strategy | Layer 1 unit + Layer 2 integration covered; Layer 3 security regression corpora + weekly red-team CI in Plan 9 |
| 10 Versioning, Release & Maintenance | Initial CHANGELOG + SECURITY (Tasks 1, 16); signed releases / SBOM / GHSA in Plan 9 |
| 11 Roadmap & Phasing | This plan IS Plan 1; sequence at top |
| 12 Open Questions | Captured for the engineer; not blocking Plan 1 |

**Placeholder scan:** `SECURITY.md` mentions PGP fingerprint as `pending; generation tracked for Plan 9` which is intentional cross-plan reference, not a missing requirement. No other placeholders.

**Type consistency:** `HookManifest`, `HookContext`, `HookDecision`, `HookModule` defined in Task 2; used unchanged through Tasks 3-9 and 14. `compileProfile` signature in Task 10 matches its consumer in Task 12. `applyCommand` signature in Task 12 (`{ wrote: boolean }`) matches the test expectation.

---

## Plan Complete

This plan ships `v0.1.0-alpha.0`: the foundation walking skeleton. Plans 2-10 build on it incrementally per the sequence at the top.

**Two execution options:**

**1. Subagent-driven (recommended)** - dispatch a fresh subagent per task, review between tasks, fast iteration. Best for a plan this size (18 tasks, ~120 steps); avoids context-window bloat.

**2. Inline** - run tasks in this session using the executing-plans skill, batch with checkpoints for review. Better if you want to watch each step land in real time.

Which approach?
