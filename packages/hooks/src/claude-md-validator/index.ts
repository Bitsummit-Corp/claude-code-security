import { readFile } from 'node:fs/promises';
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const BAD_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'disable-hooks', re: /disable hooks?/i },
  { name: 'skip-permission', re: /skip permission/i },
  { name: 'bypass-security', re: /bypass security/i },
  { name: 'ignore-audit', re: /ignore audit/i },
];

async function tryRead(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

async function loadClaudeMd(ctx: HookContext): Promise<{ path: string; content: string } | null> {
  const override = ctx.env?.CCSEC_CLAUDEMD_PATH;
  const candidates: string[] = [];
  if (override && override.length > 0) candidates.push(override);
  candidates.push(`${process.cwd()}/CLAUDE.md`);
  candidates.push(`${ctx.paths.home}/CLAUDE.md`);
  for (const p of candidates) {
    const content = await tryRead(p);
    if (content !== null) return { path: p, content };
  }
  return null;
}

const claudeMdValidator: HookModule = {
  manifest: {
    name: 'claude-md-validator',
    event: 'SessionStart',
    matchers: ['*'],
    threat: 'T-010-prompt-injection',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 2000,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const loaded = await loadClaudeMd(ctx);
    if (!loaded) {
      return { decision: 'allow', reason: 'no CLAUDE.md found at any candidate path' };
    }
    const matches: string[] = [];
    for (const p of BAD_PATTERNS) {
      if (p.re.test(loaded.content)) matches.push(p.name);
    }
    if (matches.length === 0) {
      return {
        decision: 'allow',
        reason: 'CLAUDE.md scanned, no risky directives detected',
        evidence: { kind: 'claudemd-clean', path: loaded.path },
      };
    }
    return {
      decision: 'block',
      reason: `CLAUDE.md contains risky directives: ${matches.join(', ')}`,
      evidence: { kind: 'claudemd-risky', path: loaded.path, matches, match_count: matches.length },
    };
  },
};

export default claudeMdValidator;
