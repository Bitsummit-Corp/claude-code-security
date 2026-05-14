import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

interface Match {
  kind: string;
  pattern: RegExp;
}

const PATTERNS: Match[] = [
  { kind: 'filter-branch', pattern: /\bgit\s+filter-branch\b/ },
  { kind: 'filter-repo', pattern: /\bgit\s+filter-repo\b/ },
  { kind: 'bfg-strip-blobs', pattern: /\bbfg\b.*--strip-blobs/ },
  { kind: 'git-replace', pattern: /\bgit\s+replace\b/ },
  { kind: 'update-ref', pattern: /\bgit\s+update-ref\s+(HEAD|refs\/heads\/)/ },
];

const gitHistoryRewriteGuard: HookModule = {
  manifest: {
    name: 'git-history-rewrite-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-008-history-rewrite',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd) return { decision: 'allow', reason: 'no command field' };
    for (const { kind, pattern } of PATTERNS) {
      if (pattern.test(cmd)) {
        return {
          decision: 'block',
          reason: `git history rewrite pattern: ${kind}`,
          evidence: { kind },
        };
      }
    }
    return { decision: 'allow', reason: 'no history-rewrite pattern matched' };
  },
};

export default gitHistoryRewriteGuard;
