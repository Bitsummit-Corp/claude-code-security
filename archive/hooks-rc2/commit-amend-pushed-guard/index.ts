import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const COMMIT_AMEND_RE = /\bgit\s+commit\s+(?:.*\s)?--amend\b/;

const commitAmendPushedGuard: HookModule = {
  manifest: {
    name: 'commit-amend-pushed-guard',
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
    if (COMMIT_AMEND_RE.test(cmd)) {
      return {
        decision: 'block',
        reason: 'git commit --amend rewrites history; if the commit was already pushed this corrupts shared state',
        evidence: { kind: 'commit-amend' },
      };
    }
    return { decision: 'allow', reason: 'no amend invocation' };
  },
};

export default commitAmendPushedGuard;
