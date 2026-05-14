import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const COMMIT_NO_VERIFY_RE = /\bgit\s+commit\s+(?:.*\s)?--no-verify\b/;
const COMMIT_NO_GPG_RE = /\bgit\s+commit\s+(?:.*\s)?--no-gpg-sign\b/;
const PROTECTED_PUSH_RE =
  /\bgit\s+push\s+(?:.*\s)?origin\s+(main|master|release|develop|prod|production)\b/;

const branchProtectionGuard: HookModule = {
  manifest: {
    name: 'branch-protection-guard',
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

    if (COMMIT_NO_VERIFY_RE.test(cmd)) {
      return {
        decision: 'block',
        reason: 'git commit --no-verify bypasses pre-commit hooks',
        evidence: { kind: 'commit-no-verify' },
      };
    }
    if (COMMIT_NO_GPG_RE.test(cmd)) {
      return {
        decision: 'block',
        reason: 'git commit --no-gpg-sign bypasses commit signing',
        evidence: { kind: 'commit-no-gpg-sign' },
      };
    }

    const protectedMatch = PROTECTED_PUSH_RE.exec(cmd);
    if (protectedMatch) {
      const allow = ctx.env?.CCSEC_ALLOW_PROTECTED_PUSH;
      if (!allow) {
        return {
          decision: 'block',
          reason: `direct push to protected branch '${protectedMatch[1]}' (set CCSEC_ALLOW_PROTECTED_PUSH=1 to override)`,
          evidence: { kind: 'protected-push', branch: protectedMatch[1] },
        };
      }
    }

    return { decision: 'allow', reason: 'no branch protection violation' };
  },
};

export default branchProtectionGuard;
