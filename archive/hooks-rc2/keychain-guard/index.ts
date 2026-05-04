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
