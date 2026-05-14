import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'ignore-previous-instructions', re: /ignore previous instructions/i },
  { name: 'system-prompt-disclosure', re: /system prompt/i },
  { name: 'role-override', re: /you are now/i },
  { name: 'override-instructions', re: /override.*instructions/i },
];

function extractText(input: Record<string, unknown>): string {
  if (typeof input.prompt === 'string') return input.prompt;
  if (typeof input.message === 'string') return input.message;
  return '';
}

const behavioralRuleEnforcer: HookModule = {
  manifest: {
    name: 'behavioral-rule-enforcer',
    event: 'UserPromptSubmit',
    matchers: ['*'],
    threat: 'T-010-prompt-injection',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'log',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const text = extractText(ctx.input);
    const matches: string[] = [];
    if (text.length > 0) {
      for (const p of PATTERNS) {
        if (p.re.test(text)) matches.push(p.name);
      }
    }
    return {
      decision: 'allow',
      reason:
        matches.length > 0
          ? `prompt matched ${matches.length} risky pattern(s) (passive log)`
          : 'no risky patterns detected',
      evidence: {
        kind: 'behavioral-scan',
        match_count: matches.length,
        matches,
      },
    };
  },
};

export default behavioralRuleEnforcer;
