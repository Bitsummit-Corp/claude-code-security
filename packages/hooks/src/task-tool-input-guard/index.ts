import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'ignore-previous', re: /ignore previous/i },
  { name: 'bypass-policy', re: /bypass.*polic/i },
  { name: 'override-system', re: /override.*system/i },
];

function fieldText(input: Record<string, unknown>, key: string): string {
  return typeof input[key] === 'string' ? (input[key] as string) : '';
}

const taskToolInputGuard: HookModule = {
  manifest: {
    name: 'task-tool-input-guard',
    event: 'PreToolUse',
    matchers: ['Task'],
    threat: 'T-011-subagent-escape',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const prompt = fieldText(ctx.input, 'prompt');
    const description = fieldText(ctx.input, 'description');
    const text = `${prompt}\n${description}`;
    if (text.trim().length === 0) {
      return { decision: 'allow', reason: 'no prompt/description fields to scan' };
    }
    const matches: string[] = [];
    for (const p of PATTERNS) {
      if (p.re.test(text)) matches.push(p.name);
    }
    if (matches.length === 0) {
      return { decision: 'allow', reason: 'Task prompt/description contained no risky patterns' };
    }
    return {
      decision: 'block',
      reason: `Task input matched ${matches.length} prompt-injection pattern(s)`,
      evidence: { kind: 'task-input-injection', matches, match_count: matches.length },
    };
  },
};

export default taskToolInputGuard;
