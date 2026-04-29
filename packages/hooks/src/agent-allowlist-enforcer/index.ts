import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

function parseAllowlist(env: Readonly<Record<string, string>>): string[] {
  const raw = env.CCSEC_AGENT_ALLOWLIST;
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

const agentAllowlistEnforcer: HookModule = {
  manifest: {
    name: 'agent-allowlist-enforcer',
    event: 'SubagentStart',
    matchers: ['*'],
    threat: 'T-011-subagent-escape',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'log', strict: 'log', regulated: 'block' },
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const subagentType =
      typeof ctx.input.subagent_type === 'string' ? ctx.input.subagent_type : null;
    if (!subagentType) {
      return { decision: 'allow', reason: 'no subagent_type field; nothing to record' };
    }
    const allowlist = parseAllowlist(ctx.env);
    if (allowlist.includes(subagentType)) {
      return {
        decision: 'allow',
        reason: `subagent type '${subagentType}' is allowlisted`,
        evidence: { kind: 'allowlisted', subagent_type: subagentType, allowlist },
      };
    }
    return {
      decision: 'block',
      reason: `subagent type '${subagentType}' not in allowlist (downgraded to log on baseline/strict)`,
      evidence: { kind: 'not-allowlisted', subagent_type: subagentType, allowlist },
    };
  },
};

export default agentAllowlistEnforcer;
