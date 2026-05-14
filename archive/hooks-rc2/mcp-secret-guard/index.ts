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
