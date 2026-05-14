import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';
import { detectSecrets } from '@bitsummit/ccsec-core';

const MAX_SCAN_BYTES = 256 * 1024;

function gather(response: Record<string, unknown> | undefined): { text: string; truncated: boolean } {
  if (!response) return { text: '', truncated: false };
  const parts: string[] = [];
  if (typeof response.stdout === 'string') parts.push(response.stdout);
  if (typeof response.stderr === 'string') parts.push(response.stderr);
  if (typeof response.output === 'string') parts.push(response.output);
  const joined = parts.join('\n');
  if (joined.length > MAX_SCAN_BYTES) {
    return { text: joined.slice(0, MAX_SCAN_BYTES), truncated: true };
  }
  return { text: joined, truncated: false };
}

const secretLeakDetector: HookModule = {
  manifest: {
    name: 'secret-leak-detector',
    event: 'PostToolUse',
    matchers: ['Bash', 'Read'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const { text, truncated } = gather(ctx.response);
    if (!text) return { decision: 'allow', reason: 'no response payload' };
    const hits = detectSecrets(text);
    if (hits.length === 0) {
      return {
        decision: 'allow',
        reason: truncated ? 'no secrets detected (response truncated to 256KB)' : 'no secrets detected',
      };
    }
    return {
      decision: 'block',
      reason: `secret in tool output: ${hits.map(h => h.label).join(', ')}`,
      evidence: { hits: hits.map(h => ({ label: h.label, redacted: h.redacted })) },
    };
  },
};

export default secretLeakDetector;
