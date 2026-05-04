import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';
import { detectStructuralRisks } from '@bitsummit/ccsec-core';
import type { StructuralRiskKind } from '@bitsummit/ccsec-core';

const BLOCK_KINDS: ReadonlySet<StructuralRiskKind> = new Set([
  'pipe_to_shell',
  'command_substitution',
  'process_substitution',
  'unicode_lookalike',
  'background_operator',
]);

// Allow-listed kinds (everyday shell idioms): chained_and, chained_or,
// chained_semicolon, leading_cd. These are surfaced by the parser but are
// not blocked here; surfaced via audit only.

const bashStructuralGuard: HookModule = {
  manifest: {
    name: 'bash-structural-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-006-pipe-to-shell',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd) return { decision: 'allow', reason: 'no command field' };
    const risks = detectStructuralRisks(cmd);
    if (risks.length === 0) {
      return { decision: 'allow', reason: 'no structural risks detected' };
    }
    const blocked = risks.filter((r) => BLOCK_KINDS.has(r.kind));
    if (blocked.length === 0) {
      return {
        decision: 'allow',
        reason: `only allow-listed risk kinds present: ${risks.map((r) => r.kind).join(', ')}`,
      };
    }
    const kinds = Array.from(new Set(blocked.map((r) => r.kind)));
    return {
      decision: 'block',
      reason: `bash structural risk: ${kinds.join(', ')}`,
      evidence: { kinds },
    };
  },
};

export default bashStructuralGuard;
