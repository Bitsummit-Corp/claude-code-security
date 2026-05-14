import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';
import { AuditLogger } from '@bitsummit/ccsec-core';

function resolveLogPath(ctx: HookContext): string {
  const override = ctx.env?.CCSEC_AUDIT_LOG_PATH;
  if (override && override.length > 0) return override;
  return `${ctx.paths.home}/.claude/ccsec-audit.jsonl`;
}

const auditTamperDetector: HookModule = {
  manifest: {
    name: 'audit-tamper-detector',
    event: 'PostToolUse',
    matchers: ['*'],
    threat: 'T-015-audit-tampering',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 2000,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const path = resolveLogPath(ctx);
    const result = await AuditLogger.verify(path);
    if (result.ok) {
      return {
        decision: 'allow',
        reason: `audit log intact (${result.records} records)`,
        evidence: { kind: 'verified', records: result.records, path },
      };
    }
    return {
      decision: 'block',
      reason: `audit log tampering detected at record ${result.brokenAt} (${
        result.reason ?? 'chain-broken'
      })`,
      evidence: {
        kind: 'tampered',
        broken_at: result.brokenAt,
        total_records: result.records,
        verify_reason: result.reason,
        path,
      },
    };
  },
};

export default auditTamperDetector;
