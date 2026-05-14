import { readFile } from 'node:fs/promises';
import type { HookModule, HookContext, HookDecision, AuditRecord } from '@bitsummit/ccsec-core';
import { AuditLogger } from '@bitsummit/ccsec-core';

function resolveLogPath(ctx: HookContext): string {
  const override = ctx.env?.CCSEC_AUDIT_LOG_PATH;
  if (override && override.length > 0) return override;
  return `${ctx.paths.home}/.claude/ccsec-audit.jsonl`;
}

async function readRecords(path: string): Promise<AuditRecord[]> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  const lines = raw.trim().split('\n').filter(Boolean);
  const records: AuditRecord[] = [];
  for (const line of lines) {
    try {
      records.push(JSON.parse(line) as AuditRecord);
    } catch {
      // Skip malformed lines; audit-tamper-detector is responsible for raising those.
    }
  }
  return records;
}

interface SessionStats {
  total_records: number;
  by_hook: Record<string, number>;
  by_decision: Record<string, number>;
  total_duration_ms: number;
}

function aggregate(records: AuditRecord[]): SessionStats {
  const by_hook: Record<string, number> = {};
  const by_decision: Record<string, number> = {};
  let total_duration_ms = 0;
  for (const r of records) {
    by_hook[r.hook] = (by_hook[r.hook] ?? 0) + 1;
    by_decision[r.decision] = (by_decision[r.decision] ?? 0) + 1;
    total_duration_ms += typeof r.duration_ms === 'number' ? r.duration_ms : 0;
  }
  return { total_records: records.length, by_hook, by_decision, total_duration_ms };
}

const auditSessionSummary: HookModule = {
  manifest: {
    name: 'audit-session-summary',
    event: 'SubagentStop',
    matchers: ['*'],
    threat: 'T-017-repudiation',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'log',
    timeout_ms: 2000,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const path = resolveLogPath(ctx);
    const records = await readRecords(path);
    const stats = aggregate(records);

    if (stats.total_records > 0) {
      const logger = new AuditLogger(path);
      await logger.write({
        hook: 'audit-session-summary',
        tool: 'session',
        decision: 'log',
        reason: 'session summary',
        duration_ms: 0,
        evidence_digest: JSON.stringify(stats),
      });
    }

    return {
      decision: 'allow',
      reason: `summary emitted (${stats.total_records} records aggregated)`,
      evidence: { kind: 'session-summary', path, ...stats },
    };
  },
};

export default auditSessionSummary;
