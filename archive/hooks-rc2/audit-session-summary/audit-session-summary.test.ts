import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLogger } from '@bitsummit/ccsec-core';
import guard from './index.js';

const ctx = (env: Record<string, string>, home = '/tmp') => ({
  tool: 'session',
  input: {},
  env,
  paths: { home, ssh: `${home}/.ssh`, aws: `${home}/.aws`, tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('audit-session-summary', () => {
  let dir: string;
  let logPath: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'ccsec-summary-'));
    logPath = join(dir, 'audit.jsonl');
  });

  it('manifest is wildcard SubagentStop log-only for T-017', () => {
    expect(guard.manifest.name).toBe('audit-session-summary');
    expect(guard.manifest.event).toBe('SubagentStop');
    expect(guard.manifest.matchers).toEqual(['*']);
    expect(guard.manifest.threat).toBe('T-017-repudiation');
    expect(guard.manifest.severity).toBe('log');
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(2000);
  });

  it('returns allow with stats and emits a summary record', async () => {
    const logger = new AuditLogger(logPath);
    await logger.write({
      hook: 'h1',
      tool: 'Bash',
      decision: 'allow',
      reason: 'r',
      duration_ms: 5,
    });
    await logger.write({
      hook: 'h1',
      tool: 'Bash',
      decision: 'block',
      reason: 'r',
      duration_ms: 7,
    });
    await logger.write({
      hook: 'h2',
      tool: 'WebFetch',
      decision: 'allow',
      reason: 'r',
      duration_ms: 2,
    });

    const r = await guard.run(ctx({ CCSEC_AUDIT_LOG_PATH: logPath }));
    expect(r.decision).toBe('allow');
    expect(r.evidence?.total_records).toBe(3);
    expect(r.evidence?.by_hook).toEqual({ h1: 2, h2: 1 });
    expect(r.evidence?.by_decision).toEqual({ allow: 2, block: 1 });
    expect(r.evidence?.total_duration_ms).toBe(14);

    const lines = (await readFile(logPath, 'utf8')).trim().split('\n');
    expect(lines).toHaveLength(4);
    const summary = JSON.parse(lines[3]!);
    expect(summary.hook).toBe('audit-session-summary');
    expect(summary.tool).toBe('session');
    expect(summary.decision).toBe('log');
  });

  it('aggregate counts are correct on a single record', async () => {
    const logger = new AuditLogger(logPath);
    await logger.write({
      hook: 'only',
      tool: 'Bash',
      decision: 'warn',
      reason: 'r',
      duration_ms: 3,
    });
    const r = await guard.run(ctx({ CCSEC_AUDIT_LOG_PATH: logPath }));
    expect(r.evidence?.total_records).toBe(1);
    expect(r.evidence?.by_hook).toEqual({ only: 1 });
    expect(r.evidence?.by_decision).toEqual({ warn: 1 });
  });

  it('handles missing log gracefully', async () => {
    const r = await guard.run(ctx({ CCSEC_AUDIT_LOG_PATH: join(dir, 'missing.jsonl') }));
    expect(r.decision).toBe('allow');
    expect(r.evidence?.total_records).toBe(0);
    // No summary record was emitted because there were no records to summarize.
  });

  it('falls back to ${home}/.claude/ccsec-audit.jsonl when env override is unset', async () => {
    const r = await guard.run(ctx({}, dir));
    expect(r.decision).toBe('allow');
    expect(r.evidence?.total_records).toBe(0);
  });
});
