import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLogger } from '@bitsummit/ccsec-core';
import guard from './index.js';

const ctx = (env: Record<string, string>, home = '/tmp') => ({
  tool: 'Bash',
  input: {},
  response: {},
  env,
  paths: { home, ssh: `${home}/.ssh`, aws: `${home}/.aws`, tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('audit-tamper-detector', () => {
  let dir: string;
  let logPath: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'ccsec-tamper-'));
    logPath = join(dir, 'audit.jsonl');
  });

  it('manifest is wildcard PostToolUse for T-015 with per-profile severity', () => {
    expect(guard.manifest.name).toBe('audit-tamper-detector');
    expect(guard.manifest.event).toBe('PostToolUse');
    expect(guard.manifest.matchers).toEqual(['*']);
    expect(guard.manifest.threat).toBe('T-015-audit-tampering');
    const sev = guard.manifest.severity as Record<string, string>;
    expect(sev.baseline).toBe('warn');
    expect(sev.strict).toBe('block');
    expect(sev.regulated).toBe('block');
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(2000);
  });

  it('returns allow on intact log', async () => {
    const logger = new AuditLogger(logPath);
    await logger.write({ hook: 'h', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'h', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const r = await guard.run(ctx({ CCSEC_AUDIT_LOG_PATH: logPath }));
    expect(r.decision).toBe('allow');
  });

  it('returns block on tampered log', async () => {
    const logger = new AuditLogger(logPath);
    await logger.write({ hook: 'h', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'h', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const tampered = (await readFile(logPath, 'utf8')).replace('"reason":"r"', '"reason":"x"');
    await writeFile(logPath, tampered);

    const r = await guard.run(ctx({ CCSEC_AUDIT_LOG_PATH: logPath }));
    expect(r.decision).toBe('block');
    expect(r.evidence?.broken_at).toBeDefined();
  });

  it('returns allow on missing log file', async () => {
    const r = await guard.run(ctx({ CCSEC_AUDIT_LOG_PATH: join(dir, 'never-written.jsonl') }));
    expect(r.decision).toBe('allow');
  });

  it('falls back to ${home}/.claude/ccsec-audit.jsonl when env override is unset', async () => {
    // home points at a tmp directory with no .claude/ccsec-audit.jsonl. Should be treated as
    // "no log yet" and return allow.
    const r = await guard.run(ctx({}, dir));
    expect(r.decision).toBe('allow');
  });

  it('CCSEC_AUDIT_LOG_PATH override takes precedence over default path', async () => {
    // Put a tampered log at the override path, an intact log at the default path. The
    // override path must win and the result must be block.
    const logger = new AuditLogger(logPath);
    await logger.write({ hook: 'h', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const tampered = (await readFile(logPath, 'utf8')).replace('"reason":"r"', '"reason":"X"');
    await writeFile(logPath, tampered);

    const r = await guard.run(ctx({ CCSEC_AUDIT_LOG_PATH: logPath }, dir));
    expect(r.decision).toBe('block');
  });
});
