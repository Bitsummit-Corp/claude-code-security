import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runHooks } from '../src/runner.js';
import type { HookModule } from '../src/types.js';

const allowHook: HookModule = {
  manifest: { name: 'allow-all', event: 'PreToolUse', matchers: ['Bash'], threat: 'T-999-test', profiles: ['baseline'], severity: 'log', timeout_ms: 1000 },
  run: async () => ({ decision: 'allow', reason: 'ok' }),
};
const blockHook: HookModule = {
  manifest: { name: 'block-all', event: 'PreToolUse', matchers: ['Bash'], threat: 'T-001-secret-leak', profiles: ['baseline'], severity: 'block', timeout_ms: 1000 },
  run: async () => ({ decision: 'block', reason: 'denied' }),
};
const slowHook: HookModule = {
  manifest: { name: 'slow', event: 'PreToolUse', matchers: ['Bash'], threat: 'T-016-hook-dos', profiles: ['baseline'], severity: 'log', timeout_ms: 100 },
  run: () => new Promise(r => setTimeout(() => r({ decision: 'allow', reason: 'ok' }), 500)),
};
const wrongMatcher: HookModule = { ...allowHook, manifest: { ...allowHook.manifest, name: 'edit-only', matchers: ['Edit'] } };

let auditPath: string;
beforeEach(async () => {
  auditPath = join(await mkdtemp(join(tmpdir(), 'ccsec-runner-')), 'audit.jsonl');
});

describe('runHooks', () => {
  it('aggregate allow when all hooks allow', async () => {
    const r = await runHooks({ hooks: [allowHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.decision).toBe('allow');
  });
  it('block if any hook blocks', async () => {
    const r = await runHooks({ hooks: [allowHook, blockHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.decision).toBe('block');
    expect(r.blockedBy).toBe('block-all');
  });
  it('skips hooks whose matcher does not match', async () => {
    const r = await runHooks({ hooks: [wrongMatcher], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.invocations).toHaveLength(0);
  });
  it('skips hooks not in active profile', async () => {
    const r = await runHooks({ hooks: [blockHook], profile: 'strict', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.decision).toBe('allow');
  });
  it('aborts hook that exceeds timeout_ms', async () => {
    const r = await runHooks({ hooks: [slowHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.invocations[0]?.outcome).toBe('timeout');
  });
  it('writes one audit record per invocation', async () => {
    await runHooks({ hooks: [allowHook, blockHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    const lines = (await readFile(auditPath, 'utf8')).trim().split('\n');
    expect(lines).toHaveLength(2);
  });
  it('continues running remaining hooks after a block', async () => {
    const r = await runHooks({ hooks: [blockHook, allowHook], profile: 'baseline', auditLogPath: auditPath },
      { tool: 'Bash', input: {}, event: 'PreToolUse' });
    expect(r.invocations).toHaveLength(2);
  });
});
