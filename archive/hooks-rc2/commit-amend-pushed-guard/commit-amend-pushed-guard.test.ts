import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (cmd: string) => ({
  tool: 'Bash',
  input: { command: cmd },
  env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('commit-amend-pushed-guard', () => {
  it('manifest declares per-profile severity and T-004 threat', () => {
    expect(typeof guard.manifest.severity).toBe('object');
    const sev = guard.manifest.severity as Record<string, string>;
    expect(sev.baseline).toBe('warn');
    expect(sev.strict).toBe('block');
    expect(sev.regulated).toBe('block');
    expect(guard.manifest.threat).toBe('T-004-branch-sabotage');
    expect(guard.manifest.event).toBe('PreToolUse');
    expect(guard.manifest.matchers).toEqual(['Bash']);
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(1500);
  });

  it('blocks git commit --amend', async () => {
    expect((await guard.run(ctx('git commit --amend'))).decision).toBe('block');
  });

  it('blocks git commit -a --amend', async () => {
    expect((await guard.run(ctx('git commit -a --amend'))).decision).toBe('block');
  });

  it('blocks git commit --amend -m "x"', async () => {
    expect((await guard.run(ctx('git commit --amend -m "x"'))).decision).toBe('block');
  });

  it('allows git commit -m "x"', async () => {
    expect((await guard.run(ctx('git commit -m "x"'))).decision).toBe('allow');
  });

  it('allows git commit -a', async () => {
    expect((await guard.run(ctx('git commit -a'))).decision).toBe('allow');
  });

  it('allows plain git status', async () => {
    expect((await guard.run(ctx('git status'))).decision).toBe('allow');
  });

  it('allows when command missing', async () => {
    const r = await guard.run({
      tool: 'Bash',
      input: {},
      env: {},
      paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
      log: () => undefined,
      abort: new AbortController().signal,
    });
    expect(r.decision).toBe('allow');
  });
});
