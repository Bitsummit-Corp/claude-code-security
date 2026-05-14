import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (cmd: string, env: Record<string, string> = {}) => ({
  tool: 'Bash',
  input: { command: cmd },
  env,
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('branch-protection-guard', () => {
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

  it('blocks git commit --no-verify', async () => {
    const r = await guard.run(ctx('git commit --no-verify -m "x"'));
    expect(r.decision).toBe('block');
  });

  it('blocks git commit --no-gpg-sign', async () => {
    const r = await guard.run(ctx('git commit --no-gpg-sign -m "x"'));
    expect(r.decision).toBe('block');
  });

  it('blocks git push origin main when env unset', async () => {
    const r = await guard.run(ctx('git push origin main'));
    expect(r.decision).toBe('block');
  });

  it('blocks git push origin master when env unset', async () => {
    const r = await guard.run(ctx('git push origin master'));
    expect(r.decision).toBe('block');
  });

  it('blocks git push origin production when env unset', async () => {
    const r = await guard.run(ctx('git push origin production'));
    expect(r.decision).toBe('block');
  });

  it('allows git push origin main when CCSEC_ALLOW_PROTECTED_PUSH=1', async () => {
    const r = await guard.run(ctx('git push origin main', { CCSEC_ALLOW_PROTECTED_PUSH: '1' }));
    expect(r.decision).toBe('allow');
  });

  it('allows git push origin feature/x regardless', async () => {
    const r = await guard.run(ctx('git push origin feature/x'));
    expect(r.decision).toBe('allow');
  });

  it('allows plain git status', async () => {
    const r = await guard.run(ctx('git status'));
    expect(r.decision).toBe('allow');
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
