import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (cmd: string) => ({
  tool: 'Bash', input: { command: cmd }, env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('git-destructive-guard', () => {
  it('manifest declares per-profile severity', () => {
    expect(typeof guard.manifest.severity).toBe('object');
    const sev = guard.manifest.severity as Record<string, string>;
    expect(sev.baseline).toBe('warn');
    expect(sev.strict).toBe('block');
    expect(sev.regulated).toBe('block');
  });
  it('manifest threat is T-004', () => {
    expect(guard.manifest.threat).toBe('T-004-branch-sabotage');
  });
  it('flags git reset --hard', async () => {
    expect((await guard.run(ctx('git reset --hard HEAD~10'))).decision).toBe('block');
  });
  it('flags git clean -fd', async () => {
    expect((await guard.run(ctx('git clean -fd'))).decision).toBe('block');
  });
  it('flags git push --force', async () => {
    expect((await guard.run(ctx('git push --force origin main'))).decision).toBe('block');
  });
  it('flags git push -f', async () => {
    expect((await guard.run(ctx('git push -f origin main'))).decision).toBe('block');
  });
  it('flags git branch -D on protected branches', async () => {
    expect((await guard.run(ctx('git branch -D main'))).decision).toBe('block');
  });
  it('allows git status', async () => {
    expect((await guard.run(ctx('git status'))).decision).toBe('allow');
  });
  it('allows git push without force', async () => {
    expect((await guard.run(ctx('git push origin feature/x'))).decision).toBe('allow');
  });
});
