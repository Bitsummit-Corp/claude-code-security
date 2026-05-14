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

describe('git-history-rewrite-guard', () => {
  it('manifest declares scalar block severity and T-008 threat', () => {
    expect(guard.manifest.severity).toBe('block');
    expect(guard.manifest.threat).toBe('T-008-history-rewrite');
    expect(guard.manifest.event).toBe('PreToolUse');
    expect(guard.manifest.matchers).toEqual(['Bash']);
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(1500);
  });

  it('blocks git filter-branch', async () => {
    expect(
      (await guard.run(ctx('git filter-branch --tree-filter "rm secret.txt" HEAD'))).decision,
    ).toBe('block');
  });

  it('blocks git filter-repo', async () => {
    expect(
      (await guard.run(ctx('git filter-repo --invert-paths --path secret.txt'))).decision,
    ).toBe('block');
  });

  it('blocks bfg --strip-blobs', async () => {
    expect((await guard.run(ctx('bfg --strip-blobs-bigger-than 100M'))).decision).toBe('block');
  });

  it('blocks git replace', async () => {
    expect((await guard.run(ctx('git replace abc123 def456'))).decision).toBe('block');
  });

  it('blocks git update-ref HEAD', async () => {
    expect((await guard.run(ctx('git update-ref HEAD abc123'))).decision).toBe('block');
  });

  it('blocks git update-ref refs/heads/main', async () => {
    expect((await guard.run(ctx('git update-ref refs/heads/main abc123'))).decision).toBe('block');
  });

  it('allows git status', async () => {
    expect((await guard.run(ctx('git status'))).decision).toBe('allow');
  });

  it('allows git log', async () => {
    expect((await guard.run(ctx('git log --oneline'))).decision).toBe('allow');
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
