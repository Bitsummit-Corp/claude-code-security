import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (tool: string, file_path: string) => ({
  tool, input: { file_path }, env: {},
  paths: { home: '/Users/x', ssh: '/Users/x/.ssh', aws: '/Users/x/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('dotfile-guard', () => {
  it('manifest declares per-profile severity', () => {
    const sev = guard.manifest.severity as Record<string, string>;
    expect(sev.baseline).toBe('warn');
    expect(sev.strict).toBe('block');
  });
  it('flags Edit on .zshrc', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/.zshrc'))).decision).toBe('block');
  });
  it('flags Edit on .bashrc', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/.bashrc'))).decision).toBe('block');
  });
  it('flags Edit on .gitconfig', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/.gitconfig'))).decision).toBe('block');
  });
  it('flags Edit on .ssh/config', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/.ssh/config'))).decision).toBe('block');
  });
  it('flags Write on .profile', async () => {
    expect((await guard.run(ctx('Write', '/Users/x/.profile'))).decision).toBe('block');
  });
  it('allows Edit on regular file', async () => {
    expect((await guard.run(ctx('Edit', '/Users/x/code/foo.ts'))).decision).toBe('allow');
  });
  it('allows Read of dotfile (only Edit/Write are matched)', async () => {
    // Note: Read is not in the matchers; runner skips this hook for Read.
    // Test exercises the run() function directly with tool='Read' to verify the hook tolerates it.
    expect((await guard.run(ctx('Read', '/Users/x/.zshrc'))).decision).toBe('allow');
  });
});
