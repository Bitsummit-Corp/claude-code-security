import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (tool: string, input: Record<string, unknown>) => ({
  tool, input, env: {},
  paths: { home: '/Users/x', ssh: '/Users/x/.ssh', aws: '/Users/x/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('sensitive-paths-guard', () => {
  it('manifest threat is T-003', () => {
    expect(guard.manifest.threat).toBe('T-003-credential-exfil');
  });
  it('blocks Read on .ssh subpaths', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/.ssh/id_rsa' }))).decision).toBe('block');
  });
  it('blocks Read on .aws/credentials', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/.aws/credentials' }))).decision).toBe('block');
  });
  it('blocks Read on .kube/config', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/.kube/config' }))).decision).toBe('block');
  });
  it('blocks Read on .netrc', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/.netrc' }))).decision).toBe('block');
  });
  it('blocks Read on /etc/sudoers', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/etc/sudoers' }))).decision).toBe('block');
  });
  it('blocks Bash cat of credential file', async () => {
    expect((await guard.run(ctx('Bash', { command: 'cat /Users/x/.ssh/id_rsa' }))).decision).toBe('block');
  });
  it('allows Read on benign path', async () => {
    expect((await guard.run(ctx('Read', { file_path: '/Users/x/code/foo.ts' }))).decision).toBe('allow');
  });
  it('allows Bash that does not target credential paths', async () => {
    expect((await guard.run(ctx('Bash', { command: 'ls /Users/x/code' }))).decision).toBe('allow');
  });
});
