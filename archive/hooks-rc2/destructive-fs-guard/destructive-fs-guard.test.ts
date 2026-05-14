import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (cmd: string) => ({
  tool: 'Bash', input: { command: cmd }, env: {},
  paths: { home: '/Users/x', ssh: '/Users/x/.ssh', aws: '/Users/x/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('destructive-fs-guard', () => {
  it('manifest threat is T-002', () => {
    expect(guard.manifest.threat).toBe('T-002-destructive-fs');
  });
  it('blocks rm -rf on root', async () => {
    expect((await guard.run(ctx('rm -rf /'))).decision).toBe('block');
  });
  it('blocks rm -rf on root glob', async () => {
    expect((await guard.run(ctx('rm -rf /*'))).decision).toBe('block');
  });
  it('blocks rm -rf on HOME', async () => {
    expect((await guard.run(ctx('rm -rf /Users/x'))).decision).toBe('block');
    expect((await guard.run(ctx('rm -rf $HOME'))).decision).toBe('block');
    expect((await guard.run(ctx('rm -rf ~'))).decision).toBe('block');
  });
  it('blocks mkfs', async () => {
    expect((await guard.run(ctx('mkfs.ext4 /dev/sda'))).decision).toBe('block');
  });
  it('blocks dd writing to a device', async () => {
    expect((await guard.run(ctx('dd if=/dev/zero of=/dev/sda bs=1M'))).decision).toBe('block');
  });
  it('blocks shred -u', async () => {
    expect((await guard.run(ctx('shred -u /etc/passwd'))).decision).toBe('block');
  });
  it('allows safe rm -rf inside /tmp', async () => {
    expect((await guard.run(ctx('rm -rf /tmp/scratch'))).decision).toBe('allow');
  });
  it('allows benign commands', async () => {
    expect((await guard.run(ctx('ls -la'))).decision).toBe('allow');
  });
  it('handles non-string command', async () => {
    expect((await guard.run({ ...ctx(''), input: { command: 123 as never } })).decision).toBe('allow');
  });
});
