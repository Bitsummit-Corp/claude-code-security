import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (cmd: string) => ({
  tool: 'Bash', input: { command: cmd }, env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('keychain-guard', () => {
  it('manifest threat is T-001', () => {
    expect(guard.manifest.threat).toBe('T-001-secret-leak');
  });
  it('allows existence check (no value-printing flag)', async () => {
    const r = await guard.run(ctx('security find-generic-password -a default -s API_KEY'));
    expect(r.decision).toBe('allow');
  });
  it('blocks value-printing flag form 1', async () => {
    // The flag that prints raw password value to stdout
    const flag = '-' + 'w';
    const r = await guard.run(ctx(`security find-generic-password -a default -s API_KEY ${flag}`));
    expect(r.decision).toBe('block');
  });
  it('blocks value-printing flag form 2', async () => {
    const flag = '-' + 'g';
    const r = await guard.run(ctx(`security find-generic-password ${flag} -a default -s API_KEY`));
    expect(r.decision).toBe('block');
  });
  it('allows non-keychain commands', async () => {
    const r = await guard.run(ctx('ls -la'));
    expect(r.decision).toBe('allow');
  });
  it('handles non-string command', async () => {
    const r = await guard.run({ ...ctx(''), input: { command: 123 as never } });
    expect(r.decision).toBe('allow');
  });
});
