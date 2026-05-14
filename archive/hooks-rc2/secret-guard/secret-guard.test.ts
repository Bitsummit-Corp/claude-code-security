import { describe, it, expect } from 'vitest';
import secretGuard from './index.js';

const ctx = (input: Record<string, unknown>) => ({
  tool: 'Bash', input, env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('secret-guard hook', () => {
  it('declares a valid manifest', () => {
    expect(secretGuard.manifest.name).toBe('secret-guard');
    expect(secretGuard.manifest.threat).toMatch(/^T-001-/);
  });
  it('allows benign Bash commands', async () => {
    expect((await secretGuard.run(ctx({ command: 'ls -la' }))).decision).toBe('allow');
  });
  it('blocks AWS key in command', async () => {
    const r = await secretGuard.run(ctx({ command: 'echo AKIAIOSFODNN7EXAMPLE' }));
    expect(r.decision).toBe('block');
    expect(r.reason).toMatch(/aws_access_key_id/);
  });
  it('blocks GitHub PAT', async () => {
    const r = await secretGuard.run(ctx({ command: 'curl -H "Authorization: token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"' }));
    expect(r.decision).toBe('block');
  });
  it('redacts secret in evidence', async () => {
    const r = await secretGuard.run(ctx({ command: 'echo AKIAIOSFODNN7EXAMPLE' }));
    expect(JSON.stringify(r.evidence)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(JSON.stringify(r.evidence)).toContain('AKIA');
  });
  it('blocks env-dump of secret-bearing variable', async () => {
    const r = await secretGuard.run(ctx({ command: 'printenv AWS_SECRET_ACCESS_KEY' }));
    expect(r.decision).toBe('block');
  });
  it('blocks bare env command (full environment dump)', async () => {
    const r = await secretGuard.run(ctx({ command: 'env' }));
    expect(r.decision).toBe('block');
    expect(r.reason).toMatch(/env-dump/);
  });
  it('blocks bare printenv command', async () => {
    const r = await secretGuard.run(ctx({ command: 'printenv' }));
    expect(r.decision).toBe('block');
  });
  it('handles non-string input gracefully', async () => {
    expect((await secretGuard.run(ctx({ command: 12345 as never }))).decision).toBe('allow');
  });
});
