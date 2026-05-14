import { describe, it, expect } from 'vitest';
import detector from './index.js';

const ctx = (response: Record<string, unknown>) => ({
  tool: 'Bash',
  input: { command: 'cat /tmp/foo' },
  response,
  env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('secret-leak-detector', () => {
  it('declares a valid PostToolUse manifest', () => {
    expect(detector.manifest.event).toBe('PostToolUse');
    expect(detector.manifest.threat).toBe('T-001-secret-leak');
  });
  it('allows clean stdout', async () => {
    const r = await detector.run(ctx({ stdout: 'hello world' }));
    expect(r.decision).toBe('allow');
  });
  it('blocks AWS key in stdout', async () => {
    const r = await detector.run(ctx({ stdout: 'AKIAIOSFODNN7EXAMPLE leaked' }));
    expect(r.decision).toBe('block');
    expect(r.reason).toMatch(/aws_access_key_id/);
  });
  it('blocks PEM key in stderr', async () => {
    const r = await detector.run(ctx({ stderr: '-----BEGIN RSA PRIVATE KEY-----' }));
    expect(r.decision).toBe('block');
  });
  it('redacts the secret in evidence', async () => {
    const r = await detector.run(ctx({ stdout: 'AKIAIOSFODNN7EXAMPLE' }));
    expect(JSON.stringify(r.evidence)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(JSON.stringify(r.evidence)).toContain('AKIA');
  });
  it('handles missing response gracefully', async () => {
    const r = await detector.run({ ...ctx({}), response: undefined });
    expect(r.decision).toBe('allow');
  });
  it('truncates very large responses to 256KB before scanning', async () => {
    const huge = 'a'.repeat(300_000) + ' AKIAIOSFODNN7EXAMPLE';
    const r = await detector.run(ctx({ stdout: huge }));
    expect(r.decision).toBe('allow');
    expect(r.reason).toMatch(/truncated/);
  });
});
