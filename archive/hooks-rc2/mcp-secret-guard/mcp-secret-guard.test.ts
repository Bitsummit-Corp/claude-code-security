import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (tool: string, input: Record<string, unknown>) => ({
  tool, input, env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined, abort: new AbortController().signal,
});

describe('mcp-secret-guard', () => {
  it('manifest matchers includes mcp__*', () => {
    expect(guard.manifest.matchers).toContain('mcp__*');
  });
  it('allows clean MCP tool input', async () => {
    const r = await guard.run(ctx('mcp__server__exec', { query: 'hello' }));
    expect(r.decision).toBe('allow');
  });
  it('blocks MCP tool input containing AWS key', async () => {
    const r = await guard.run(ctx('mcp__server__exec', { token: 'AKIAIOSFODNN7EXAMPLE' }));
    expect(r.decision).toBe('block');
    expect(r.reason).toMatch(/aws_access_key_id/);
  });
  it('blocks nested secret in object payload', async () => {
    const r = await guard.run(ctx('mcp__db__query', {
      headers: { authorization: 'Bearer ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789' },
    }));
    expect(r.decision).toBe('block');
  });
  it('redacts secret in evidence', async () => {
    const r = await guard.run(ctx('mcp__x', { k: 'AKIAIOSFODNN7EXAMPLE' }));
    expect(JSON.stringify(r.evidence)).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });
});
