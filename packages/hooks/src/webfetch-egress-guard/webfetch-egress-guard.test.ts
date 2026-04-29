import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (input: Record<string, unknown>) => ({
  tool: 'WebFetch',
  input,
  env: {},
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('webfetch-egress-guard', () => {
  it('manifest declares scalar block severity for T-005 on WebFetch', () => {
    expect(guard.manifest.name).toBe('webfetch-egress-guard');
    expect(guard.manifest.event).toBe('PreToolUse');
    expect(guard.manifest.matchers).toEqual(['WebFetch']);
    expect(guard.manifest.threat).toBe('T-005-network-exfil');
    expect(guard.manifest.severity).toBe('block');
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(1500);
  });

  it('allows fetches to allowlisted hosts (docs.anthropic.com)', async () => {
    const r = await guard.run(ctx({ url: 'https://docs.anthropic.com/en/docs/claude-code' }));
    expect(r.decision).toBe('allow');
  });

  it('allows github.com paths', async () => {
    const r = await guard.run(ctx({ url: 'https://github.com/anthropics/anthropic-sdk' }));
    expect(r.decision).toBe('allow');
  });

  it('blocks non-allowlisted hosts', async () => {
    const r = await guard.run(ctx({ url: 'https://evil.example.com/payload' }));
    expect(r.decision).toBe('block');
  });

  it('blocks IP-literal hosts', async () => {
    const r = await guard.run(ctx({ url: 'https://1.2.3.4/x' }));
    expect(r.decision).toBe('block');
  });

  it('blocks bracketed IPv6 literal hosts', async () => {
    const r = await guard.run(ctx({ url: 'https://[2001:db8::1]/x' }));
    expect(r.decision).toBe('block');
  });

  it('blocks DoH hosts even though they are public', async () => {
    const r = await guard.run(ctx({ url: 'https://cloudflare-dns.com/dns-query?name=evil.com' }));
    expect(r.decision).toBe('block');
  });

  it('blocks malformed URLs as suspicious', async () => {
    const r = await guard.run(ctx({ url: 'not-a-url' }));
    expect(r.decision).toBe('block');
  });

  it('allows when url field is missing or non-string', async () => {
    const r = await guard.run(ctx({ url: 123 }));
    expect(r.decision).toBe('allow');
  });
});
