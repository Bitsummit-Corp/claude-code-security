import { describe, it, expect } from 'vitest';
import guard from './index.js';

const ctx = (input: Record<string, unknown>, env: Record<string, string> = {}) => ({
  tool: 'SubagentStart',
  input,
  env,
  paths: { home: '/h', ssh: '/h/.ssh', aws: '/h/.aws', tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('subagent-spawn-guard', () => {
  it('manifest is wildcard SubagentStart for T-011 with per-profile severity', () => {
    expect(guard.manifest.name).toBe('subagent-spawn-guard');
    expect(guard.manifest.event).toBe('SubagentStart');
    expect(guard.manifest.matchers).toEqual(['*']);
    expect(guard.manifest.threat).toBe('T-011-subagent-escape');
    const sev = guard.manifest.severity as Record<string, string>;
    expect(sev.baseline).toBe('warn');
    expect(sev.strict).toBe('block');
    expect(sev.regulated).toBe('block');
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(1500);
  });

  it('allows when subagent_type is missing', async () => {
    const r = await guard.run(ctx({}, { CCSEC_AGENT_ALLOWLIST: 'reviewer,planner' }));
    expect(r.decision).toBe('allow');
  });

  it('allows when subagent_type is in allowlist', async () => {
    const r = await guard.run(
      ctx({ subagent_type: 'reviewer' }, { CCSEC_AGENT_ALLOWLIST: 'reviewer,planner' }),
    );
    expect(r.decision).toBe('allow');
    expect(r.evidence?.kind).toBe('allowlisted');
  });

  it('blocks when subagent_type is not in allowlist', async () => {
    const r = await guard.run(
      ctx({ subagent_type: 'rogue-agent' }, { CCSEC_AGENT_ALLOWLIST: 'reviewer,planner' }),
    );
    expect(r.decision).toBe('block');
    expect(r.evidence?.kind).toBe('not-allowlisted');
    expect(r.evidence?.subagent_type).toBe('rogue-agent');
  });

  it('blocks when allowlist is empty', async () => {
    const r = await guard.run(ctx({ subagent_type: 'reviewer' }, { CCSEC_AGENT_ALLOWLIST: '' }));
    expect(r.decision).toBe('block');
  });
});
