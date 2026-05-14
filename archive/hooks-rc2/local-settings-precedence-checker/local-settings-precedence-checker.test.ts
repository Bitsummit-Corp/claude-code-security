import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import guard from './index.js';

const ctx = (env: Record<string, string>, home = '/nonexistent') => ({
  tool: 'SessionStart',
  input: {},
  env,
  paths: { home, ssh: `${home}/.ssh`, aws: `${home}/.aws`, tmp: '/tmp' },
  log: () => undefined,
  abort: new AbortController().signal,
});

describe('local-settings-precedence-checker', () => {
  let dir: string;
  let settingsPath: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'ccsec-precedence-'));
    settingsPath = join(dir, 'settings.local.json');
  });

  it('manifest is wildcard SessionStart for T-013-settings-precedence with per-profile severity', () => {
    expect(guard.manifest.name).toBe('local-settings-precedence-checker');
    expect(guard.manifest.event).toBe('SessionStart');
    expect(guard.manifest.matchers).toEqual(['*']);
    expect(guard.manifest.threat).toBe('T-013-settings-precedence');
    const sev = guard.manifest.severity as Record<string, string>;
    expect(sev.baseline).toBe('warn');
    expect(sev.strict).toBe('warn');
    expect(sev.regulated).toBe('block');
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(1500);
  });

  it('returns allow when settings.local.json missing', async () => {
    const r = await guard.run(ctx({ CCSEC_LOCAL_SETTINGS_PATH: join(dir, 'never.json') }));
    expect(r.decision).toBe('allow');
  });

  it('returns block (severity-mapped) when settings.local.json exists', async () => {
    await writeFile(settingsPath, JSON.stringify({ permissions: { allow: ['Bash(*)'] } }));
    const r = await guard.run(ctx({ CCSEC_LOCAL_SETTINGS_PATH: settingsPath }));
    expect(r.decision).toBe('block');
    expect(r.evidence?.kind).toBe('local-settings-present');
    expect(r.evidence?.path).toBe(settingsPath);
  });

  it('falls back to ${home}/.claude/settings.local.json when env override is unset', async () => {
    // home points at tmp dir with no .claude/ subdir. Should be treated as missing.
    const r = await guard.run(ctx({}, dir));
    expect(r.decision).toBe('allow');
  });
});
