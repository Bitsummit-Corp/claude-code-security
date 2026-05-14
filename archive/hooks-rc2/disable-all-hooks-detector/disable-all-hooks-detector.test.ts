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

describe('disable-all-hooks-detector', () => {
  let dir: string;
  let settingsPath: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'ccsec-disable-hooks-'));
    settingsPath = join(dir, 'settings.local.json');
  });

  it('manifest is wildcard SessionStart for T-012 with scalar warn severity', () => {
    expect(guard.manifest.name).toBe('disable-all-hooks-detector');
    expect(guard.manifest.event).toBe('SessionStart');
    expect(guard.manifest.matchers).toEqual(['*']);
    expect(guard.manifest.threat).toBe('T-012-mdm-bypass');
    expect(guard.manifest.severity).toBe('warn');
    expect(guard.manifest.profiles).toEqual(['baseline', 'strict', 'regulated']);
    expect(guard.manifest.timeout_ms).toBe(1500);
  });

  it('returns allow when settings.local.json missing', async () => {
    const r = await guard.run(ctx({ CCSEC_LOCAL_SETTINGS_PATH: join(dir, 'never.json') }));
    expect(r.decision).toBe('allow');
  });

  it('returns allow when disableAllHooks is false or missing', async () => {
    await writeFile(settingsPath, JSON.stringify({ permissions: { allow: [] } }));
    const r = await guard.run(ctx({ CCSEC_LOCAL_SETTINGS_PATH: settingsPath }));
    expect(r.decision).toBe('allow');
  });

  it('returns block (downgraded to warn by runner) when disableAllHooks is true', async () => {
    await writeFile(settingsPath, JSON.stringify({ disableAllHooks: true }));
    const r = await guard.run(ctx({ CCSEC_LOCAL_SETTINGS_PATH: settingsPath }));
    expect(r.decision).toBe('block');
    expect(r.evidence?.kind).toBe('hooks-disabled');
    expect(r.evidence?.path).toBe(settingsPath);
  });

  it('returns allow on malformed JSON', async () => {
    await writeFile(settingsPath, '{ not valid json');
    const r = await guard.run(ctx({ CCSEC_LOCAL_SETTINGS_PATH: settingsPath }));
    expect(r.decision).toBe('allow');
  });
});
