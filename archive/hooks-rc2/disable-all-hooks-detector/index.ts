import { readFile } from 'node:fs/promises';
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

function resolvePath(ctx: HookContext): string {
  const override = ctx.env?.CCSEC_LOCAL_SETTINGS_PATH;
  if (override && override.length > 0) return override;
  return `${ctx.paths.home}/.claude/settings.local.json`;
}

const disableAllHooksDetector: HookModule = {
  manifest: {
    name: 'disable-all-hooks-detector',
    event: 'SessionStart',
    matchers: ['*'],
    threat: 'T-012-mdm-bypass',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'warn',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const path = resolvePath(ctx);
    let raw: string;
    try {
      raw = await readFile(path, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return { decision: 'allow', reason: 'no settings.local.json present' };
      }
      throw err;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return {
        decision: 'allow',
        reason: 'settings.local.json could not be parsed; skipping check',
        evidence: { kind: 'parse-error', path },
      };
    }
    const flag = (parsed as { disableAllHooks?: unknown } | null)?.disableAllHooks;
    if (flag === true) {
      return {
        decision: 'block',
        reason: 'settings.local.json sets disableAllHooks=true (downgraded to warn by runner)',
        evidence: { kind: 'hooks-disabled', path },
      };
    }
    return {
      decision: 'allow',
      reason: 'disableAllHooks not set in settings.local.json',
      evidence: { kind: 'hooks-enabled', path },
    };
  },
};

export default disableAllHooksDetector;
