import { stat } from 'node:fs/promises';
import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

function resolvePath(ctx: HookContext): string {
  const override = ctx.env?.CCSEC_LOCAL_SETTINGS_PATH;
  if (override && override.length > 0) return override;
  return `${ctx.paths.home}/.claude/settings.local.json`;
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw err;
  }
}

const localSettingsPrecedenceChecker: HookModule = {
  manifest: {
    name: 'local-settings-precedence-checker',
    event: 'SessionStart',
    matchers: ['*'],
    threat: 'T-013-settings-precedence',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'warn', regulated: 'block' },
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const path = resolvePath(ctx);
    if (!(await exists(path))) {
      return { decision: 'allow', reason: 'no user-level settings.local.json found' };
    }
    return {
      decision: 'block',
      reason: 'settings.local.json overrides managed policy precedence (severity per profile)',
      evidence: { kind: 'local-settings-present', path },
    };
  },
};

export default localSettingsPrecedenceChecker;
