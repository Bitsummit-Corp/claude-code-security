import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const DOTFILE_PATTERNS = [
  /\/\.zshrc$/,
  /\/\.zprofile$/,
  /\/\.bashrc$/,
  /\/\.bash_profile$/,
  /\/\.profile$/,
  /\/\.gitconfig$/,
  /\/\.git\/config$/,
  /\/\.ssh\/config$/,
  /\/\.npmrc$/,
  /\/\.tool-versions$/,
];

function matchDotfile(path: string): RegExp | null {
  for (const re of DOTFILE_PATTERNS) {
    if (re.test(path)) return re;
  }
  return null;
}

const dotfileGuard: HookModule = {
  manifest: {
    name: 'dotfile-guard',
    event: 'PreToolUse',
    matchers: ['Edit', 'Write'],
    threat: 'T-002-destructive-fs',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    if (ctx.tool !== 'Edit' && ctx.tool !== 'Write') {
      return { decision: 'allow', reason: 'unhandled tool' };
    }
    const fp = typeof ctx.input.file_path === 'string' ? ctx.input.file_path : '';
    const hit = matchDotfile(fp);
    if (hit) {
      return { decision: 'block', reason: `dotfile modification: ${fp}`, evidence: { pattern: hit.source, path: fp } };
    }
    return { decision: 'allow', reason: 'not a tracked dotfile' };
  },
};

export default dotfileGuard;
