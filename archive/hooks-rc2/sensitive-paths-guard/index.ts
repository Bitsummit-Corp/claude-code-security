import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const SENSITIVE_PATH_FRAGMENTS = [
  '/.ssh/',
  '/.aws/',
  '/.gnupg/',
  '/.kube/',
  '/.docker/',
  '/.netrc',
  '/.config/gh/hosts.yml',
  '/etc/sudoers',
  '/etc/shadow',
];

function isSensitive(path: string): string | null {
  for (const frag of SENSITIVE_PATH_FRAGMENTS) {
    if (path.includes(frag)) return frag;
  }
  return null;
}

const sensitivePathsGuard: HookModule = {
  manifest: {
    name: 'sensitive-paths-guard',
    event: 'PreToolUse',
    matchers: ['Read', 'Bash'],
    threat: 'T-003-credential-exfil',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    if (ctx.tool === 'Read') {
      const fp = typeof ctx.input.file_path === 'string' ? ctx.input.file_path : '';
      const hit = isSensitive(fp);
      if (hit) return { decision: 'block', reason: `Read on sensitive path: ${hit}`, evidence: { match: hit, path: fp } };
      return { decision: 'allow', reason: 'no sensitive path' };
    }
    if (ctx.tool === 'Bash') {
      const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : '';
      const hit = isSensitive(cmd);
      if (hit) return { decision: 'block', reason: `Bash references sensitive path: ${hit}`, evidence: { match: hit } };
      return { decision: 'allow', reason: 'no sensitive path in command' };
    }
    return { decision: 'allow', reason: 'unhandled tool' };
  },
};

export default sensitivePathsGuard;
