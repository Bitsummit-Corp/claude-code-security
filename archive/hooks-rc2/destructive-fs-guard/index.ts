import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const RM_RF_ROOT_RE = /\brm\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+(?:\/(?:\s|$|\*)|\/\*)/;
const RM_RF_HOME_RE = /\brm\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+(?:~|\$HOME|\$\{HOME\})(?:\s|$|\/)/;
const MKFS_RE = /\bmkfs(?:\.[a-z0-9]+)?\b/;
const DD_DEVICE_RE = /\bdd\s+.*\bof=\/dev\//;
const SHRED_U_RE = /\bshred\s+(?:-[a-zA-Z]*u[a-zA-Z]*\s+|--remove\s+)/;

interface Match { kind: string; pattern: RegExp; }
const PATTERNS: Match[] = [
  { kind: 'rm-rf-root', pattern: RM_RF_ROOT_RE },
  { kind: 'rm-rf-home', pattern: RM_RF_HOME_RE },
  { kind: 'mkfs', pattern: MKFS_RE },
  { kind: 'dd-to-device', pattern: DD_DEVICE_RE },
  { kind: 'shred-unlink', pattern: SHRED_U_RE },
];

function homeRmRf(cmd: string, homePath: string): boolean {
  const re = new RegExp(`\\brm\\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\\s+)+${homePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\s|$|/)`);
  return re.test(cmd);
}

const destructiveFsGuard: HookModule = {
  manifest: {
    name: 'destructive-fs-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-002-destructive-fs',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd) return { decision: 'allow', reason: 'no command field' };

    for (const { kind, pattern } of PATTERNS) {
      if (pattern.test(cmd)) {
        return { decision: 'block', reason: `destructive pattern: ${kind}`, evidence: { kind } };
      }
    }
    if (ctx.paths.home && homeRmRf(cmd, ctx.paths.home)) {
      return { decision: 'block', reason: 'destructive pattern: rm-rf-home-literal', evidence: { kind: 'rm-rf-home-literal' } };
    }
    return { decision: 'allow', reason: 'no destructive pattern matched' };
  },
};

export default destructiveFsGuard;
