import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const PIPE_TO_SHELL_RE = /\|\s*(?:sh|bash|zsh|fish|ksh)\b/;

const pipeToShellGuard: HookModule = {
  manifest: {
    name: 'pipe-to-shell-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-006-pipe-to-shell',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd) return { decision: 'allow', reason: 'no command field' };
    if (PIPE_TO_SHELL_RE.test(cmd)) {
      return {
        decision: 'block',
        reason: 'piping output into a shell interpreter (sh/bash/zsh/fish/ksh)',
        evidence: { kind: 'pipe_to_shell' },
      };
    }
    return { decision: 'allow', reason: 'no pipe-to-shell pattern' };
  },
};

export default pipeToShellGuard;
