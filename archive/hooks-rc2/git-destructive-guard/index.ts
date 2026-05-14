import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const RESET_HARD_RE = /\bgit\s+reset\s+--hard\b/;
const CLEAN_FD_RE = /\bgit\s+clean\s+(?:-[a-zA-Z]*[fd][a-zA-Z]*\b|--force\b)/;
const PUSH_FORCE_RE = /\bgit\s+push\s+(?:.*\s)?(?:--force\b|-f\b|--force-with-lease\b)/;
const BRANCH_DELETE_PROTECTED_RE = /\bgit\s+branch\s+-D\s+(main|master|release|develop|prod|production)\b/;
const REBASE_INTERACTIVE_RE = /\bgit\s+rebase\s+(?:-i\b|--interactive\b)/;

interface Match { kind: string; pattern: RegExp; }
const PATTERNS: Match[] = [
  { kind: 'reset-hard', pattern: RESET_HARD_RE },
  { kind: 'clean-fd', pattern: CLEAN_FD_RE },
  { kind: 'push-force', pattern: PUSH_FORCE_RE },
  { kind: 'branch-delete-protected', pattern: BRANCH_DELETE_PROTECTED_RE },
  { kind: 'rebase-interactive', pattern: REBASE_INTERACTIVE_RE },
];

const gitDestructiveGuard: HookModule = {
  manifest: {
    name: 'git-destructive-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-004-branch-sabotage',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd) return { decision: 'allow', reason: 'no command field' };
    for (const { kind, pattern } of PATTERNS) {
      if (pattern.test(cmd)) {
        return { decision: 'block', reason: `git destructive pattern: ${kind}`, evidence: { kind } };
      }
    }
    return { decision: 'allow', reason: 'no destructive git pattern matched' };
  },
};

export default gitDestructiveGuard;
