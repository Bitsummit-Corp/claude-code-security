import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const GITMODULES_PATH_RE = /\.gitmodules$/;
const SUBMODULE_ADD_UPDATE_RE = /\bgit\s+submodule\s+(?:add|update)\b/;

const submoduleInjectionGuard: HookModule = {
  manifest: {
    name: 'submodule-injection-guard',
    event: 'PreToolUse',
    matchers: ['Edit', 'Write', 'Bash'],
    threat: 'T-005-supply-chain-submodule',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    if (ctx.tool === 'Edit' || ctx.tool === 'Write') {
      const filePath = typeof ctx.input.file_path === 'string' ? ctx.input.file_path : null;
      if (filePath && GITMODULES_PATH_RE.test(filePath)) {
        return {
          decision: 'block',
          reason: 'modifying .gitmodules can introduce malicious submodules into the supply chain',
          evidence: { kind: 'gitmodules-edit', file_path: filePath },
        };
      }
      return { decision: 'allow', reason: 'edit/write does not touch .gitmodules' };
    }

    if (ctx.tool === 'Bash') {
      const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
      if (!cmd) return { decision: 'allow', reason: 'no command field' };
      if (SUBMODULE_ADD_UPDATE_RE.test(cmd)) {
        return {
          decision: 'block',
          reason: 'git submodule add/update can pull arbitrary external code into the working tree',
          evidence: { kind: 'submodule-add-update' },
        };
      }
      return { decision: 'allow', reason: 'no submodule add/update' };
    }

    return { decision: 'allow', reason: 'unmatched tool' };
  },
};

export default submoduleInjectionGuard;
