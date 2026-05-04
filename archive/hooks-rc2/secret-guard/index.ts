import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';
import { detectSecrets } from '@bitsummit/ccsec-core';

const ENV_DUMP_RE = /\b(?:printenv|env)\b(?:\s+([A-Z_][A-Z0-9_]*))?/;
const SECRET_ENV_NAMES = /(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL)/;
const ECHO_VAR_RE = /\becho\s+["']?\$\{?([A-Z_][A-Z0-9_]*)/;

const secretGuard: HookModule = {
  manifest: {
    name: 'secret-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const command = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!command) return { decision: 'allow', reason: 'no command field' };

    const hits = detectSecrets(command);
    if (hits.length > 0) {
      return {
        decision: 'block',
        reason: `secret literal in command: ${hits.map(h => h.label).join(', ')}`,
        evidence: { hits: hits.map(h => ({ label: h.label, redacted: h.redacted })) },
      };
    }

    const envDump = command.match(ENV_DUMP_RE);
    if (envDump) {
      const target = envDump[1] ?? '';
      if (!target || SECRET_ENV_NAMES.test(target)) {
        return { decision: 'block', reason: `env-dump of secret variable: ${target || '(all)'}`, evidence: { kind: 'env-dump', target } };
      }
    }

    const echoVar = command.match(ECHO_VAR_RE);
    if (echoVar && SECRET_ENV_NAMES.test(echoVar[1] ?? '')) {
      return { decision: 'block', reason: `echo of secret variable: ${echoVar[1]}`, evidence: { kind: 'secret-env', target: echoVar[1] } };
    }

    return { decision: 'allow', reason: 'no secret patterns detected' };
  },
};

export default secretGuard;
