import type { HookEvent, HookModule, HookProfile } from './types.js';
import { AuditLogger } from './audit-logger.js';

export interface RunInput {
  tool: string;
  input: Record<string, unknown>;
  event: HookEvent;
  env?: Readonly<Record<string, string>>;
}
export interface RunOptions {
  hooks: HookModule[];
  profile: HookProfile;
  auditLogPath: string;
  defaultTimeoutMs?: number;
}
export interface HookInvocation {
  hook: string;
  outcome: 'allow' | 'block' | 'warn' | 'timeout' | 'error';
  reason: string;
  duration_ms: number;
}
export interface RunResult {
  decision: 'allow' | 'block' | 'warn';
  blockedBy?: string;
  invocations: HookInvocation[];
}

export async function runHooks(opts: RunOptions, run: RunInput): Promise<RunResult> {
  const logger = new AuditLogger(opts.auditLogPath);
  const invocations: HookInvocation[] = [];
  let aggregate: 'allow' | 'block' | 'warn' = 'allow';
  let blockedBy: string | undefined;

  for (const hook of opts.hooks) {
    if (hook.manifest.event !== run.event) continue;
    if (!hook.manifest.matchers.includes(run.tool)) continue;
    if (!hook.manifest.profiles.includes(opts.profile)) continue;

    const start = Date.now();
    const controller = new AbortController();
    const timeoutMs = hook.manifest.timeout_ms ?? opts.defaultTimeoutMs ?? 1500;
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let outcome: HookInvocation['outcome'] = 'allow';
    let reason = '';

    try {
      const decision = await Promise.race([
        hook.run({
          tool: run.tool,
          input: run.input,
          env: run.env ?? {},
          paths: { home: process.env.HOME ?? '', ssh: `${process.env.HOME}/.ssh`, aws: `${process.env.HOME}/.aws`, tmp: '/tmp' },
          log: () => undefined,
          abort: controller.signal,
        }),
        new Promise<never>((_, reject) => {
          controller.signal.addEventListener('abort', () => reject(new Error('aborted')));
        }),
      ]);
      outcome = decision.decision;
      reason = decision.reason;
    } catch (e) {
      outcome = controller.signal.aborted ? 'timeout' : 'error';
      reason = (e as Error).message;
    } finally {
      clearTimeout(timer);
    }

    const duration_ms = Date.now() - start;
    invocations.push({ hook: hook.manifest.name, outcome, reason, duration_ms });
    await logger.write({ hook: hook.manifest.name, tool: run.tool, decision: outcome, reason, duration_ms });

    if (outcome === 'block' && aggregate !== 'block') {
      aggregate = 'block';
      blockedBy = hook.manifest.name;
    } else if (outcome === 'warn' && aggregate === 'allow') {
      aggregate = 'warn';
    }
  }
  return { decision: aggregate, ...(blockedBy ? { blockedBy } : {}), invocations };
}
