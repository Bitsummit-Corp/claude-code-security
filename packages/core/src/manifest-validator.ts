import { z } from 'zod';
import type { HookManifest } from './types.js';

export class ManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ManifestError';
  }
}

const ManifestSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]*$/),
  event: z.enum([
    'PreToolUse',
    'PostToolUse',
    'UserPromptSubmit',
    'SessionStart',
    'SubagentStart',
    'SubagentStop',
  ]),
  matchers: z.array(z.string().min(1)).min(1),
  threat: z.string().regex(/^T-\d{3}-[a-z0-9-]+$/),
  profiles: z.array(z.enum(['baseline', 'strict', 'regulated'])).min(1),
  severity: z.enum(['block', 'warn', 'log']),
  timeout_ms: z.number().int().min(100).max(30000),
});

export function validateManifest(input: unknown): HookManifest {
  const result = ManifestSchema.safeParse(input);
  if (!result.success) {
    const path = result.error.errors[0]?.path.join('.') ?? '<root>';
    const msg = result.error.errors[0]?.message ?? 'unknown';
    throw new ManifestError(`invalid manifest at ${path}: ${msg}`);
  }
  return result.data as HookManifest;
}
