import { describe, it, expect, beforeEach } from 'vitest';
import { readFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runHooks } from '@bitsummit/ccsec-core';
import secretGuard from '@bitsummit/ccsec-hooks/dist/secret-guard/index.js';
import secretLeakDetector from '@bitsummit/ccsec-hooks/dist/secret-leak-detector/index.js';
import keychainGuard from '@bitsummit/ccsec-hooks/dist/keychain-guard/index.js';
import mcpSecretGuard from '@bitsummit/ccsec-hooks/dist/mcp-secret-guard/index.js';
import destructiveFsGuard from '@bitsummit/ccsec-hooks/dist/destructive-fs-guard/index.js';
import gitDestructiveGuard from '@bitsummit/ccsec-hooks/dist/git-destructive-guard/index.js';
import sensitivePathsGuard from '@bitsummit/ccsec-hooks/dist/sensitive-paths-guard/index.js';
import dotfileGuard from '@bitsummit/ccsec-hooks/dist/dotfile-guard/index.js';

const ALL_HOOKS = [
  secretGuard, secretLeakDetector, keychainGuard, mcpSecretGuard,
  destructiveFsGuard, gitDestructiveGuard, sensitivePathsGuard, dotfileGuard,
];

const here = dirname(fileURLToPath(import.meta.url));

describe('integration: sensitive-paths-attempt', () => {
  let auditPath: string;
  beforeEach(async () => {
    auditPath = join(await mkdtemp(join(tmpdir(), 'ccsec-int-')), 'audit.jsonl');
  });

  it('replay matches expected', async () => {
    const fx = JSON.parse(await readFile(join(here, 'transcripts', 'sensitive-paths-attempt.json'), 'utf8'));
    for (let i = 0; i < fx.events.length; i++) {
      const ev = fx.events[i];
      const exp = fx.expected[i];
      const result = await runHooks(
        { hooks: ALL_HOOKS, profile: 'baseline', auditLogPath: auditPath },
        { tool: ev.tool, event: ev.event, input: ev.input, response: ev.response },
      );
      expect(result.decision, `event ${i}`).toBe(exp.decision);
      if (exp.blockedBy) expect(result.blockedBy).toBe(exp.blockedBy);
    }
  });
});
