import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import type { TargetOS } from '@bitsummit/ccsec-core';
import { compileProfile } from '../compiler.js';

export interface ApplyCommandArgs {
  settingsRoot: string;
  profile: 'baseline' | 'strict' | 'regulated';
  claudeDir: string;
  os: TargetOS;
  env?: Readonly<Record<string, string>>;
  dryRun: boolean;
  force?: boolean;
  installRules?: boolean;
  rulesRoot?: string;
}

interface Lockfile { profile: string; ccsec_version: string; applied_at: string; settings_sha256: string; }
const VERSION = '0.9.0-rc.2';
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

const DEFAULT_RULES_ROOT = fileURLToPath(new URL('../../../rules/templates', import.meta.url));

async function pathExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw e;
  }
}

export async function applyCommand(args: ApplyCommandArgs): Promise<{ wrote: boolean; rulesInstalled?: boolean }> {
  const compiled = await compileProfile({
    settingsRoot: args.settingsRoot,
    profile: args.profile,
    os: args.os,
    ...(args.env !== undefined ? { env: args.env } : {}),
    stripThreatField: false,
  });
  const settingsPath = join(args.claudeDir, 'settings.json');
  const lockPath = join(args.claudeDir, '.ccsec-lock.json');

  if (!args.force) {
    try {
      const lock = JSON.parse(await readFile(lockPath, 'utf8')) as Lockfile;
      const existing = await readFile(settingsPath, 'utf8');
      if (sha256(existing) !== lock.settings_sha256) {
        throw new Error(`existing ${settingsPath} has been modified since last apply; refusing to clobber.`);
      }
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
  }

  if (args.dryRun) return { wrote: false };

  await mkdir(args.claudeDir, { recursive: true });
  const body = JSON.stringify(compiled, null, 2) + '\n';
  await writeFile(settingsPath, body, 'utf8');
  const lock: Lockfile = { profile: args.profile, ccsec_version: VERSION, applied_at: new Date().toISOString(), settings_sha256: sha256(body) };
  await writeFile(lockPath, JSON.stringify(lock, null, 2) + '\n', 'utf8');

  let rulesInstalled = false;
  if (args.installRules) {
    const rulesRoot = args.rulesRoot ?? DEFAULT_RULES_ROOT;
    const claudeMdPath = join(args.claudeDir, 'CLAUDE.md');
    if (!(await pathExists(claudeMdPath))) {
      const templatePath = join(rulesRoot, `${args.profile}.md`);
      const template = await readFile(templatePath, 'utf8');
      await writeFile(claudeMdPath, template, 'utf8');
      rulesInstalled = true;
    }
  }

  return { wrote: true, rulesInstalled };
}
