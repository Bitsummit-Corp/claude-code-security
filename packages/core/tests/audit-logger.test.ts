import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLogger } from '../src/audit-logger.js';

describe('AuditLogger', () => {
  let path: string;
  beforeEach(async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ccsec-audit-'));
    path = join(dir, 'audit.jsonl');
  });

  it('appends one JSONL record per write', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'block', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'b', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    expect(lines).toHaveLength(2);
  });

  it('chains records via hash + prev_hash', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'b', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    const r1 = JSON.parse(lines[0]!), r2 = JSON.parse(lines[1]!);
    expect(r2.prev_hash).toBe(r1.hash);
    expect(r1.prev_hash).toBeUndefined();
  });

  it('verifies an intact log', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'b', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    expect(await AuditLogger.verify(path)).toEqual({ ok: true, records: 2 });
  });

  it('detects tampering on verify', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    await logger.write({ hook: 'b', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const tampered = (await readFile(path, 'utf8')).replace('"reason":"r"', '"reason":"X"');
    await writeFile(path, tampered);
    expect((await AuditLogger.verify(path)).ok).toBe(false);
  });

  it('serializes concurrent writes', async () => {
    const logger = new AuditLogger(path);
    await Promise.all(
      [0, 1, 2, 3, 4].map((i) =>
        logger.write({
          hook: `h${i}`,
          tool: 'Bash',
          decision: 'allow',
          reason: `r${i}`,
          duration_ms: 1,
        }),
      ),
    );
    const result = await AuditLogger.verify(path);
    expect(result).toEqual({ ok: true, records: 5 });
  });

  it('concurrent writes never produce duplicate prev_hash', async () => {
    const logger = new AuditLogger(path);
    await Promise.all(
      [0, 1, 2, 3, 4].map((i) =>
        logger.write({
          hook: `h${i}`,
          tool: 'Bash',
          decision: 'allow',
          reason: `r${i}`,
          duration_ms: 1,
        }),
      ),
    );
    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    const prevHashes = lines
      .map((l) => JSON.parse(l).prev_hash)
      .filter((h: unknown): h is string => typeof h === 'string');
    expect(new Set(prevHashes).size).toBe(prevHashes.length);
    expect(prevHashes.length).toBe(4); // 5 records => 4 prev_hash links
  });

  it('verify on missing file returns ok:true records:0', async () => {
    const missing = join(path, '..', 'no-such-file.jsonl');
    await expect(AuditLogger.verify(missing)).resolves.toEqual({ ok: true, records: 0 });
  });

  it('verify on invalid JSON line returns ok:false with brokenAt', async () => {
    const logger = new AuditLogger(path);
    await logger.write({ hook: 'a', tool: 'Bash', decision: 'allow', reason: 'r', duration_ms: 1 });
    const original = await readFile(path, 'utf8');
    await writeFile(path, original + '{ this is not valid json\n');
    const result = await AuditLogger.verify(path);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(1);
  });
});
