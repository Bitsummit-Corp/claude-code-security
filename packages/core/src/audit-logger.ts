import { appendFile, readFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';

export interface AuditInput {
  hook: string;
  tool: string;
  decision: string;
  reason: string;
  duration_ms: number;
  evidence_digest?: string;
  _ts?: string;
}

export interface AuditRecord extends AuditInput {
  ts: string;
  prev_hash?: string;
  hash: string;
}

function hashRecord(record: Omit<AuditRecord, 'hash'>): string {
  return createHash('sha256').update(JSON.stringify(record)).digest('hex');
}

export class AuditLogger {
  private prevHash: string | undefined;
  private pending: Promise<void> = Promise.resolve();
  constructor(private readonly path: string) {}

  async write(input: AuditInput): Promise<void> {
    const next = this.pending.then(() => this.appendRecord(input));
    // Keep the queue alive even if one write rejects so subsequent writes
    // can still proceed; the rejection itself is forwarded to its caller.
    this.pending = next.catch(() => undefined);
    return next;
  }

  private async appendRecord(input: AuditInput): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    if (this.prevHash === undefined) this.prevHash = await this.loadLastHash();
    const ts = input._ts ?? new Date().toISOString();
    const { _ts, ...rest } = input;
    const base: Omit<AuditRecord, 'hash'> = {
      ...rest,
      ts,
      ...(this.prevHash !== undefined ? { prev_hash: this.prevHash } : {}),
    };
    const hash = hashRecord(base);
    this.prevHash = hash;
    await appendFile(this.path, JSON.stringify({ ...base, hash }) + '\n', 'utf8');
  }

  private async loadLastHash(): Promise<string | undefined> {
    let raw: string;
    try {
      raw = await readFile(this.path, 'utf8');
    } catch {
      return undefined;
    }
    const lines = raw.trim().split('\n').filter(Boolean);
    const last = lines[lines.length - 1];
    if (!last) return undefined;
    try {
      return JSON.parse(last).hash;
    } catch (err) {
      // Surface corruption rather than silently starting a fresh chain.
      console.warn(
        `[ccsec-audit-logger] last line of ${this.path} failed to parse; starting new chain. ${
          (err as Error).message
        }`,
      );
      return undefined;
    }
  }

  static async verify(
    path: string,
  ): Promise<{ ok: boolean; records: number; brokenAt?: number; reason?: string }> {
    let raw: string;
    try {
      raw = await readFile(path, 'utf8');
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === 'ENOENT') return { ok: true, records: 0 };
      throw err;
    }
    const lines = raw.trim().split('\n').filter(Boolean);
    let prev: string | undefined;
    for (let i = 0; i < lines.length; i++) {
      let r: AuditRecord;
      try {
        r = JSON.parse(lines[i]!) as AuditRecord;
      } catch {
        return { ok: false, records: lines.length, brokenAt: i, reason: 'invalid-json' };
      }
      if (r.prev_hash !== prev) {
        return { ok: false, records: lines.length, brokenAt: i, reason: 'prev-hash-mismatch' };
      }
      const { hash, ...rest } = r;
      if (hashRecord(rest) !== hash) {
        return { ok: false, records: lines.length, brokenAt: i, reason: 'hash-mismatch' };
      }
      prev = hash;
    }
    return { ok: true, records: lines.length };
  }
}
