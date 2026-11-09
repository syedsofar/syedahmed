import { sha256 } from './crypto';
import { getDb, persist } from './store';
import type { AuditEntry } from '../shared/types';

interface Actor { id: string; username: string }

function hashOf(e: Omit<AuditEntry, 'hash'>) {
  const ordered = [e.seq, e.at, e.userId, e.username, e.action, e.projectId ?? '', e.target ?? '', e.detail ?? '', e.ip ?? '', e.prevHash];
  return sha256(JSON.stringify(ordered));
}

/** Append-only, hash-chained audit trail. Each entry commits to the previous entry's hash. */
export function audit(
  actor: Actor | null,
  action: string,
  opts: { projectId?: string; target?: string; detail?: string; ip?: string } = {},
) {
  const db = getDb();
  const prev = db.audit[db.audit.length - 1];
  const base: Omit<AuditEntry, 'hash'> = {
    seq: (prev?.seq ?? 0) + 1,
    at: new Date().toISOString(),
    userId: actor?.id ?? 'anonymous',
    username: actor?.username ?? 'anonymous',
    action,
    projectId: opts.projectId,
    target: opts.target,
    detail: opts.detail?.slice(0, 500),
    ip: opts.ip,
    prevHash: prev?.hash ?? 'GENESIS',
  };
  const entry: AuditEntry = { ...base, hash: hashOf(base) };
  db.audit.push(entry);
  persist();
  return entry;
}

export function verifyChain(): { ok: boolean; checked: number; brokenAt?: number } {
  const list = getDb().audit;
  let prevHash = 'GENESIS';
  for (const e of list) {
    const { hash, ...base } = e;
    if (e.prevHash !== prevHash || hashOf(base) !== hash) return { ok: false, checked: list.length, brokenAt: e.seq };
    prevHash = hash;
  }
  return { ok: true, checked: list.length };
}
