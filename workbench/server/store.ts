import fs from 'node:fs';
import path from 'node:path';
import { config } from './config';
import { decrypt, encrypt } from './crypto';
import type { AuditEntry, ControlCatalog, ModelVersion, ProjectData, PublicUser } from '../shared/types';

export interface StoredUser extends PublicUser {
  passwordHash: string;
  createdAt: string;
  mustChangePassword: boolean;
}

export interface StoredProject extends Omit<ProjectData, 'versions'> {
  versions: ModelVersion[];
}

export interface Db {
  schemaVersion: 1;
  users: StoredUser[];
  projects: Record<string, StoredProject>;
  catalogs: ControlCatalog[];
  audit: AuditEntry[];
}

const file = () => path.join(config.dataDir, 'store.enc');
export const uploadsDir = () => path.join(config.dataDir, 'uploads');

let db: Db | null = null;
let timer: NodeJS.Timeout | null = null;

/** The whole store is a single AES-256-GCM encrypted JSON document. */
export function loadDb(): Db {
  fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(uploadsDir(), { recursive: true, mode: 0o700 });
  if (fs.existsSync(file())) {
    db = JSON.parse(decrypt(fs.readFileSync(file()), 'store').toString('utf8')) as Db;
  } else {
    db = { schemaVersion: 1, users: [], projects: {}, catalogs: [], audit: [] };
  }
  return db;
}

export function getDb(): Db {
  if (!db) throw new Error('Database not loaded');
  return db;
}

/** Persist atomically (write temp file, then rename). Debounced unless immediate. */
export function persist(immediate = false) {
  const write = () => {
    timer = null;
    const blob = encrypt(Buffer.from(JSON.stringify(getDb())), 'store');
    const tmp = file() + '.tmp';
    fs.writeFileSync(tmp, blob, { mode: 0o600 });
    fs.renameSync(tmp, file());
  };
  if (immediate) {
    if (timer) clearTimeout(timer);
    write();
    return;
  }
  if (!timer) timer = setTimeout(write, 150);
}

export function flush() {
  if (timer) {
    clearTimeout(timer);
    persist(true);
  }
}

export function publicUser(u: StoredUser): PublicUser {
  return { id: u.id, username: u.username, displayName: u.displayName, role: u.role, disabled: u.disabled };
}
