import type { NextFunction, Request, Response } from 'express';
import { config } from './config';
import { token } from './crypto';
import { getDb, type StoredProject, type StoredUser } from './store';
import type { ProjectRole, Role } from '../shared/types';

export const COOKIE = 'sawb_sid';

interface Session {
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
}

const sessions = new Map<string, Session>();

export function createSession(userId: string) {
  const sid = token(32);
  const s: Session = { userId, csrf: token(24), createdAt: Date.now(), lastSeen: Date.now() };
  sessions.set(sid, s);
  return { sid, session: s };
}

export function destroySession(sid: string | undefined) {
  if (sid) sessions.delete(sid);
}

export function destroyUserSessions(userId: string) {
  for (const [k, s] of sessions) if (s.userId === userId) sessions.delete(k);
}

export function cookieOptions() {
  return { httpOnly: true, sameSite: 'strict' as const, secure: config.secureCookies, path: '/' };
}

// ------------------------------------------------------------------ login throttling

const failures = new Map<string, { count: number; until: number; first: number }>();
const WINDOW = 15 * 60 * 1000;

export function loginBlocked(key: string): number {
  const f = failures.get(key);
  if (!f) return 0;
  if (f.until > Date.now()) return Math.ceil((f.until - Date.now()) / 1000);
  if (Date.now() - f.first > WINDOW) failures.delete(key);
  return 0;
}

export function recordFailure(key: string) {
  const f = failures.get(key) ?? { count: 0, until: 0, first: Date.now() };
  f.count += 1;
  if (f.count >= 5) f.until = Date.now() + WINDOW;
  failures.set(key, f);
}

export function clearFailures(key: string) {
  failures.delete(key);
}

// ------------------------------------------------------------------ permissions

export type Permission =
  | 'project:create'
  | 'project:edit'
  | 'project:delete'
  | 'member:manage'
  | 'model:edit'
  | 'threat:edit'
  | 'control:edit'
  | 'risk:edit'
  | 'risk:approve'
  | 'evidence:upload'
  | 'evidence:approve_ai'
  | 'report:export'
  | 'catalog:import'
  | 'catalog:approve'
  | 'user:manage'
  | 'audit:read_all';

const ROLE_PERMS: Record<Role, Permission[]> = {
  admin: ['project:create', 'project:edit', 'project:delete', 'member:manage', 'model:edit', 'threat:edit', 'control:edit', 'risk:edit', 'risk:approve', 'evidence:upload', 'evidence:approve_ai', 'report:export', 'catalog:import', 'catalog:approve', 'user:manage', 'audit:read_all'],
  lead_reviewer: ['project:create', 'project:edit', 'project:delete', 'member:manage', 'model:edit', 'threat:edit', 'control:edit', 'risk:edit', 'risk:approve', 'evidence:upload', 'evidence:approve_ai', 'report:export', 'catalog:approve'],
  analyst: ['project:edit', 'model:edit', 'threat:edit', 'control:edit', 'risk:edit', 'evidence:upload', 'report:export'],
  viewer: [],
};

export function roleCan(role: Role, p: Permission) {
  return ROLE_PERMS[role].includes(p);
}

export function permissionsFor(role: Role) {
  return ROLE_PERMS[role];
}

/** Project-scoped permissions that also require write membership on the project. */
const PROJECT_WRITE: Permission[] = ['project:edit', 'model:edit', 'threat:edit', 'control:edit', 'risk:edit', 'evidence:upload', 'evidence:approve_ai', 'risk:approve', 'report:export'];
const PROJECT_OWNER: Permission[] = ['member:manage', 'project:delete'];

export function projectRole(user: StoredUser, p: StoredProject): ProjectRole | 'admin' | null {
  if (user.role === 'admin') return 'admin';
  return p.project.members.find((m) => m.userId === user.id)?.role ?? null;
}

export function canAccessProject(user: StoredUser, p: StoredProject) {
  return projectRole(user, p) !== null;
}

export function projectCan(user: StoredUser, p: StoredProject, perm: Permission): boolean {
  const pr = projectRole(user, p);
  if (!pr) return false;
  if (!roleCan(user.role, perm)) return false;
  if (pr === 'admin') return true;
  if (PROJECT_OWNER.includes(perm)) return pr === 'owner';
  if (PROJECT_WRITE.includes(perm)) return pr === 'owner' || pr === 'editor';
  return true;
}

// ------------------------------------------------------------------ middleware

declare module 'express-serve-static-core' {
  interface Request {
    user?: StoredUser;
    sid?: string;
    session?: Session;
  }
}

export function authenticate(req: Request, _res: Response, next: NextFunction) {
  const sid = req.cookies?.[COOKIE] as string | undefined;
  if (sid) {
    const s = sessions.get(sid);
    const now = Date.now();
    if (s) {
      const idle = now - s.lastSeen > config.sessionIdleMinutes * 60_000;
      const tooOld = now - s.createdAt > config.sessionMaxHours * 3_600_000;
      const user = getDb().users.find((u) => u.id === s.userId);
      if (idle || tooOld || !user || user.disabled) {
        sessions.delete(sid);
      } else {
        s.lastSeen = now;
        req.user = user;
        req.sid = sid;
        req.session = s;
      }
    }
  }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required.' });
  // Double-submit CSRF token on every state-changing request.
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    if (req.get('x-csrf-token') !== req.session!.csrf) return res.status(403).json({ error: 'Missing or invalid CSRF token.' });
  }
  next();
}

export function requirePerm(p: Permission) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roleCan(req.user.role, p)) return res.status(403).json({ error: `Your role does not permit: ${p}.` });
    next();
  };
}
