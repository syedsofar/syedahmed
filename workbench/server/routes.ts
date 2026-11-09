import express, { type Request, type Response, type NextFunction } from 'express';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config';
import { audit, verifyChain } from './audit';
import {
  authenticate, canAccessProject, clearFailures, COOKIE, cookieOptions, createSession, destroySession, destroyUserSessions,
  loginBlocked, permissionsFor, projectCan, projectRole, recordFailure, requireAuth, requirePerm, roleCan, type Permission,
} from './auth';
import { decrypt, encrypt, hashPassword, newId, passwordProblem, sha256, verifyPassword } from './crypto';
import { getDb, persist, publicUser, uploadsDir, type StoredProject, type StoredUser } from './store';
import {
  controlReviewSchema, manualThreatSchema, modelSchema, parse, projectCreateSchema, projectPatchSchema, riskSchema, threatPatchSchema,
} from './validation';
import { renderDocx, renderPdf, renderXlsx } from './export';
import { getAiStatus, AI_ADAPTERS } from './ai';
import { analyzeModel, ENGINE_NAME, ENGINE_VERSION, mergeRun } from '../shared/engine';
import { canSetStatus, validateCatalogImport } from '../shared/controls';
import { canonicalJson, defaultRiskMatrix, riskBand } from '../shared/schema';
import { buildReport, REPORT_TYPES, type ReportType } from '../shared/report';
import type { ArchitectureModel, ProjectData, Risk, Threat } from '../shared/types';
import { MODEL_SCHEMA } from '../shared/types';

export const api = express.Router();
api.use(authenticate);

const ip = (req: Request) => req.ip;
const actor = (req: Request) => ({ id: req.user!.id, username: req.user!.username });
const nowIso = () => new Date().toISOString();

type Handler = (req: Request, res: Response) => unknown | Promise<unknown>;
const h = (fn: Handler) => (req: Request, res: Response, next: NextFunction) => Promise.resolve(fn(req, res)).catch(next);

function bad(res: Response, status: number, error: string) {
  res.status(status).json({ error });
}

// ------------------------------------------------------------------ auth

api.post('/auth/login', h((req, res) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== 'string' || typeof password !== 'string') return bad(res, 400, 'Username and password are required.');
  const key = `${username.toLowerCase()}|${ip(req)}`;
  const wait = loginBlocked(key);
  if (wait) return bad(res, 429, `Too many failed attempts. Try again in ${Math.ceil(wait / 60)} minute(s).`);
  const user = getDb().users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  // Always run a hash to keep timing similar for unknown users.
  const ok = user ? verifyPassword(password, user.passwordHash) : (verifyPassword(password, hashPassword('timing-equaliser')), false);
  if (!user || !ok || user.disabled) {
    recordFailure(key);
    audit(user ? { id: user.id, username: user.username } : null, 'auth.login_failed', { detail: `username=${username.slice(0, 60)}`, ip: ip(req) });
    return bad(res, 401, 'Invalid username or password.');
  }
  clearFailures(key);
  destroySession(req.cookies?.[COOKIE]);
  const { sid, session } = createSession(user.id);
  res.cookie(COOKIE, sid, cookieOptions());
  audit({ id: user.id, username: user.username }, 'auth.login', { ip: ip(req) });
  res.json({ user: publicUser(user), csrf: session.csrf, permissions: permissionsFor(user.role), mustChangePassword: user.mustChangePassword, environment: config.mode });
}));

api.get('/auth/session', (req, res) => {
  if (!req.user) return res.json(null);
  res.json({ user: publicUser(req.user), csrf: req.session!.csrf, permissions: permissionsFor(req.user.role), mustChangePassword: req.user.mustChangePassword, environment: config.mode });
});

api.post('/auth/logout', requireAuth, (req, res) => {
  audit(actor(req), 'auth.logout', { ip: ip(req) });
  destroySession(req.sid);
  res.clearCookie(COOKIE, cookieOptions());
  res.json({ ok: true });
});

api.post('/auth/password', requireAuth, h((req, res) => {
  const { current, next } = req.body ?? {};
  if (typeof current !== 'string' || typeof next !== 'string') return bad(res, 400, 'Current and new password are required.');
  if (!verifyPassword(current, req.user!.passwordHash)) return bad(res, 403, 'Current password is incorrect.');
  const problem = passwordProblem(next);
  if (problem) return bad(res, 400, problem);
  req.user!.passwordHash = hashPassword(next);
  req.user!.mustChangePassword = false;
  persist();
  audit(actor(req), 'auth.password_changed', { ip: ip(req) });
  res.json({ ok: true });
}));

// Everything below requires an authenticated session + CSRF token for writes.
api.use(requireAuth);

// ------------------------------------------------------------------ users

api.get('/users', (req, res) => {
  res.json(getDb().users.map(publicUser));
});

api.post('/users', requirePerm('user:manage'), h((req, res) => {
  const { username, displayName, role, password } = req.body ?? {};
  if (!/^[a-z0-9._-]{3,40}$/i.test(username ?? '')) return bad(res, 400, 'Username must be 3–40 characters (letters, digits, . _ -).');
  if (!['admin', 'lead_reviewer', 'analyst', 'viewer'].includes(role)) return bad(res, 400, 'Invalid role.');
  if (typeof displayName !== 'string' || !displayName.trim()) return bad(res, 400, 'Display name is required.');
  const problem = passwordProblem(password ?? '');
  if (problem) return bad(res, 400, problem);
  const db = getDb();
  if (db.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) return bad(res, 409, 'Username already exists.');
  const u: StoredUser = { id: newId(), username, displayName: displayName.trim().slice(0, 80), role, disabled: false, passwordHash: hashPassword(password), createdAt: nowIso(), mustChangePassword: true };
  db.users.push(u);
  persist();
  audit(actor(req), 'user.created', { target: u.username, detail: `role=${role}` });
  res.status(201).json(publicUser(u));
}));

api.patch('/users/:id', requirePerm('user:manage'), h((req, res) => {
  const u = getDb().users.find((x) => x.id === req.params.id);
  if (!u) return bad(res, 404, 'User not found.');
  const { role, disabled, displayName, password } = req.body ?? {};
  const changes: string[] = [];
  if (u.id === req.user!.id && (disabled === true || (role && role !== 'admin'))) return bad(res, 400, 'You cannot disable or demote your own account.');
  if (role !== undefined) {
    if (!['admin', 'lead_reviewer', 'analyst', 'viewer'].includes(role)) return bad(res, 400, 'Invalid role.');
    u.role = role; changes.push(`role=${role}`);
  }
  if (typeof disabled === 'boolean') { u.disabled = disabled; changes.push(`disabled=${disabled}`); if (disabled) destroyUserSessions(u.id); }
  if (typeof displayName === 'string' && displayName.trim()) { u.displayName = displayName.trim().slice(0, 80); changes.push('displayName'); }
  if (typeof password === 'string' && password) {
    const problem = passwordProblem(password);
    if (problem) return bad(res, 400, problem);
    u.passwordHash = hashPassword(password); u.mustChangePassword = true; destroyUserSessions(u.id); changes.push('password reset');
  }
  persist();
  audit(actor(req), 'user.updated', { target: u.username, detail: changes.join(', ') });
  res.json(publicUser(u));
}));

// ------------------------------------------------------------------ helpers for projects

function loadProject(req: Request, res: Response, perm?: Permission): StoredProject | null {
  const p = getDb().projects[req.params.id];
  if (!p || !canAccessProject(req.user!, p)) { bad(res, 404, 'Project not found.'); return null; }
  if (perm && !projectCan(req.user!, p, perm)) { bad(res, 403, `You do not have "${perm}" rights on this project.`); return null; }
  if (perm && perm !== 'project:edit' && p.project.status === 'archived' && perm !== 'report:export') {
    bad(res, 409, 'Archived assessments are read-only. Change the status to re-open it.');
    return null;
  }
  return p;
}

function toClient(p: StoredProject): ProjectData {
  return { ...p, versions: p.versions.map(({ model: _m, ...v }) => v) };
}

function touch(p: StoredProject, req: Request, action: string, detail?: string) {
  p.project.updatedAt = nowIso();
  p.project.history.push({ at: p.project.updatedAt, by: req.user!.id, action, detail });
  if (p.project.history.length > 500) p.project.history.splice(0, p.project.history.length - 500);
  persist();
  audit(actor(req), action.toLowerCase().replace(/\s+/g, '_').slice(0, 60), { projectId: p.project.id, detail });
}

function summary(p: StoredProject, req: Request) {
  const m = p.project.riskMatrix;
  const live = p.threats.filter((t) => t.decision !== 'rejected');
  return {
    ...p.project,
    myRole: projectRole(req.user!, p),
    latestVersion: p.versions[p.versions.length - 1]?.version ?? 0,
    counts: {
      components: p.model.components.length,
      confirmed: live.filter((t) => t.classification === 'confirmed').length,
      hypothesis: live.filter((t) => t.classification === 'hypothesis').length,
      missing_evidence: live.filter((t) => t.classification === 'missing_evidence').length,
      risks: p.risks.length,
      risksPendingApproval: p.risks.filter((r) => r.approval.state !== 'approved').length,
      highRisks: p.risks.filter((r) => riskBand(m, r.likelihood, r.impact).min >= (m.bands[m.bands.length - 2]?.min ?? 10)).length,
    },
  };
}

// ------------------------------------------------------------------ dashboard

api.get('/dashboard', (req, res) => {
  const db = getDb();
  const projects = Object.values(db.projects).filter((p) => canAccessProject(req.user!, p));
  const ids = new Set(projects.map((p) => p.project.id));
  const bands: Record<string, { count: number; color: string }> = {};
  const overdue: { projectId: string; project: string; risk: string; action: string; dueDate: string }[] = [];
  const today = nowIso().slice(0, 10);
  for (const p of projects) {
    for (const r of p.risks) {
      const b = riskBand(p.project.riskMatrix, r.likelihood, r.impact);
      bands[b.name] = { count: (bands[b.name]?.count ?? 0) + 1, color: b.color };
      for (const a of r.actions) if (!a.done && a.dueDate && a.dueDate < today) overdue.push({ projectId: p.project.id, project: p.project.name, risk: r.ref, action: a.description, dueDate: a.dueDate });
    }
  }
  res.json({
    projects: projects.map((p) => summary(p, req)),
    riskBands: bands,
    overdue: overdue.slice(0, 20),
    recent: db.audit.filter((a) => a.projectId && ids.has(a.projectId)).slice(-15).reverse(),
  });
});

// ------------------------------------------------------------------ projects

api.get('/projects', (req, res) => {
  res.json(Object.values(getDb().projects).filter((p) => canAccessProject(req.user!, p)).map((p) => summary(p, req)));
});

api.post('/projects', requirePerm('project:create'), h((req, res) => {
  const r = parse(projectCreateSchema, req.body);
  if (!r.ok) return bad(res, 400, r.error);
  const db = getDb();
  const approved = new Set(db.catalogs.filter((c) => c.status === 'approved').map((c) => c.id));
  if (r.value.catalogIds.some((id) => !approved.has(id))) return bad(res, 400, 'Only approved control catalog versions can be selected.');
  const id = newId();
  const now = nowIso();
  const members: { userId: string; role: 'owner' | 'editor' | 'viewer' }[] = [{ userId: req.user!.id, role: 'owner' }];
  if (r.value.reviewerId && r.value.reviewerId !== req.user!.id && db.users.some((u) => u.id === r.value.reviewerId)) members.push({ userId: r.value.reviewerId, role: 'editor' as const });
  db.projects[id] = {
    project: {
      ...r.value, id, status: 'draft', createdAt: now, createdBy: req.user!.id, updatedAt: now, isDemo: config.mode === 'demonstration',
      members, riskMatrix: defaultRiskMatrix(), narrative: { executiveSummary: '', limitations: '', recommendations: '' },
      history: [{ at: now, by: req.user!.id, action: 'Created assessment' }],
    },
    model: { schema: MODEL_SCHEMA, components: [], flows: [], zones: [], notes: '' },
    versions: [], threats: [], runs: [], controlReviews: [], risks: [], evidence: [],
  };
  persist();
  audit(actor(req), 'project.created', { projectId: id, detail: r.value.name });
  res.status(201).json(toClient(db.projects[id]));
}));

api.get('/projects/:id', (req, res) => {
  const p = loadProject(req, res);
  if (p) res.json({ ...toClient(p), myRole: projectRole(req.user!, p) });
});

api.patch('/projects/:id', h((req, res) => {
  const p = getDb().projects[req.params.id];
  if (!p || !canAccessProject(req.user!, p)) return bad(res, 404, 'Project not found.');
  if (!projectCan(req.user!, p, 'project:edit')) return bad(res, 403, 'You cannot edit this project.');
  const r = parse(projectPatchSchema, req.body);
  if (!r.ok) return bad(res, 400, r.error);
  const v = r.value;
  if (v.status && v.status !== p.project.status) {
    if ((v.status === 'final' || p.project.status === 'final') && !roleCan(req.user!.role, 'risk:approve')) return bad(res, 403, 'Only a lead reviewer or administrator can finalise or re-open a final assessment.');
    if (v.status === 'final' && p.risks.some((x) => x.approval.state !== 'approved')) return bad(res, 409, 'All risks must be approved by a reviewer before the assessment can be finalised.');
  }
  if (p.project.status === 'archived' && !v.status) return bad(res, 409, 'Archived assessments are read-only. Change the status to re-open it.');
  if (v.catalogIds) {
    const approved = new Set(getDb().catalogs.filter((c) => c.status === 'approved').map((c) => c.id));
    if (v.catalogIds.some((id) => !approved.has(id) && !p.project.catalogIds.includes(id))) return bad(res, 400, 'Only approved control catalog versions can be selected.');
  }
  if (v.riskMatrix && !projectCan(req.user!, p, 'risk:approve')) return bad(res, 403, 'Only a lead reviewer can change the risk matrix.');
  const changed = Object.keys(v);
  Object.assign(p.project, v);
  touch(p, req, v.status ? `Status changed to ${v.status}` : 'Updated assessment details', changed.join(', '));
  res.json(toClient(p));
}));

api.delete('/projects/:id', h((req, res) => {
  const p = loadProject(req, res, 'project:delete');
  if (!p) return;
  for (const e of p.evidence) fs.rmSync(path.join(uploadsDir(), `${e.id}.bin`), { force: true });
  delete getDb().projects[p.project.id];
  persist();
  audit(actor(req), 'project.deleted', { projectId: p.project.id, detail: p.project.name });
  res.json({ ok: true });
}));

/** Create a new draft assessment from an existing one (copies model, settings and versions). */
api.post('/projects/:id/clone', requirePerm('project:create'), h((req, res) => {
  const p = loadProject(req, res);
  if (!p) return;
  const id = newId();
  const now = nowIso();
  const copy: StoredProject = JSON.parse(JSON.stringify({ ...p, threats: [], runs: [], controlReviews: [], risks: [], evidence: [] }));
  copy.project = {
    ...copy.project, id, name: `${p.project.name} (draft copy)`, status: 'draft', createdAt: now, createdBy: req.user!.id, updatedAt: now,
    members: [{ userId: req.user!.id, role: 'owner' }],
    history: [{ at: now, by: req.user!.id, action: 'Created draft from existing assessment', detail: p.project.name }],
  };
  getDb().projects[id] = copy;
  persist();
  audit(actor(req), 'project.cloned', { projectId: id, detail: `from ${p.project.id}` });
  res.status(201).json(toClient(copy));
}));

api.put('/projects/:id/members', h((req, res) => {
  const p = loadProject(req, res, 'member:manage');
  if (!p) return;
  const members = req.body?.members;
  if (!Array.isArray(members)) return bad(res, 400, 'members must be an array.');
  const users = new Set(getDb().users.map((u) => u.id));
  const clean = members.filter((m) => users.has(m?.userId) && ['owner', 'editor', 'viewer'].includes(m?.role)).map((m) => ({ userId: m.userId as string, role: m.role as 'owner' | 'editor' | 'viewer' }));
  if (!clean.some((m) => m.role === 'owner')) return bad(res, 400, 'A project must have at least one owner.');
  p.project.members = Array.from(new Map(clean.map((m) => [m.userId, m])).values());
  touch(p, req, 'Updated project members', p.project.members.map((m) => `${getDb().users.find((u) => u.id === m.userId)?.username}:${m.role}`).join(', '));
  res.json(toClient(p));
}));

// ------------------------------------------------------------------ architecture model

api.put('/projects/:id/model', h((req, res) => {
  const p = loadProject(req, res, 'model:edit');
  if (!p) return;
  const r = parse(modelSchema, req.body?.model);
  if (!r.ok) return bad(res, 400, `Model rejected: ${r.error}`);
  p.model = r.value as ArchitectureModel;
  p.project.updatedAt = nowIso();
  persist();
  res.json({ ok: true, updatedAt: p.project.updatedAt });
}));

api.post('/projects/:id/versions', h((req, res) => {
  const p = loadProject(req, res, 'model:edit');
  if (!p) return;
  const message = String(req.body?.message ?? '').trim().slice(0, 300);
  if (!message) return bad(res, 400, 'A version message is required.');
  const hash = sha256(canonicalJson(p.model));
  const last = p.versions[p.versions.length - 1];
  if (last && last.hash === hash) return bad(res, 409, `No changes since version ${last.version}.`);
  const version = (last?.version ?? 0) + 1;
  p.versions.push({ version, savedAt: nowIso(), savedBy: req.user!.id, message, hash, model: JSON.parse(JSON.stringify(p.model)) });
  touch(p, req, `Saved model version ${version}`, message);
  res.status(201).json(toClient(p));
}));

api.get('/projects/:id/versions/:v', (req, res) => {
  const p = loadProject(req, res);
  if (!p) return;
  const v = p.versions.find((x) => x.version === Number(req.params.v));
  if (!v) return bad(res, 404, 'Version not found.');
  res.json(v);
});

api.post('/projects/:id/versions/:v/restore', h((req, res) => {
  const p = loadProject(req, res, 'model:edit');
  if (!p) return;
  const v = p.versions.find((x) => x.version === Number(req.params.v));
  if (!v) return bad(res, 404, 'Version not found.');
  p.model = JSON.parse(JSON.stringify(v.model));
  touch(p, req, `Restored working model from version ${v.version}`);
  res.json(toClient(p));
}));

// ------------------------------------------------------------------ threat analysis

api.post('/projects/:id/analysis', h((req, res) => {
  const p = loadProject(req, res, 'threat:edit');
  if (!p) return;
  const provider = String(req.body?.provider ?? 'rules');
  if (provider !== 'rules') {
    const status = getAiStatus();
    return bad(res, 503, `Analysis provider "${provider}" is not operational: ${status.message}`);
  }
  const latest = p.versions[p.versions.length - 1];
  if (!latest) return bad(res, 409, 'Save a model version before running analysis. Analysis always runs against a saved, immutable version.');
  const methods = p.project.methodologies;
  if (!methods.length) return bad(res, 400, 'Select at least one methodology in the assessment settings.');
  const result = analyzeModel(latest.model, methods, latest.version);
  const runId = newId();
  const referenced = new Set(p.risks.flatMap((r) => r.threatIds));
  p.threats = mergeRun(p.threats, result.drafts, { runId, at: nowIso(), by: req.user!.id, newId, referenced });
  const live = p.threats.filter((t) => t.runId === runId);
  const run = {
    id: runId, at: nowIso(), by: req.user!.id, provider: ENGINE_NAME, providerVersion: ENGINE_VERSION, modelVersion: latest.version, methodologies: methods,
    counts: {
      confirmed: live.filter((t) => t.classification === 'confirmed').length,
      hypothesis: live.filter((t) => t.classification === 'hypothesis').length,
      missing_evidence: live.filter((t) => t.classification === 'missing_evidence').length,
    },
    skippedUnconfirmed: result.skippedUnconfirmed,
  };
  p.runs.push(run);
  touch(p, req, `Ran threat analysis on model v${latest.version}`, `${methods.join('/')}: ${run.counts.confirmed} confirmed, ${run.counts.hypothesis} hypotheses, ${run.counts.missing_evidence} missing evidence; ${run.skippedUnconfirmed} unconfirmed elements excluded`);
  res.json(toClient(p));
}));

api.post('/projects/:id/threats', h((req, res) => {
  const p = loadProject(req, res, 'threat:edit');
  if (!p) return;
  const r = parse(manualThreatSchema, req.body);
  if (!r.ok) return bad(res, 400, r.error);
  const now = nowIso();
  const t: Threat = {
    ...r.value, id: newId(), key: `MANUAL:${newId()}`, methodology: 'MANUAL', rationale: 'Authored by analyst.', basis: [],
    decision: 'accepted', analystNotes: '', modelVersion: p.versions[p.versions.length - 1]?.version ?? 0, runId: '', createdAt: now, updatedAt: now, updatedBy: req.user!.id,
  };
  p.threats.push(t);
  touch(p, req, 'Added analyst-authored threat', t.title);
  res.status(201).json(toClient(p));
}));

api.patch('/projects/:id/threats/:tid', h((req, res) => {
  const p = loadProject(req, res, 'threat:edit');
  if (!p) return;
  const t = p.threats.find((x) => x.id === req.params.tid);
  if (!t) return bad(res, 404, 'Threat not found.');
  const r = parse(threatPatchSchema, req.body);
  if (!r.ok) return bad(res, 400, r.error);
  const v = r.value;
  const engineOwned = ['title', 'category', 'classification', 'affectedAssets', 'attackScenario', 'preconditions', 'existingControls', 'missingInformation', 'mitigation', 'tags'] as const;
  if (t.methodology !== 'MANUAL' && engineOwned.some((k) => v[k] !== undefined)) {
    return bad(res, 400, 'Generated threats are derived from model facts; change the model and re-run analysis, or record your view in analyst notes.');
  }
  if ((v.likelihood !== undefined || v.impact !== undefined) && t.methodology !== 'MANUAL' && !(v.analystNotes ?? t.analystNotes).trim()) {
    return bad(res, 400, 'Adjusting the rating of a generated threat requires an analyst note explaining the change.');
  }
  Object.assign(t, v, { updatedAt: nowIso(), updatedBy: req.user!.id });
  touch(p, req, 'Updated threat', `${t.title}${v.decision ? ` → ${v.decision}` : ''}`);
  res.json(toClient(p));
}));

api.delete('/projects/:id/threats/:tid', h((req, res) => {
  const p = loadProject(req, res, 'threat:edit');
  if (!p) return;
  const t = p.threats.find((x) => x.id === req.params.tid);
  if (!t) return bad(res, 404, 'Threat not found.');
  if (t.methodology !== 'MANUAL') return bad(res, 400, 'Generated threats cannot be deleted; reject them instead so the decision is recorded.');
  if (p.risks.some((r) => r.threatIds.includes(t.id))) return bad(res, 409, 'Threat is linked to a risk; unlink it first.');
  p.threats = p.threats.filter((x) => x.id !== t.id);
  touch(p, req, 'Deleted analyst-authored threat', t.title);
  res.json(toClient(p));
}));

// ------------------------------------------------------------------ control review

api.put('/projects/:id/controls/:catalogId/:controlId', h((req, res) => {
  const p = loadProject(req, res, 'control:edit');
  if (!p) return;
  const cat = getDb().catalogs.find((c) => c.id === req.params.catalogId);
  if (!cat || cat.status !== 'approved' || !p.project.catalogIds.includes(cat.id)) return bad(res, 400, 'Control reviews can only be recorded against approved catalogs selected for this assessment.');
  if (!cat.controls.some((c) => c.id === req.params.controlId)) return bad(res, 404, 'Control not in catalog.');
  const r = parse(controlReviewSchema, req.body);
  if (!r.ok) return bad(res, 400, r.error);
  const problem = canSetStatus(r.value.status, r.value.evidenceRefs, r.value.notes);
  if (problem) return bad(res, 400, problem);
  let rv = p.controlReviews.find((x) => x.catalogId === cat.id && x.controlId === req.params.controlId);
  if (!rv) {
    rv = { id: newId(), catalogId: cat.id, controlId: req.params.controlId, status: 'not_assessed', notes: '', evidenceRefs: [], updatedAt: '', updatedBy: '' };
    p.controlReviews.push(rv);
  }
  Object.assign(rv, r.value, { updatedAt: nowIso(), updatedBy: req.user!.id });
  touch(p, req, 'Updated control review', `${cat.framework} ${req.params.controlId} → ${r.value.status}`);
  res.json(toClient(p));
}));

// ------------------------------------------------------------------ risks

function nextRiskRef(p: StoredProject) {
  const n = Math.max(0, ...p.risks.map((r) => Number(r.ref.replace(/\D/g, '')) || 0)) + 1;
  return `R-${String(n).padStart(3, '0')}`;
}

api.post('/projects/:id/risks', h((req, res) => {
  const p = loadProject(req, res, 'risk:edit');
  if (!p) return;
  const r = parse(riskSchema, req.body);
  if (!r.ok) return bad(res, 400, r.error);
  const ids = new Set(p.threats.map((t) => t.id));
  if (r.value.threatIds.some((id) => !ids.has(id))) return bad(res, 400, 'Linked threat not found.');
  const now = nowIso();
  const risk: Risk = { ...r.value, id: newId(), ref: nextRiskRef(p), approval: { state: 'pending' }, createdBy: req.user!.id, createdAt: now, updatedAt: now };
  p.risks.push(risk);
  touch(p, req, 'Registered risk', `${risk.ref} ${risk.title}`);
  res.status(201).json(toClient(p));
}));

api.patch('/projects/:id/risks/:rid', h((req, res) => {
  const p = loadProject(req, res, 'risk:edit');
  if (!p) return;
  const risk = p.risks.find((x) => x.id === req.params.rid);
  if (!risk) return bad(res, 404, 'Risk not found.');
  const r = parse(riskSchema, req.body);
  if (!r.ok) return bad(res, 400, r.error);
  const material = (['likelihood', 'impact', 'residualLikelihood', 'residualImpact', 'strategy', 'owner', 'targetDate'] as const).some((k) => r.value[k] !== risk[k]);
  Object.assign(risk, r.value, { updatedAt: nowIso() });
  if (material && risk.approval.state === 'approved') risk.approval = { state: 'pending', comment: 'Re-approval required: rating, owner, treatment or target date changed.' };
  touch(p, req, 'Updated risk', `${risk.ref}${material ? ' (material change)' : ''}`);
  res.json(toClient(p));
}));

api.delete('/projects/:id/risks/:rid', h((req, res) => {
  const p = loadProject(req, res, 'risk:edit');
  if (!p) return;
  const risk = p.risks.find((x) => x.id === req.params.rid);
  if (!risk) return bad(res, 404, 'Risk not found.');
  if (risk.approval.state === 'approved' && !projectCan(req.user!, p, 'risk:approve')) return bad(res, 403, 'Approved risks can only be removed by a reviewer.');
  p.risks = p.risks.filter((x) => x.id !== risk.id);
  touch(p, req, 'Removed risk', `${risk.ref} ${risk.title}`);
  res.json(toClient(p));
}));

api.post('/projects/:id/risks/:rid/approval', h((req, res) => {
  const p = loadProject(req, res, 'risk:approve');
  if (!p) return;
  const risk = p.risks.find((x) => x.id === req.params.rid);
  if (!risk) return bad(res, 404, 'Risk not found.');
  const decision = req.body?.decision;
  const comment = String(req.body?.comment ?? '').slice(0, 1000);
  if (!['approve', 'request_changes'].includes(decision)) return bad(res, 400, 'decision must be approve or request_changes.');
  if (risk.createdBy === req.user!.id) return bad(res, 403, 'Segregation of duties: the person who registered a risk cannot approve it.');
  if (decision === 'approve' && !risk.owner.trim()) return bad(res, 400, 'A risk owner must be assigned before approval.');
  if (decision === 'request_changes' && !comment.trim()) return bad(res, 400, 'A comment is required when requesting changes.');
  risk.approval = { state: decision === 'approve' ? 'approved' : 'changes_requested', by: req.user!.id, at: nowIso(), comment };
  touch(p, req, decision === 'approve' ? 'Approved risk' : 'Requested changes to risk', `${risk.ref}${comment ? `: ${comment}` : ''}`);
  res.json(toClient(p));
}));

// ------------------------------------------------------------------ evidence (secure file handling)

const ALLOWED = [
  { mime: 'application/pdf', ext: ['.pdf'], magic: (b: Buffer) => b.subarray(0, 5).toString('latin1') === '%PDF-' },
  { mime: 'image/png', ext: ['.png'], magic: (b: Buffer) => b.readUInt32BE(0) === 0x89504e47 },
  { mime: 'image/jpeg', ext: ['.jpg', '.jpeg'], magic: (b: Buffer) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { mime: 'application/vnd.jgraph.mxfile', ext: ['.drawio', '.xml'], magic: (b: Buffer) => /^\s*(<\?xml[^>]*>\s*)?<(mxfile|mxGraphModel)\b/.test(b.subarray(0, 400).toString('utf8')) },
];

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: config.maxUploadBytes, files: 1, fields: 5 } });

function safeName(name: string) {
  return path.basename(name).replace(/[^\w.\- ()]/g, '_').slice(0, 120) || 'file';
}

api.post('/projects/:id/evidence', upload.single('file'), h((req, res) => {
  const p = loadProject(req, res, 'evidence:upload');
  if (!p) return;
  const f = req.file;
  if (!f) return bad(res, 400, 'No file received.');
  if (config.mode === 'demonstration' && req.body?.syntheticConfirmed !== 'true') {
    return bad(res, 400, 'This is a demonstration environment. Confirm the file contains only synthetic or sanitised non-client data before uploading.');
  }
  const ext = path.extname(f.originalname).toLowerCase();
  const kind = ALLOWED.find((a) => a.ext.includes(ext));
  if (!kind || f.buffer.length < 8 || !kind.magic(f.buffer)) return bad(res, 415, 'Unsupported or mismatched file type. Allowed: PDF, PNG, JPEG, draw.io (.drawio/.xml). File content must match its extension.');
  const id = newId();
  fs.writeFileSync(path.join(uploadsDir(), `${id}.bin`), encrypt(f.buffer, `evidence:${id}`), { mode: 0o600 });
  const ev = {
    id, fileName: safeName(f.originalname), mimeType: kind.mime, size: f.buffer.length, sha256: sha256(f.buffer), uploadedBy: req.user!.id, uploadedAt: nowIso(),
    description: String(req.body?.description ?? '').slice(0, 500), aiProcessingApproved: false, confirmation: 'pending' as const,
  };
  p.evidence.push(ev);
  touch(p, req, 'Uploaded evidence file', `${ev.fileName} (${ev.size} bytes, sha256 ${ev.sha256.slice(0, 16)}…)`);
  res.status(201).json(toClient(p));
}));

api.get('/projects/:id/evidence/:eid/content', h((req, res) => {
  const p = loadProject(req, res);
  if (!p) return;
  const ev = p.evidence.find((e) => e.id === req.params.eid);
  if (!ev) return bad(res, 404, 'Evidence not found.');
  const buf = decrypt(fs.readFileSync(path.join(uploadsDir(), `${ev.id}.bin`)), `evidence:${ev.id}`);
  if (sha256(buf) !== ev.sha256) return bad(res, 500, 'Integrity check failed for stored evidence.');
  audit(actor(req), 'evidence.accessed', { projectId: p.project.id, target: ev.fileName });
  res.setHeader('Content-Type', ev.mimeType === 'application/vnd.jgraph.mxfile' ? 'text/plain; charset=utf-8' : ev.mimeType);
  res.setHeader('Content-Disposition', `${req.query.download ? 'attachment' : 'inline'}; filename="${ev.fileName.replace(/"/g, '')}"`);
  res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'; img-src 'self'; style-src 'unsafe-inline'");
  res.setHeader('Cache-Control', 'no-store');
  res.send(buf);
}));

api.patch('/projects/:id/evidence/:eid', h((req, res) => {
  const p = loadProject(req, res, 'evidence:upload');
  if (!p) return;
  const ev = p.evidence.find((e) => e.id === req.params.eid);
  if (!ev) return bad(res, 404, 'Evidence not found.');
  const { description, confirmation, aiProcessingApproved } = req.body ?? {};
  if (typeof description === 'string') ev.description = description.slice(0, 500);
  if (['pending', 'transcribed', 'not_used'].includes(confirmation)) ev.confirmation = confirmation;
  if (typeof aiProcessingApproved === 'boolean') {
    if (!projectCan(req.user!, p, 'evidence:approve_ai')) return bad(res, 403, 'Only a lead reviewer or administrator can approve AI processing of a document.');
    if (aiProcessingApproved && config.mode !== 'production') return bad(res, 409, 'AI processing of uploaded documents cannot be approved in the demonstration environment.');
    ev.aiProcessingApproved = aiProcessingApproved;
  }
  touch(p, req, 'Updated evidence record', `${ev.fileName}: ${Object.keys(req.body ?? {}).join(', ')}`);
  res.json(toClient(p));
}));

api.delete('/projects/:id/evidence/:eid', h((req, res) => {
  const p = loadProject(req, res, 'evidence:upload');
  if (!p) return;
  const ev = p.evidence.find((e) => e.id === req.params.eid);
  if (!ev) return bad(res, 404, 'Evidence not found.');
  fs.rmSync(path.join(uploadsDir(), `${ev.id}.bin`), { force: true });
  p.evidence = p.evidence.filter((e) => e.id !== ev.id);
  touch(p, req, 'Deleted evidence file', ev.fileName);
  res.json(toClient(p));
}));

// ------------------------------------------------------------------ catalogs

api.get('/catalogs', (_req, res) => {
  res.json(getDb().catalogs);
});

api.post('/catalogs', requirePerm('catalog:import'), h((req, res) => {
  const v = validateCatalogImport(req.body);
  if (!v.ok) return bad(res, 400, v.errors.join(' '));
  const db = getDb();
  if (db.catalogs.some((c) => c.framework === v.value.framework && c.version === v.value.version)) return bad(res, 409, 'A catalog with this framework and version already exists. Use a new version label.');
  const cat = {
    id: newId(), framework: v.value.framework, name: v.value.name, version: v.value.version, source: v.value.source, status: 'draft' as const,
    isDemo: false, importedBy: req.user!.id, importedAt: nowIso(), contentHash: sha256(canonicalJson(v.value.controls)), controls: v.value.controls,
  };
  db.catalogs.push(cat);
  persist();
  audit(actor(req), 'catalog.imported', { target: `${cat.framework} ${cat.version}`, detail: `${cat.controls.length} controls, hash ${cat.contentHash.slice(0, 16)}` });
  res.status(201).json(cat);
}));

api.post('/catalogs/:cid/approve', requirePerm('catalog:approve'), h((req, res) => {
  const cat = getDb().catalogs.find((c) => c.id === req.params.cid);
  if (!cat) return bad(res, 404, 'Catalog not found.');
  if (cat.status !== 'draft') return bad(res, 409, 'Only draft catalogs can be approved.');
  if (cat.importedBy === req.user!.id) return bad(res, 403, 'Segregation of duties: the importer cannot approve the same catalog version.');
  if (sha256(canonicalJson(cat.controls)) !== cat.contentHash) return bad(res, 409, 'Catalog content hash mismatch; re-import required.');
  Object.assign(cat, { status: 'approved', approvedBy: req.user!.id, approvedAt: nowIso() });
  persist();
  audit(actor(req), 'catalog.approved', { target: `${cat.framework} ${cat.version}` });
  res.json(cat);
}));

api.post('/catalogs/:cid/retire', requirePerm('catalog:import'), h((req, res) => {
  const cat = getDb().catalogs.find((c) => c.id === req.params.cid);
  if (!cat) return bad(res, 404, 'Catalog not found.');
  cat.status = 'retired';
  persist();
  audit(actor(req), 'catalog.retired', { target: `${cat.framework} ${cat.version}` });
  res.json(cat);
}));

// ------------------------------------------------------------------ AI service interface

api.get('/ai/status', (_req, res) => {
  res.json({ ...getAiStatus(), adapters: Object.keys(AI_ADAPTERS) });
});

api.post('/ai/extract', h((req, res) => {
  const p = getDb().projects[req.body?.projectId];
  if (!p || !canAccessProject(req.user!, p) || !projectCan(req.user!, p, 'model:edit')) return bad(res, 404, 'Project not found.');
  const ev = p.evidence.find((e) => e.id === req.body?.evidenceId);
  if (!ev) return bad(res, 404, 'Evidence not found.');
  const status = getAiStatus();
  audit(actor(req), 'ai.extract_requested', { projectId: p.project.id, target: ev.fileName, detail: status.message });
  if (!ev.aiProcessingApproved) return bad(res, 403, 'This document has not been approved for AI processing. Nothing was sent.');
  if (req.body?.userConfirmed !== true) return bad(res, 400, 'Explicit confirmation is required for each AI request. Nothing was sent.');
  if (!status.configured || !status.adapterImplemented || !status.documentProcessingAllowed) return bad(res, 503, `AI extraction is not operational: ${status.message} Nothing was sent.`);
  return bad(res, 501, 'AI extraction adapter not implemented.');
}));

// ------------------------------------------------------------------ exports

const exportJson = express.json({ limit: '12mb' });

api.post('/projects/:id/report-preview', h((req, res) => {
  const p = loadProject(req, res);
  if (!p) return;
  const type = req.body?.type as ReportType;
  if (!REPORT_TYPES[type]) return bad(res, 400, 'Unknown report type.');
  res.json(buildReport(type, toClient(p), getDb().users.map(publicUser), getDb().catalogs));
}));

api.post('/projects/:id/export', exportJson, h(async (req, res) => {
  const p = loadProject(req, res, 'report:export');
  if (!p) return;
  const type = req.body?.type as ReportType;
  const format = req.body?.format as 'docx' | 'pdf' | 'xlsx';
  if (!REPORT_TYPES[type]) return bad(res, 400, 'Unknown report type.');
  if (!['docx', 'pdf', 'xlsx'].includes(format)) return bad(res, 400, 'Unknown format.');
  let diagram: Buffer | undefined;
  if (typeof req.body?.diagramPng === 'string') {
    const b = Buffer.from(req.body.diagramPng.replace(/^data:image\/png;base64,/, ''), 'base64');
    if (b.length > 8 && b.readUInt32BE(0) === 0x89504e47) diagram = b;
  }
  const doc = buildReport(type, toClient(p), getDb().users.map(publicUser), getDb().catalogs);
  const buf = format === 'docx' ? await renderDocx(doc, diagram) : format === 'pdf' ? await renderPdf(doc, diagram) : await renderXlsx(doc);
  const mime = { docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', pdf: 'application/pdf', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }[format];
  const name = `${p.project.clientAlias}-${type}-${nowIso().slice(0, 10)}${p.project.isDemo ? '-DEMO' : ''}.${format}`.replace(/[^\w.-]/g, '_');
  audit(actor(req), 'report.exported', { projectId: p.project.id, target: name, detail: `${type} ${format} sha256=${sha256(buf).slice(0, 16)}` });
  res.setHeader('Content-Type', mime);
  res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send(buf);
}));

// ------------------------------------------------------------------ audit

api.get('/audit', (req, res) => {
  const db = getDb();
  const projectId = req.query.projectId as string | undefined;
  if (projectId) {
    const p = db.projects[projectId];
    if (!p || !canAccessProject(req.user!, p)) return bad(res, 404, 'Project not found.');
    return res.json(db.audit.filter((a) => a.projectId === projectId).slice(-500).reverse());
  }
  if (!roleCan(req.user!.role, 'audit:read_all')) return bad(res, 403, 'Only administrators can view the global audit trail.');
  res.json(db.audit.slice(-1000).reverse());
});

api.get('/audit/verify', requirePerm('audit:read_all'), (_req, res) => {
  res.json(verifyChain());
});

api.get('/environment', (_req, res) => {
  res.json({ mode: config.mode, maxUploadMb: Math.round(config.maxUploadBytes / 1048576), ai: getAiStatus() });
});

// Fallback error handler (no stack traces to clients).
api.use((err: Error & { code?: string }, req: Request, res: Response, _next: NextFunction) => {
  if (err.code === 'LIMIT_FILE_SIZE') return bad(res, 413, `File exceeds the ${Math.round(config.maxUploadBytes / 1048576)} MB limit.`);
  console.error('[api error]', req.method, req.path, err);
  bad(res, 500, 'Internal error. The incident was logged.');
});
