import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const PORT = 4399;
const BASE = `http://127.0.0.1:${PORT}/api`;
const PW = 'Demo-Password-2026';
let proc: ChildProcess;
let dir: string;

class Client {
  cookie = '';
  csrf = '';
  async req(method: string, url: string, body?: unknown, raw = false) {
    const headers: Record<string, string> = { cookie: this.cookie };
    let payload: BodyInit | undefined;
    if (body instanceof FormData) payload = body;
    else if (body !== undefined) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); }
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf;
    const res = await fetch(BASE + url, { method, headers, body: payload });
    const set = res.headers.get('set-cookie');
    if (set) this.cookie = set.split(';')[0];
    const data = raw ? Buffer.from(await res.arrayBuffer()) : await res.json().catch(() => null);
    return { status: res.status, data, headers: res.headers };
  }
  async login(u: string) {
    const r = await this.req('POST', '/auth/login', { username: u, password: PW });
    this.csrf = r.data?.csrf ?? '';
    return r;
  }
}

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sawb-test-'));
  proc = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], {
    env: { ...process.env, PORT: String(PORT), SAWB_DATA_DIR: dir, SAWB_DEMO_PASSWORD: PW, SAWB_ENV: 'demonstration' },
    stdio: 'pipe',
  });
  for (let i = 0; i < 60; i++) {
    try { await fetch(`${BASE}/auth/session`); return; } catch { await new Promise((r) => setTimeout(r, 250)); }
  }
  throw new Error('server did not start');
}, 30000);

afterAll(() => {
  proc?.kill();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('API security and workflow', () => {
  const lead = new Client();
  const analyst = new Client();
  const viewer = new Client();
  let projectId = '';

  it('rejects bad credentials and accepts valid ones', async () => {
    const bad = new Client();
    expect((await bad.req('POST', '/auth/login', { username: 'lead', password: 'nope' })).status).toBe(401);
    expect((await lead.login('lead')).status).toBe(200);
    expect((await analyst.login('analyst')).status).toBe(200);
    expect((await viewer.login('viewer')).status).toBe(200);
    expect(lead.cookie).toMatch(/^sawb_sid=/);
  });

  it('requires authentication and a CSRF token', async () => {
    expect((await new Client().req('GET', '/projects')).status).toBe(401);
    const noCsrf = new Client();
    noCsrf.cookie = lead.cookie;
    expect((await noCsrf.req('POST', '/projects', { name: 'x' })).status).toBe(403);
  });

  it('lists the seeded demo project with engine-generated threats', async () => {
    const r = await lead.req('GET', '/projects');
    expect(r.status).toBe(200);
    expect(r.data).toHaveLength(1);
    expect(r.data[0].isDemo).toBe(true);
    projectId = r.data[0].id;
    const d = await lead.req('GET', `/projects/${projectId}`);
    expect(d.data.threats.length).toBeGreaterThan(10);
    expect(d.data.runs[0].skippedUnconfirmed).toBeGreaterThan(0);
  });

  it('enforces role and project-level permissions', async () => {
    expect((await viewer.req('POST', `/projects/${projectId}/analysis`, {})).status).toBe(403);
    expect((await analyst.req('POST', '/projects', { name: 'x' })).status).toBe(403);
    expect((await analyst.req('GET', '/audit')).status).toBe(403);
    // Analyst creates nothing outside membership: a lead-created project is invisible to the analyst.
    const created = await lead.req('POST', '/projects', { name: 'Private', clientAlias: 'P', scope: '', architectureVersion: '', reviewerId: '', reviewDate: '', methodologies: ['STRIDE'], catalogIds: [] });
    expect(created.status).toBe(201);
    expect((await analyst.req('GET', `/projects/${created.data.project.id}`)).status).toBe(404);
  });

  it('validates the canonical model and versions it', async () => {
    const d = (await analyst.req('GET', `/projects/${projectId}`)).data;
    const bad = { ...d.model, flows: [...d.model.flows, { ...d.model.flows[0], id: 'x', to: 'missing' }] };
    expect((await analyst.req('PUT', `/projects/${projectId}/model`, { model: bad })).status).toBe(400);
    const m = { ...d.model, notes: d.model.notes + ' updated' };
    expect((await analyst.req('PUT', `/projects/${projectId}/model`, { model: m })).status).toBe(200);
    const v = await analyst.req('POST', `/projects/${projectId}/versions`, { message: 'notes update' });
    expect(v.status).toBe(201);
    expect(v.data.versions).toHaveLength(2);
    expect((await analyst.req('POST', `/projects/${projectId}/versions`, { message: 'again' })).status).toBe(409);
    const run = await analyst.req('POST', `/projects/${projectId}/analysis`, { provider: 'rules' });
    expect(run.data.runs.at(-1).modelVersion).toBe(2);
    expect((await analyst.req('POST', `/projects/${projectId}/analysis`, { provider: 'openai' })).status).toBe(503);
  });

  it('does not let generated threat facts be edited', async () => {
    const d = (await analyst.req('GET', `/projects/${projectId}`)).data;
    const t = d.threats[0];
    expect((await analyst.req('PATCH', `/projects/${projectId}/threats/${t.id}`, { title: 'changed' })).status).toBe(400);
    expect((await analyst.req('PATCH', `/projects/${projectId}/threats/${t.id}`, { likelihood: 1 })).status).toBe(400);
    expect((await analyst.req('PATCH', `/projects/${projectId}/threats/${t.id}`, { likelihood: 1, analystNotes: 'compensating control seen' })).status).toBe(200);
  });

  it('requires evidence to mark a control satisfied', async () => {
    const d = (await lead.req('GET', `/projects/${projectId}`)).data;
    const cat = d.project.catalogIds[0];
    const cats = (await lead.req('GET', '/catalogs')).data;
    const ctl = cats.find((c: { id: string }) => c.id === cat).controls[0].id;
    const url = `/projects/${projectId}/controls/${cat}/${encodeURIComponent(ctl)}`;
    expect((await analyst.req('PUT', url, { status: 'evidence_satisfied', notes: '', evidenceRefs: [] })).status).toBe(400);
    expect((await analyst.req('PUT', url, { status: 'evidence_satisfied', notes: '', evidenceRefs: ['Policy v3'] })).status).toBe(200);
  });

  it('enforces segregation of duties on risk approval', async () => {
    const d = (await lead.req('GET', `/projects/${projectId}`)).data;
    const risk = d.risks[0];
    // Owner required before approval
    expect((await lead.req('POST', `/projects/${projectId}/risks/${risk.id}/approval`, { decision: 'approve' })).status).toBe(400);
    await analyst.req('PATCH', `/projects/${projectId}/risks/${risk.id}`, { ...risk, owner: 'Head of IT (client)' });
    expect((await analyst.req('POST', `/projects/${projectId}/risks/${risk.id}/approval`, { decision: 'approve' })).status).toBe(403);
    const ok = await lead.req('POST', `/projects/${projectId}/risks/${risk.id}/approval`, { decision: 'approve' });
    expect(ok.status).toBe(200);
    const created = await lead.req('POST', `/projects/${projectId}/risks`, { title: 'Lead risk', description: '', threatIds: [], likelihood: 2, impact: 2, residualLikelihood: 1, residualImpact: 2, owner: 'x', strategy: 'accept', status: 'open', targetDate: '', actions: [] });
    const mine = created.data.risks.at(-1);
    expect((await lead.req('POST', `/projects/${projectId}/risks/${mine.id}/approval`, { decision: 'approve' })).status).toBe(403);
  });

  it('handles uploads securely', async () => {
    const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a5e00000000049454e44ae426082', 'hex');
    const form = (buf: Buffer, name: string, synthetic = true) => {
      const f = new FormData();
      f.append('file', new Blob([new Uint8Array(buf)]), name);
      f.append('description', 'test');
      f.append('syntheticConfirmed', String(synthetic));
      return f;
    };
    expect((await analyst.req('POST', `/projects/${projectId}/evidence`, form(png, 'd.png', false))).status).toBe(400);
    expect((await analyst.req('POST', `/projects/${projectId}/evidence`, form(Buffer.from('MZ not a pdf'), 'evil.pdf'))).status).toBe(415);
    const ok = await analyst.req('POST', `/projects/${projectId}/evidence`, form(png, '../../d.png'));
    expect(ok.status).toBe(201);
    const ev = ok.data.evidence.at(-1);
    expect(ev.fileName).toBe('d.png');
    const stored = fs.readFileSync(path.join(dir, 'uploads', `${ev.id}.bin`));
    expect(stored.includes(png.subarray(0, 8))).toBe(false); // encrypted at rest
    const back = await analyst.req('GET', `/projects/${projectId}/evidence/${ev.id}/content`, undefined, true);
    expect(Buffer.compare(back.data, png)).toBe(0);
    expect(back.headers.get('content-security-policy')).toContain('sandbox');
    // AI processing cannot be approved or used in demonstration
    expect((await lead.req('PATCH', `/projects/${projectId}/evidence/${ev.id}`, { aiProcessingApproved: true })).status).toBe(409);
    expect((await lead.req('POST', '/ai/extract', { projectId, evidenceId: ev.id, userConfirmed: true })).status).toBe(403);
    const st = await lead.req('GET', '/ai/status');
    expect(st.data.configured).toBe(false);
    expect(st.data.adapterImplemented).toBe(false);
  });

  it('generates DOCX, PDF and XLSX through the reporting service', async () => {
    for (const [format, magic] of [['docx', 'PK'], ['pdf', '%PDF'], ['xlsx', 'PK']] as const) {
      const r = await analyst.req('POST', `/projects/${projectId}/export`, { type: 'architecture_review', format }, true);
      expect(r.status).toBe(200);
      expect((r.data as Buffer).subarray(0, magic.length).toString('latin1')).toBe(magic);
      expect(r.headers.get('content-disposition')).toContain('DEMO');
    }
    expect((await viewer.req('POST', `/projects/${projectId}/export`, { type: 'risk_register', format: 'pdf' })).status).toBe(403);
  });

  it('keeps an intact hash-chained audit trail and encrypts the store', async () => {
    const admin = new Client();
    await admin.login('admin');
    const v = await admin.req('GET', '/audit/verify');
    expect(v.data.ok).toBe(true);
    expect(v.data.checked).toBeGreaterThan(10);
    await new Promise((r) => setTimeout(r, 400));
    const raw = fs.readFileSync(path.join(dir, 'store.enc'));
    expect(raw.subarray(0, 5).toString()).toBe('SAWB1');
    expect(raw.includes(Buffer.from('DEMO-CLIENT-ALPHA'))).toBe(false);
  });

  it('locks out after repeated failed logins', async () => {
    const c = new Client();
    for (let i = 0; i < 5; i++) await c.req('POST', '/auth/login', { username: 'viewer', password: 'bad' });
    expect((await c.req('POST', '/auth/login', { username: 'viewer', password: PW })).status).toBe(429);
  });
});
