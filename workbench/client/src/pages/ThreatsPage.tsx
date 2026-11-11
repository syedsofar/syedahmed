import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Play, Bot, Cpu, Plus, ShieldAlert, Check, X, RotateCcw, Gauge } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useProject } from '../lib/project';
import { Badge, Callout, Empty, Field, Modal, TagInput, fmtDate, useToast } from '../components/ui';
import { CONTROL_TAGS } from '@shared/controls';
import { ENGINE_NAME, ENGINE_VERSION } from '@shared/engine';
import { riskBand } from '@shared/schema';
import type { AiStatus, ProjectData, Threat, ThreatClass } from '@shared/types';

export const CLASS_INFO: Record<ThreatClass, { label: string; tone: string; help: string }> = {
  confirmed: { label: 'Confirmed findings', tone: 'danger', help: 'An explicit, confirmed model fact shows the relevant control is absent or weak.' },
  hypothesis: { label: 'Hypotheses', tone: 'teal', help: 'Structurally applicable threats where controls are recorded as present but not verified. Validate with evidence.' },
  missing_evidence: { label: 'Missing evidence', tone: 'warn', help: 'Facts needed to evaluate the threat are unknown. These become information requests to the client.' },
};

export function RatingChip({ l, i }: { l: number; i: number }) {
  const { data } = useProject();
  const b = riskBand(data.project.riskMatrix, l, i);
  return <span className="badge" style={{ background: b.color, color: '#1b2430' }}>{b.name} {b.score}</span>;
}

export function threatRef(threats: Threat[], t: Threat) {
  return `T-${String(threats.findIndex((x) => x.id === t.id) + 1).padStart(3, '0')}`;
}

export function ThreatsPage() {
  const { data, can, mutate } = useProject();
  const { userName } = useAuth();
  const toast = useToast();
  const nav = useNavigate();
  const [tab, setTab] = useState<ThreatClass | 'rejected'>('confirmed');
  const [method, setMethod] = useState('all');
  const [q, setQ] = useState('');
  const [selId, setSelId] = useState<string | null>(null);
  const [ai, setAi] = useState<AiStatus | null>(null);
  const [running, setRunning] = useState(false);
  const [manual, setManual] = useState(false);
  const [showRuns, setShowRuns] = useState(false);

  useEffect(() => { api.get<AiStatus>('/ai/status').then(setAi).catch(() => setAi(null)); }, []);

  const latest = data.versions[data.versions.length - 1];
  const lastRun = data.runs[data.runs.length - 1];
  const unconfirmed = data.model.components.filter((c) => c.status !== 'confirmed').length + data.model.flows.filter((f) => f.status !== 'confirmed').length;

  const list = useMemo(() => data.threats.filter((t) => {
    if (tab === 'rejected' ? t.decision !== 'rejected' : t.decision === 'rejected' || t.classification !== tab) return false;
    if (method !== 'all' && t.methodology !== method) return false;
    const s = q.toLowerCase();
    return !s || t.title.toLowerCase().includes(s) || t.affectedAssets.some((a) => a.toLowerCase().includes(s)) || t.category.toLowerCase().includes(s);
  }).sort((a, b) => b.likelihood * b.impact - a.likelihood * a.impact), [data.threats, tab, method, q]);

  const counts = (c: ThreatClass) => data.threats.filter((t) => t.classification === c && t.decision !== 'rejected').length;
  const sel = data.threats.find((t) => t.id === selId) ?? null;

  const run = async () => {
    setRunning(true);
    await mutate(() => api.post<ProjectData>(`/projects/${data.project.id}/analysis`, { provider: 'rules' }), 'Analysis complete.');
    setRunning(false);
  };

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Threat model</h1><div className="sub">Threat scenarios derived from the confirmed components, flows and zones of a saved model version. Analysis never adds architecture facts; it separates confirmed findings, hypotheses and missing evidence.</div></div>
        <div className="actions">{can('threat:edit') && <button className="btn" onClick={() => setManual(true)}><Plus size={16} /> Analyst-authored threat</button>}</div>
      </div>

      <div className="grid grid-2">
        <section className="card">
          <div className="card-head"><Cpu size={16} /><h2>{ENGINE_NAME}</h2><Badge tone="ok">operational</Badge><span className="small muted right">v{ENGINE_VERSION} · runs server-side</span></div>
          <div className="card-body stack">
            <div className="small">Methodologies: {data.project.methodologies.map((m) => <Badge key={m} tone="navy">{m}</Badge>)} <Link to=".." relative="path" className="small">change</Link></div>
            <div className="small muted">PROTOTYPE: the ArchGuard rule checks on confirmed components and flows. STRIDE-per-element rules, PASTA attack-path analysis (entry points → critical assets over confirmed flows) and OCTAVE Allegro information-asset areas of concern. Re-running keeps analyst decisions for unchanged threats.</div>
            {!latest && <Callout tone="warn">Save a model version in the <Link to="../architecture">architecture editor</Link> first.</Callout>}
            {unconfirmed > 0 && <Callout tone="warn">{unconfirmed} unconfirmed element(s) in the working model will be excluded.</Callout>}
            {lastRun && latest && lastRun.modelVersion !== latest.version && <Callout tone="warn">The latest run used v{lastRun.modelVersion}; the newest version is v{latest.version}.</Callout>}
            <div className="row gap wrap">
              {can('threat:edit') && <button className="btn btn-teal" disabled={!latest || running || !data.project.methodologies.length} onClick={run}><Play size={14} /> {running ? 'Analysing…' : `Run analysis on v${latest?.version ?? '–'}`}</button>}
              {lastRun && <span className="small muted">Last run {fmtDate(lastRun.at)} by {userName(lastRun.by)} on v{lastRun.modelVersion} ({lastRun.skippedUnconfirmed} unconfirmed excluded)</span>}
              {data.runs.length > 0 && <button className="btn btn-sm right" onClick={() => setShowRuns(true)}>Run history ({data.runs.length})</button>}
            </div>
          </div>
        </section>
        <section className="card">
          <div className="card-head"><Bot size={16} /><h2>AI analysis provider</h2><Badge tone={ai?.adapterImplemented && ai.configured ? 'ok' : 'danger'}>{ai?.adapterImplemented && ai.configured ? 'available' : 'not operational'}</Badge></div>
          <div className="card-body stack small">
            <p>{ai?.message ?? 'Status unavailable.'}</p>
            <p className="muted">Interface: <code>POST /api/projects/:id/analysis</code> with <code>provider</code>, and <code>POST /api/ai/extract</code> for documents. An AI adapter would only propose additional <em>hypotheses</em>, never confirmed findings, and every proposal would require analyst acceptance. Uploaded documents are never sent without per-document approval and per-request confirmation.</p>
            <p className="muted">Configured provider: {ai?.provider ?? 'none'} · adapter implemented: {ai?.adapterImplemented ? 'yes' : 'no'} · environment: {ai?.environment}</p>
          </div>
        </section>
      </div>

      <div className="tabs" style={{ marginTop: 18 }} role="tablist">
        {(Object.keys(CLASS_INFO) as ThreatClass[]).map((c) => <button key={c} className={tab === c ? 'on' : ''} onClick={() => { setTab(c); setSelId(null); }}>{CLASS_INFO[c].label} <span className="count">{counts(c)}</span></button>)}
        <button className={tab === 'rejected' ? 'on' : ''} onClick={() => { setTab('rejected'); setSelId(null); }}>Rejected <span className="count">{data.threats.filter((t) => t.decision === 'rejected').length}</span></button>
      </div>
      {tab !== 'rejected' && <p className="small muted" style={{ marginTop: -6 }}>{CLASS_INFO[tab].help}</p>}

      <div className="split">
        <section className="card">
          <div className="card-head">
            <input type="search" placeholder="Search title, asset or category" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 280 }} />
            <select value={method} onChange={(e) => setMethod(e.target.value)} style={{ width: 150 }}>
              <option value="all">All methods</option><option>STRIDE</option><option>PASTA</option><option>OCTAVE</option><option>PROTOTYPE</option><option value="MANUAL">Analyst-authored</option>
            </select>
            <span className="small muted right">{list.length} shown</span>
          </div>
          {list.length === 0 ? <Empty icon={<ShieldAlert size={32} />} title={data.runs.length ? 'No threats in this view' : 'No analysis has been run yet'} /> : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Ref</th><th>Threat</th><th>Method</th><th>Rating</th><th>Decision</th></tr></thead>
              <tbody>
                {list.map((t) => (
                  <tr key={t.id} className={`clickable ${selId === t.id ? 'selected' : ''}`} onClick={() => setSelId(t.id)}>
                    <td className="mono nowrap">{threatRef(data.threats, t)}</td>
                    <td><strong>{t.title}</strong><div className="small muted">{t.category}{t.tags.includes('not-in-latest-run') && <> · <Badge tone="warn">not in latest run</Badge></>}</div></td>
                    <td><Badge tone="navy">{t.methodology}</Badge></td>
                    <td className="nowrap"><RatingChip l={t.likelihood} i={t.impact} /></td>
                    <td><Badge tone={t.decision === 'accepted' ? 'ok' : t.decision === 'rejected' ? 'neutral' : 'warn'}>{t.decision}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </section>
        <aside className="card drawer">
          {sel ? <ThreatDetail key={sel.id} t={sel} onPromote={() => nav(`../risks?fromThreat=${sel.id}`)} /> : <Empty title="Select a threat" >Details, decision and evidence appear here.</Empty>}
        </aside>
      </div>

      {manual && <ManualThreatModal onClose={() => setManual(false)} />}
      {showRuns && (
        <Modal title="Analysis run history" wide onClose={() => setShowRuns(false)}>
          <table className="table"><thead><tr><th>When</th><th>By</th><th>Provider</th><th>Model</th><th>Methods</th><th>Confirmed</th><th>Hypotheses</th><th>Missing</th><th>Excluded</th></tr></thead><tbody>
            {[...data.runs].reverse().map((r) => <tr key={r.id}><td className="small nowrap">{fmtDate(r.at)}</td><td>{userName(r.by)}</td><td className="small">{r.provider} v{r.providerVersion}</td><td>v{r.modelVersion}</td><td>{r.methodologies.join(', ')}</td><td>{r.counts.confirmed}</td><td>{r.counts.hypothesis}</td><td>{r.counts.missing_evidence}</td><td>{r.skippedUnconfirmed}</td></tr>)}
          </tbody></table>
        </Modal>
      )}
    </div>
  );
}

function ThreatDetail({ t, onPromote }: { t: Threat; onPromote: () => void }) {
  const { data, can, mutate } = useProject();
  const { userName } = useAuth();
  const [notes, setNotes] = useState(t.analystNotes);
  const [refs, setRefs] = useState(t.evidenceRefs);
  const [l, setL] = useState(t.likelihood);
  const [i, setI] = useState(t.impact);
  const editable = can('threat:edit');
  const url = `/projects/${data.project.id}/threats/${t.id}`;
  const dirty = notes !== t.analystNotes || JSON.stringify(refs) !== JSON.stringify(t.evidenceRefs) || l !== t.likelihood || i !== t.impact;
  const names = new Map<string, string>([...data.model.components.map((c) => [c.id, c.name] as [string, string]), ...data.model.zones.map((z) => [z.id, z.name] as [string, string])]);
  for (const f of data.model.flows) names.set(f.id, `${names.get(f.from) ?? '?'} → ${names.get(f.to) ?? '?'}`);
  const linkedRisks = data.risks.filter((r) => r.threatIds.includes(t.id));

  return (
    <div className="card-body stack">
      <div className="row gap wrap"><Badge tone="navy">{t.methodology}</Badge><Badge tone={CLASS_INFO[t.classification].tone}>{CLASS_INFO[t.classification].label.replace(/s$/, '')}</Badge><span className="mono small muted right">{threatRef(data.threats, t)}</span></div>
      <h3>{t.title}</h3>
      <dl className="kv">
        <dt>Category</dt><dd>{t.category}</dd>
        <dt>Affected assets</dt><dd>{t.affectedAssets.join(', ')}</dd>
        <dt>Attack scenario</dt><dd>{t.attackScenario}</dd>
        <dt>Preconditions</dt><dd>{t.preconditions.length ? <ul className="list-plain">{t.preconditions.map((p) => <li key={p}>{p}</li>)}</ul> : '—'}</dd>
        <dt>Existing controls</dt><dd>{t.existingControls.length ? <ul className="list-plain">{t.existingControls.map((p) => <li key={p}>{p}</li>)}</ul> : 'None recorded'}</dd>
        <dt>Missing information</dt><dd>{t.missingInformation.length ? <ul className="list-plain">{t.missingInformation.map((p) => <li key={p}>{p}</li>)}</ul> : 'None'}</dd>
        <dt>Rating</dt><dd>L{t.likelihood} × I{t.impact} = <RatingChip l={t.likelihood} i={t.impact} /></dd>
        <dt>Mitigation</dt><dd>{t.mitigation}</dd>
        <dt>Rationale</dt><dd className="small">{t.rationale}</dd>
        <dt>Basis (model v{t.modelVersion})</dt><dd className="small">{t.basis.length ? <ul className="list-plain">{t.basis.map((b, k) => <li key={k}>{names.get(b.elementId) ?? b.elementKind}: <code>{b.fact}</code> = <strong>{b.value}</strong></li>)}</ul> : 'Analyst-authored'}</dd>
        <dt>Control tags</dt><dd>{t.tags.map((x) => <span key={x} className="chip" style={{ marginRight: 4 }}>{x}</span>)}</dd>
        <dt>Last updated</dt><dd className="small">{fmtDate(t.updatedAt)} by {userName(t.updatedBy)}</dd>
      </dl>

      {editable && (
        <div className="row gap wrap">
          <button className="btn btn-sm btn-teal" disabled={t.decision === 'accepted'} onClick={() => mutate(() => api.patch<ProjectData>(url, { decision: 'accepted' }), 'Threat accepted.')}><Check size={14} /> Accept</button>
          <button className="btn btn-sm btn-danger" disabled={t.decision === 'rejected'} onClick={() => mutate(() => api.patch<ProjectData>(url, { decision: 'rejected' }), 'Threat rejected.')}><X size={14} /> Reject</button>
          <button className="btn btn-sm" disabled={t.decision === 'proposed'} onClick={() => mutate(() => api.patch<ProjectData>(url, { decision: 'proposed' }))}><RotateCcw size={14} /> Reset</button>
          {can('risk:edit') && t.decision !== 'rejected' && t.classification !== 'missing_evidence' && <button className="btn btn-sm btn-primary" onClick={onPromote}><Gauge size={14} /> Register as risk</button>}
        </div>
      )}
      {linkedRisks.length > 0 && <div className="small">Linked risks: {linkedRisks.map((r) => <Link key={r.id} to="../risks" className="badge badge-teal" style={{ marginRight: 4 }}>{r.ref}</Link>)}</div>}

      <Field label="Analyst notes"><textarea value={notes} onChange={(e) => setNotes(e.target.value)} disabled={!editable} rows={3} /></Field>
      <Field label="Evidence references" hint={`Evidence IDs: ${data.evidence.map((e) => e.id.slice(0, 8)).join(', ') || 'none uploaded'} — or document/interview references`}>
        <TagInput value={refs} onChange={setRefs} disabled={!editable} placeholder="Add reference + Enter" />
      </Field>
      <div className="form-grid">
        <Field label="Likelihood"><select value={l} disabled={!editable} onChange={(e) => setL(Number(e.target.value))}>{[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n} {data.project.riskMatrix.likelihoodLabels[n - 1]}</option>)}</select></Field>
        <Field label="Impact"><select value={i} disabled={!editable} onChange={(e) => setI(Number(e.target.value))}>{[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n} {data.project.riskMatrix.impactLabels[n - 1]}</option>)}</select></Field>
      </div>
      {(l !== t.likelihood || i !== t.impact) && t.methodology !== 'MANUAL' && <p className="small muted">Changing the rating of a generated threat requires an analyst note.</p>}
      {editable && <div><button className="btn btn-primary btn-sm" disabled={!dirty} onClick={() => mutate(() => api.patch<ProjectData>(url, { analystNotes: notes, evidenceRefs: refs, likelihood: l, impact: i }), 'Threat updated.')}>Save changes</button></div>}
      {t.methodology === 'MANUAL' && editable && <button className="btn btn-sm btn-danger" onClick={() => mutate(() => api.del<ProjectData>(url), 'Threat deleted.')}>Delete analyst-authored threat</button>}
    </div>
  );
}

function ManualThreatModal({ onClose }: { onClose: () => void }) {
  const { data, mutate } = useProject();
  const [v, setV] = useState({ title: '', category: 'Spoofing', classification: 'hypothesis' as ThreatClass, affectedAssets: [] as string[], attackScenario: '', preconditions: [] as string[], existingControls: [] as string[], missingInformation: [] as string[], likelihood: 3, impact: 3, mitigation: '', tags: [] as string[], evidenceRefs: [] as string[] });
  const set = <K extends keyof typeof v>(k: K, val: (typeof v)[K]) => setV({ ...v, [k]: val });
  const save = async () => { if (await mutate(() => api.post<ProjectData>(`/projects/${data.project.id}/threats`, v), 'Threat added.')) onClose(); };
  return (
    <Modal title="Analyst-authored threat" wide onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={!v.title.trim()} onClick={save}>Add threat</button></>}>
      <Callout>Use for threats identified through interviews or document review that the rule engine cannot derive. A confirmed finding should cite evidence.</Callout>
      <div className="form-grid" style={{ marginTop: 12 }}>
        <Field label="Title *" full><input type="text" value={v.title} onChange={(e) => set('title', e.target.value)} /></Field>
        <Field label="Category"><select value={v.category} onChange={(e) => set('category', e.target.value)}>{['Spoofing', 'Tampering', 'Repudiation', 'Information disclosure', 'Denial of service', 'Elevation of privilege', 'Attack path', 'Area of concern', 'Other'].map((c) => <option key={c}>{c}</option>)}</select></Field>
        <Field label="Classification"><select value={v.classification} onChange={(e) => set('classification', e.target.value as ThreatClass)}><option value="confirmed">Confirmed finding</option><option value="hypothesis">Hypothesis</option><option value="missing_evidence">Missing evidence</option></select></Field>
        <Field label="Affected assets" full><TagInput value={v.affectedAssets} onChange={(x) => set('affectedAssets', x)} placeholder={data.model.components.slice(0, 2).map((c) => c.name).join(', ')} /></Field>
        <Field label="Attack scenario" full><textarea value={v.attackScenario} onChange={(e) => set('attackScenario', e.target.value)} /></Field>
        <Field label="Preconditions"><TagInput value={v.preconditions} onChange={(x) => set('preconditions', x)} /></Field>
        <Field label="Existing controls"><TagInput value={v.existingControls} onChange={(x) => set('existingControls', x)} /></Field>
        <Field label="Missing information"><TagInput value={v.missingInformation} onChange={(x) => set('missingInformation', x)} /></Field>
        <Field label="Evidence references"><TagInput value={v.evidenceRefs} onChange={(x) => set('evidenceRefs', x)} /></Field>
        <Field label="Likelihood (1–5)"><input type="number" min={1} max={5} value={v.likelihood} onChange={(e) => set('likelihood', Math.max(1, Math.min(5, Number(e.target.value))))} /></Field>
        <Field label="Impact (1–5)"><input type="number" min={1} max={5} value={v.impact} onChange={(e) => set('impact', Math.max(1, Math.min(5, Number(e.target.value))))} /></Field>
        <Field label="Mitigation" full><textarea value={v.mitigation} onChange={(e) => set('mitigation', e.target.value)} /></Field>
        <Field label="Control mapping tags" full hint="Used to map this threat to catalog controls.">
          <div className="row gap-s wrap">{CONTROL_TAGS.map((tg) => <label key={tg} className="chip" style={{ cursor: 'pointer', background: v.tags.includes(tg) ? 'var(--teal-100)' : undefined }}><input type="checkbox" hidden checked={v.tags.includes(tg)} onChange={() => set('tags', v.tags.includes(tg) ? v.tags.filter((x) => x !== tg) : [...v.tags, tg])} />{tg}</label>)}</div>
        </Field>
      </div>
    </Modal>
  );
}
