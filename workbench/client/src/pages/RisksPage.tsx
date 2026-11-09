import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Plus, Settings2, Trash2, CheckCircle2, MessageSquareWarning, Gauge } from 'lucide-react';
import { api, uid } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useProject } from '../lib/project';
import { Badge, Callout, Empty, Field, Modal, fmtDate, fmtDay } from '../components/ui';
import { riskBand, defaultRiskMatrix } from '@shared/schema';
import type { ProjectData, Risk, RiskMatrixConfig } from '@shared/types';
import { RatingChip, threatRef } from './ThreatsPage';

type RiskDraft = Omit<Risk, 'id' | 'ref' | 'approval' | 'createdBy' | 'createdAt' | 'updatedAt'>;

const emptyRisk = (): RiskDraft => ({ title: '', description: '', threatIds: [], likelihood: 3, impact: 3, residualLikelihood: 2, residualImpact: 3, owner: '', strategy: 'mitigate', status: 'open', targetDate: '', actions: [] });

export function RiskMatrix({ cfg, risks, residual, sel, onSelect }: { cfg: RiskMatrixConfig; risks: Risk[]; residual?: boolean; sel?: [number, number] | null; onSelect?: (c: [number, number] | null) => void }) {
  const cells = [];
  for (let l = 5; l >= 1; l--) {
    cells.push(<div key={`ly${l}`} className="axis">{l} · {cfg.likelihoodLabels[l - 1]}</div>);
    for (let i = 1; i <= 5; i++) {
      const b = riskBand(cfg, l, i);
      const n = risks.filter((r) => (residual ? r.residualLikelihood : r.likelihood) === l && (residual ? r.residualImpact : r.impact) === i).length;
      const isSel = sel && sel[0] === l && sel[1] === i;
      cells.push(
        <div key={`${l}-${i}`} className={`cell ${onSelect ? 'clickable' : ''} ${isSel ? 'sel' : ''}`} style={{ background: b.color, opacity: n ? 1 : 0.55 }} title={`${b.name} (score ${b.score})`}
          onClick={() => onSelect?.(isSel ? null : [l, i])}>{n || ''}</div>,
      );
    }
  }
  return (
    <div className="matrix" role="grid" aria-label="Risk matrix">
      {cells}
      <div />
      {cfg.impactLabels.map((x, i) => <div key={x + i} className="axis axis-x">{i + 1} · {x}</div>)}
    </div>
  );
}

export function RisksPage() {
  const { data, can, mutate } = useProject();
  const { userName } = useAuth();
  const [params, setParams] = useSearchParams();
  const [editing, setEditing] = useState<{ id?: string; v: RiskDraft } | null>(null);
  const [cfgOpen, setCfgOpen] = useState(false);
  const [residual, setResidual] = useState(false);
  const [cell, setCell] = useState<[number, number] | null>(null);
  const [approve, setApprove] = useState<Risk | null>(null);
  const cfg = data.project.riskMatrix;

  useEffect(() => {
    const tid = params.get('fromThreat');
    if (!tid) return;
    const t = data.threats.find((x) => x.id === tid);
    if (t) setEditing({ v: { ...emptyRisk(), title: t.title, description: t.attackScenario, threatIds: [t.id], likelihood: t.likelihood, impact: t.impact, residualLikelihood: Math.max(1, t.likelihood - 2), residualImpact: t.impact, actions: [{ id: uid('a'), description: t.mitigation, owner: '', dueDate: '', done: false }] } });
    setParams({}, { replace: true });
  }, []);

  const list = useMemo(() => data.risks.filter((r) => !cell || ((residual ? r.residualLikelihood : r.likelihood) === cell[0] && (residual ? r.residualImpact : r.impact) === cell[1]))
    .sort((a, b) => b.likelihood * b.impact - a.likelihood * a.impact), [data.risks, cell, residual]);

  const save = async () => {
    if (!editing) return;
    const url = editing.id ? `/projects/${data.project.id}/risks/${editing.id}` : `/projects/${data.project.id}/risks`;
    const ok = await mutate(() => (editing.id ? api.patch<ProjectData>(url, editing.v) : api.post<ProjectData>(url, editing.v)), editing.id ? 'Risk updated.' : 'Risk registered (pending reviewer approval).');
    if (ok) setEditing(null);
  };

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Risk register</h1><div className="sub">Configurable 5×5 likelihood × impact matrix with ownership, treatment, target dates and reviewer approval. The person who registers a risk cannot approve it.</div></div>
        <div className="actions">
          {can('risk:approve') && <button className="btn" onClick={() => setCfgOpen(true)}><Settings2 size={16} /> Matrix settings</button>}
          {can('risk:edit') && <button className="btn btn-primary" onClick={() => setEditing({ v: emptyRisk() })}><Plus size={16} /> New risk</button>}
        </div>
      </div>

      <div className="grid risk-grid">
        <section className="card">
          <div className="card-head"><h2>Heatmap</h2><div className="seg right"><button className={!residual ? 'on' : ''} onClick={() => setResidual(false)}>Inherent</button><button className={residual ? 'on' : ''} onClick={() => setResidual(true)}>Residual</button></div></div>
          <div className="card-body">
            <RiskMatrix cfg={cfg} risks={data.risks} residual={residual} sel={cell} onSelect={setCell} />
            <div className="row gap wrap small" style={{ marginTop: 10 }}>{[...cfg.bands].sort((a, b) => a.min - b.min).map((b) => <span key={b.name} className="row gap-s"><span style={{ width: 12, height: 12, borderRadius: 3, background: b.color }} />{b.name} ≥ {b.min}</span>)}</div>
            {cell && <p className="small muted">Filtered to L{cell[0]} × I{cell[1]}. <button className="btn btn-sm" onClick={() => setCell(null)}>Clear</button></p>}
          </div>
        </section>
        <section className="card">
          <div className="card-head"><h2>Risks</h2><span className="small muted right">{list.length} of {data.risks.length}</span></div>
          {list.length === 0 ? <Empty icon={<Gauge size={32} />} title="No risks">Register risks from accepted threats in the threat model, or create one here.</Empty> : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Ref</th><th>Risk</th><th>Owner</th><th>Inherent</th><th>Residual</th><th>Treatment</th><th>Target</th><th>Approval</th><th /></tr></thead>
              <tbody>
                {list.map((r) => {
                  const overdue = r.targetDate && r.targetDate < new Date().toISOString().slice(0, 10) && r.status !== 'closed';
                  return (
                    <tr key={r.id}>
                      <td className="mono">{r.ref}</td>
                      <td><button className="btn-link" style={{ background: 'none', border: 0, padding: 0, color: 'var(--navy-700)', fontWeight: 600, cursor: 'pointer', textAlign: 'left' }} onClick={() => setEditing({ id: r.id, v: { title: r.title, description: r.description, threatIds: r.threatIds, likelihood: r.likelihood, impact: r.impact, residualLikelihood: r.residualLikelihood, residualImpact: r.residualImpact, owner: r.owner, strategy: r.strategy, status: r.status, targetDate: r.targetDate, actions: r.actions } })}>{r.title}</button>
                        <div className="small muted">{r.actions.filter((a) => a.done).length}/{r.actions.length} actions done</div></td>
                      <td>{r.owner || <Badge tone="warn">unassigned</Badge>}</td>
                      <td className="nowrap"><RatingChip l={r.likelihood} i={r.impact} /></td>
                      <td className="nowrap"><RatingChip l={r.residualLikelihood} i={r.residualImpact} /></td>
                      <td className="small">{r.strategy}<div className="muted">{r.status.replace('_', ' ')}</div></td>
                      <td className="nowrap">{overdue ? <Badge tone="danger">{fmtDay(r.targetDate)}</Badge> : fmtDay(r.targetDate)}</td>
                      <td>
                        <Badge tone={r.approval.state === 'approved' ? 'ok' : r.approval.state === 'changes_requested' ? 'danger' : 'warn'}>{r.approval.state.replace('_', ' ')}</Badge>
                        {r.approval.by && <div className="small muted">{userName(r.approval.by)}</div>}
                      </td>
                      <td className="nowrap">{can('risk:approve') && <button className="btn btn-sm" onClick={() => setApprove(r)}>Review</button>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table></div>
          )}
        </section>
      </div>

      {editing && <RiskEditor editing={editing} setEditing={setEditing} onSave={save} />}
      {cfgOpen && <MatrixSettings onClose={() => setCfgOpen(false)} />}
      {approve && <ApprovalModal risk={approve} onClose={() => setApprove(null)} />}
    </div>
  );
}

function RiskEditor({ editing, setEditing, onSave }: { editing: { id?: string; v: RiskDraft }; setEditing: (e: { id?: string; v: RiskDraft } | null) => void; onSave: () => void }) {
    const { data, can, mutate } = useProject();
    const { userName } = useAuth();
    const cfg = data.project.riskMatrix;
    const v = editing.v;
    const set = <K extends keyof RiskDraft>(k: K, val: RiskDraft[K]) => setEditing({ ...editing, v: { ...v, [k]: val } });
    const editable = can('risk:edit');
    const risk = data.risks.find((r) => r.id === editing.id);
    const candidates = data.threats.filter((t) => t.decision !== 'rejected');
    const lsel = (k: 'likelihood' | 'residualLikelihood') => <select value={v[k]} disabled={!editable} onChange={(e) => set(k, Number(e.target.value))}>{[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n} {cfg.likelihoodLabels[n - 1]}</option>)}</select>;
    const isel = (k: 'impact' | 'residualImpact') => <select value={v[k]} disabled={!editable} onChange={(e) => set(k, Number(e.target.value))}>{[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n} {cfg.impactLabels[n - 1]}</option>)}</select>;
    return (
      <Modal title={editing.id ? `Edit ${risk?.ref}` : 'Register risk'} wide onClose={() => setEditing(null)} footer={<>
        {editing.id && editable && <button className="btn btn-danger" style={{ marginRight: 'auto' }} onClick={async () => { if (await mutate(() => api.del<ProjectData>(`/projects/${data.project.id}/risks/${editing.id}`), 'Risk removed.')) setEditing(null); }}><Trash2 size={14} /> Remove</button>}
        <button className="btn" onClick={() => setEditing(null)}>Cancel</button>
        {editable && <button className="btn btn-primary" disabled={!v.title.trim()} onClick={onSave}>Save risk</button>}
      </>}>
        {risk?.approval.state === 'approved' && <Callout tone="info">Approved by {userName(risk.approval.by)} on {fmtDate(risk.approval.at)}. Changing rating, owner, treatment or target date returns it to pending approval.</Callout>}
        {risk?.approval.state === 'changes_requested' && <Callout tone="warn">Changes requested: {risk.approval.comment}</Callout>}
        <div className="form-grid" style={{ marginTop: 10 }}>
          <Field label="Title *" full><input type="text" value={v.title} disabled={!editable} onChange={(e) => set('title', e.target.value)} maxLength={200} /></Field>
          <Field label="Description" full><textarea value={v.description} disabled={!editable} onChange={(e) => set('description', e.target.value)} /></Field>
          <Field label="Linked threats" full>
            <select multiple value={v.threatIds} disabled={!editable} onChange={(e) => set('threatIds', Array.from(e.target.selectedOptions).map((o) => o.value))} style={{ height: 110 }}>
              {candidates.map((t) => <option key={t.id} value={t.id}>{threatRef(data.threats, t)} · {t.title}</option>)}
            </select>
          </Field>
          <Field label="Inherent likelihood">{lsel('likelihood')}</Field>
          <Field label="Inherent impact">{isel('impact')}</Field>
          <Field label="Residual likelihood (target)">{lsel('residualLikelihood')}</Field>
          <Field label="Residual impact (target)">{isel('residualImpact')}</Field>
          <div className="small">Inherent: <RatingChip l={v.likelihood} i={v.impact} /> → Residual: <RatingChip l={v.residualLikelihood} i={v.residualImpact} /></div><div />
          <Field label="Risk owner" hint="Accountable person or role at the client (required for approval)."><input type="text" value={v.owner} disabled={!editable} onChange={(e) => set('owner', e.target.value)} maxLength={120} /></Field>
          <Field label="Target date"><input type="date" value={v.targetDate} disabled={!editable} onChange={(e) => set('targetDate', e.target.value)} /></Field>
          <Field label="Treatment strategy"><select value={v.strategy} disabled={!editable} onChange={(e) => set('strategy', e.target.value as Risk['strategy'])}><option value="mitigate">Mitigate</option><option value="accept">Accept</option><option value="transfer">Transfer</option><option value="avoid">Avoid</option></select></Field>
          <Field label="Treatment status"><select value={v.status} disabled={!editable} onChange={(e) => set('status', e.target.value as Risk['status'])}><option value="open">Open</option><option value="in_progress">In progress</option><option value="implemented">Implemented</option><option value="closed">Closed</option></select></Field>
        </div>
        <div style={{ marginTop: 14 }}>
          <div className="row gap"><div className="field-label grow">Mitigation actions</div>{editable && <button className="btn btn-sm" onClick={() => set('actions', [...v.actions, { id: uid('a'), description: '', owner: '', dueDate: '', done: false }])}><Plus size={14} /> Add action</button>}</div>
          {v.actions.length === 0 ? <p className="small muted">No actions defined.</p> : (
            <table className="table"><thead><tr><th>Done</th><th>Action</th><th>Owner</th><th>Due</th><th /></tr></thead><tbody>
              {v.actions.map((a, idx) => {
                const upd = (patch: Partial<typeof a>) => set('actions', v.actions.map((x, j) => (j === idx ? { ...x, ...patch } : x)));
                return (
                  <tr key={a.id}>
                    <td><input type="checkbox" checked={a.done} disabled={!editable} onChange={(e) => upd({ done: e.target.checked })} /></td>
                    <td><textarea rows={2} value={a.description} disabled={!editable} onChange={(e) => upd({ description: e.target.value })} style={{ minHeight: 40 }} /></td>
                    <td style={{ width: 150 }}><input type="text" value={a.owner} disabled={!editable} onChange={(e) => upd({ owner: e.target.value })} /></td>
                    <td style={{ width: 150 }}><input type="date" value={a.dueDate} disabled={!editable} onChange={(e) => upd({ dueDate: e.target.value })} /></td>
                    <td>{editable && <button className="icon-btn" onClick={() => set('actions', v.actions.filter((_, j) => j !== idx))} aria-label="Remove action"><Trash2 size={14} /></button>}</td>
                  </tr>
                );
              })}
            </tbody></table>
          )}
        </div>
      </Modal>
    );
  }

function ApprovalModal({ risk, onClose }: { risk: Risk; onClose: () => void }) {
    const { data, mutate } = useProject();
    const { userName } = useAuth();
    const [comment, setComment] = useState('');
    const decide = async (decision: 'approve' | 'request_changes') => {
      if (await mutate(() => api.post<ProjectData>(`/projects/${data.project.id}/risks/${risk.id}/approval`, { decision, comment }), decision === 'approve' ? 'Risk approved.' : 'Changes requested.')) onClose();
    };
    return (
      <Modal title={`Reviewer approval — ${risk.ref}`} onClose={onClose} footer={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-danger" onClick={() => decide('request_changes')}><MessageSquareWarning size={14} /> Request changes</button>
        <button className="btn btn-teal" onClick={() => decide('approve')}><CheckCircle2 size={14} /> Approve</button>
      </>}>
        <dl className="kv">
          <dt>Risk</dt><dd>{risk.title}</dd>
          <dt>Owner</dt><dd>{risk.owner || <Badge tone="warn">unassigned — required for approval</Badge>}</dd>
          <dt>Inherent → residual</dt><dd><RatingChip l={risk.likelihood} i={risk.impact} /> → <RatingChip l={risk.residualLikelihood} i={risk.residualImpact} /></dd>
          <dt>Treatment</dt><dd>{risk.strategy} · {risk.status.replace('_', ' ')} · target {fmtDay(risk.targetDate)}</dd>
          <dt>Registered by</dt><dd>{userName(risk.createdBy)} on {fmtDate(risk.createdAt)}</dd>
        </dl>
        <Field label="Comment" hint="Required when requesting changes."><textarea value={comment} onChange={(e) => setComment(e.target.value)} /></Field>
      </Modal>
    );
  }

function MatrixSettings({ onClose }: { onClose: () => void }) {
    const { data, mutate } = useProject();
    const cfg = data.project.riskMatrix;
    const [m, setM] = useState<RiskMatrixConfig>(JSON.parse(JSON.stringify(cfg)));
    const save = async () => { if (await mutate(() => api.patch<ProjectData>(`/projects/${data.project.id}`, { riskMatrix: m }), 'Risk matrix updated.')) onClose(); };
    return (
      <Modal title="Risk matrix settings" wide onClose={onClose} footer={<><button className="btn" style={{ marginRight: 'auto' }} onClick={() => setM(defaultRiskMatrix())}>Reset to default</button><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" onClick={save}>Save matrix</button></>}>
        <div className="grid grid-2">
          <div className="stack">
            <div className="field-label">Likelihood labels (1 → 5)</div>
            {m.likelihoodLabels.map((l, i) => <input key={i} type="text" value={l} onChange={(e) => { const x = [...m.likelihoodLabels] as RiskMatrixConfig['likelihoodLabels']; x[i] = e.target.value; setM({ ...m, likelihoodLabels: x }); }} />)}
            <div className="field-label">Impact labels (1 → 5)</div>
            {m.impactLabels.map((l, i) => <input key={i} type="text" value={l} onChange={(e) => { const x = [...m.impactLabels] as RiskMatrixConfig['impactLabels']; x[i] = e.target.value; setM({ ...m, impactLabels: x }); }} />)}
          </div>
          <div className="stack">
            <div className="row gap"><div className="field-label grow">Rating bands (score = L × I)</div><button className="btn btn-sm" disabled={m.bands.length >= 6} onClick={() => setM({ ...m, bands: [...m.bands, { name: 'New band', min: 25, color: '#7a5c99' }] })}><Plus size={14} /> Band</button></div>
            {m.bands.map((b, i) => (
              <div key={i} className="row gap">
                <input type="text" value={b.name} onChange={(e) => setM({ ...m, bands: m.bands.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) })} />
                <input type="number" min={1} max={25} value={b.min} style={{ width: 80 }} onChange={(e) => setM({ ...m, bands: m.bands.map((x, j) => (j === i ? { ...x, min: Number(e.target.value) } : x)) })} />
                <input type="color" value={b.color} onChange={(e) => setM({ ...m, bands: m.bands.map((x, j) => (j === i ? { ...x, color: e.target.value } : x)) })} />
                <button className="icon-btn" disabled={m.bands.length <= 2} onClick={() => setM({ ...m, bands: m.bands.filter((_, j) => j !== i) })}><Trash2 size={14} /></button>
              </div>
            ))}
            <p className="small muted">Each band applies from its minimum score upwards. One band must start at 1.</p>
            <RiskMatrix cfg={m} risks={data.risks} />
          </div>
        </div>
      </Modal>
    );
  }
