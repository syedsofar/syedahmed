import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ListChecks } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useProject } from '../lib/project';
import { useCatalogs } from '../components/ProjectForm';
import { Badge, Callout, Empty, Field, TagInput, fmtDate } from '../components/ui';
import { FRAMEWORK_LABELS, REVIEW_STATUS_LABELS, canSetStatus, mapThreatsToControls, suggestedStatus, type ControlMapping } from '@shared/controls';
import type { ControlReview, ProjectData } from '@shared/types';
import { threatRef } from './ThreatsPage';

const STATUS_TONE: Record<ControlReview['status'], string> = { not_assessed: 'neutral', information_missing: 'warn', gap_identified: 'danger', evidence_satisfied: 'ok', not_applicable: 'sage' };

export function ControlsPage() {
  const { data } = useProject();
  const catalogs = useCatalogs();
  const selected = catalogs.filter((c) => data.project.catalogIds.includes(c.id));
  const [catId, setCatId] = useState('');
  const [filter, setFilter] = useState('all');
  const [ctl, setCtl] = useState<string | null>(null);
  useEffect(() => { if (!catId && selected.length) setCatId(selected[0].id); }, [selected.length]);
  const cat = selected.find((c) => c.id === catId);
  const maps = useMemo(() => (cat ? mapThreatsToControls(cat, data.threats) : []), [cat, data.threats]);
  const review = (id: string) => data.controlReviews.find((r) => r.catalogId === catId && r.controlId === id);
  const rows = maps.filter((m) => {
    const st = review(m.control.id)?.status ?? 'not_assessed';
    if (filter === 'all') return true;
    if (filter === 'relevant') return m.confirmed.length + m.hypotheses.length + m.missing.length > 0;
    return st === filter;
  });
  const active = maps.find((m) => m.control.id === ctl);

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Security control review</h1><div className="sub">Findings are mapped to controls by topic so reviewers can see what is relevant. Mapping identifies relevance only — it never establishes compliance.</div></div>
      </div>
      <Callout>Compliance is <strong>not inferred from architecture diagrams</strong>. A control can be marked “Evidence reviewed — satisfied” only with at least one evidence reference. Only approved, versioned catalog content is used.</Callout>

      {selected.length === 0 ? (
        <div className="card" style={{ marginTop: 16 }}><Empty icon={<ListChecks size={32} />} title="No control catalogs selected">Select approved catalogs in the <Link to="..">assessment details</Link>.</Empty></div>
      ) : (
        <>
          <div className="row gap wrap" style={{ margin: '16px 0 12px' }}>
            <div className="seg">{selected.map((c) => <button key={c.id} className={catId === c.id ? 'on' : ''} onClick={() => { setCatId(c.id); setCtl(null); }}>{c.framework.replace('_', ' ')}</button>)}</div>
            <select value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 230 }}>
              <option value="all">All controls</option><option value="relevant">With mapped findings</option>
              {Object.entries(REVIEW_STATUS_LABELS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
          </div>
          {cat && (
            <div className="small muted" style={{ marginBottom: 10 }}>
              {FRAMEWORK_LABELS[cat.framework]} — version <strong>{cat.version}</strong> · status <Badge tone={cat.status === 'approved' ? 'ok' : 'danger'}>{cat.status}</Badge> {cat.isDemo && <Badge tone="demo">demonstration excerpt</Badge>} · content hash <code>{cat.contentHash.slice(0, 12)}</code>
              {cat.status !== 'approved' && <Callout tone="danger">This catalog version is no longer approved. Existing reviews are retained but no new reviews can be recorded.</Callout>}
            </div>
          )}
          <div className="split">
            <section className="card">
              <div className="table-wrap"><table className="table">
                <thead><tr><th>Control</th><th>Title</th><th title="Confirmed / hypotheses / missing evidence">Mapped</th><th>Suggested</th><th>Review status</th></tr></thead>
                <tbody>
                  {rows.map((m) => {
                    const r = review(m.control.id);
                    const sug = suggestedStatus(m);
                    return (
                      <tr key={m.control.id} className={`clickable ${ctl === m.control.id ? 'selected' : ''}`} onClick={() => setCtl(m.control.id)}>
                        <td className="mono nowrap">{m.control.id}</td>
                        <td><strong>{m.control.title}</strong><div className="small muted">{m.control.domain}</div></td>
                        <td className="nowrap"><Badge tone="danger">{m.confirmed.length}</Badge> <Badge tone="teal">{m.hypotheses.length}</Badge> <Badge tone="warn">{m.missing.length}</Badge></td>
                        <td>{sug !== 'not_assessed' ? <Badge tone={STATUS_TONE[sug]}>{REVIEW_STATUS_LABELS[sug]}</Badge> : <span className="muted small">—</span>}</td>
                        <td><Badge tone={STATUS_TONE[r?.status ?? 'not_assessed']}>{REVIEW_STATUS_LABELS[r?.status ?? 'not_assessed']}</Badge></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table></div>
            </section>
            <aside className="card drawer">
              {active && cat ? <ControlEditor key={`${cat.id}:${active.control.id}`} catalogId={cat.id} approved={cat.status === 'approved'} m={active} review={review(active.control.id)} /> : <Empty title="Select a control">Mapped findings and the review record appear here.</Empty>}
            </aside>
          </div>
        </>
      )}
    </div>
  );
}

function ControlEditor({ catalogId, approved, m, review }: { catalogId: string; approved: boolean; m: ControlMapping; review?: ControlReview }) {
  const { data, can, mutate } = useProject();
  const { userName } = useAuth();
  const [status, setStatus] = useState<ControlReview['status']>(review?.status ?? suggestedStatus(m));
  const [notes, setNotes] = useState(review?.notes ?? '');
  const [refs, setRefs] = useState<string[]>(review?.evidenceRefs ?? []);
  const problem = canSetStatus(status, refs, notes);
  const editable = can('control:edit') && approved;
  const group = (label: string, list: typeof m.confirmed, tone: string) => list.length > 0 && (
    <div><div className="field-label">{label}</div><ul className="list-plain small">{list.map((t) => <li key={t.id}><Badge tone={tone}>{threatRef(data.threats, t)}</Badge> {t.title}{t.decision === 'proposed' && <span className="muted"> (pending review)</span>}</li>)}</ul></div>
  );
  const missingInfo = Array.from(new Set(m.missing.flatMap((t) => t.missingInformation)));

  return (
    <div className="card-body stack">
      <div><span className="mono muted">{m.control.id}</span><h3>{m.control.title}</h3><div className="small muted">{m.control.domain} · tags: {m.control.tags.join(', ')}</div></div>
      {group('Confirmed findings', m.confirmed, 'danger')}
      {group('Hypotheses to validate', m.hypotheses, 'teal')}
      {missingInfo.length > 0 && <div><div className="field-label">Missing information flagged</div><ul className="list-plain small">{missingInfo.slice(0, 12).map((x) => <li key={x}>{x}</li>)}</ul>{missingInfo.length > 12 && <div className="small muted">…and {missingInfo.length - 12} more</div>}</div>}
      {m.confirmed.length + m.hypotheses.length + m.missing.length === 0 && <p className="small muted">No generated findings map to this control. That does not mean it is satisfied — assess it from evidence or mark not applicable with justification.</p>}
      <Field label="Review status">
        <select value={status} disabled={!editable} onChange={(e) => setStatus(e.target.value as ControlReview['status'])}>
          {Object.entries(REVIEW_STATUS_LABELS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
      </Field>
      <Field label="Reviewer notes"><textarea value={notes} disabled={!editable} onChange={(e) => setNotes(e.target.value)} rows={3} /></Field>
      <Field label="Evidence references" hint="Policy documents, configuration exports, interview notes or evidence IDs."><TagInput value={refs} onChange={setRefs} disabled={!editable} placeholder="Add reference + Enter" /></Field>
      {problem && <Callout tone="warn">{problem}</Callout>}
      {editable && <div><button className="btn btn-primary btn-sm" disabled={!!problem} onClick={() => mutate(() => api.put<ProjectData>(`/projects/${data.project.id}/controls/${catalogId}/${encodeURIComponent(m.control.id)}`, { status, notes, evidenceRefs: refs }), 'Control review saved.')}>Save review</button></div>}
      {review?.updatedAt && <div className="small muted">Last reviewed {fmtDate(review.updatedAt)} by {userName(review.updatedBy)}</div>}
    </div>
  );
}
