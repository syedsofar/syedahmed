import { useEffect, useState } from 'react';
import { BookMarked, Upload, CheckCircle2, Archive } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Badge, Callout, Empty, Modal, fmtDate, useToast } from '../components/ui';
import { CONTROL_TAGS, FRAMEWORK_LABELS, validateCatalogImport } from '@shared/controls';
import type { ControlCatalog } from '@shared/types';

const EXAMPLE = `{
  "framework": "NIST_CSF",
  "name": "NIST CSF",
  "version": "2.0 (firm-approved 2026-01)",
  "source": "Official publication reference, approval record ID",
  "controls": [
    { "id": "PR.AA-01", "domain": "Protect", "title": "…", "tags": ["identity", "authentication"] }
  ]
}`;

export function CatalogsPage() {
  const [cats, setCats] = useState<ControlCatalog[] | null>(null);
  const [view, setView] = useState<ControlCatalog | null>(null);
  const [importing, setImporting] = useState<{ text: string; errors: string[] } | null>(null);
  const { can, userName, session } = useAuth();
  const toast = useToast();
  const load = () => api.get<ControlCatalog[]>('/catalogs').then(setCats).catch(toast.error);
  useEffect(() => { load(); }, []);

  const submit = async () => {
    if (!importing) return;
    let parsed: unknown;
    try { parsed = JSON.parse(importing.text); } catch { return setImporting({ ...importing, errors: ['Invalid JSON.'] }); }
    const v = validateCatalogImport(parsed);
    if (!v.ok) return setImporting({ ...importing, errors: v.errors });
    try { await api.post('/catalogs', parsed); toast.ok('Catalog imported as DRAFT. A different reviewer must approve it before use.'); setImporting(null); load(); } catch (e) { toast.error(e); }
  };
  const act = async (c: ControlCatalog, a: 'approve' | 'retire') => {
    try { await api.post(`/catalogs/${c.id}/${a}`); toast.ok(a === 'approve' ? 'Catalog version approved.' : 'Catalog version retired.'); load(); } catch (e) { toast.error(e); }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Control catalogs</h1><div className="sub">Versioned control content for NCA ECC, SAMA CSF, NIST CSF and ISO/IEC 27001. Catalogs are imported as drafts, approved by a different reviewer (segregation of duties), and only approved versions can be used in assessments.</div></div>
        <div className="actions">{can('catalog:import') && <button className="btn btn-primary" onClick={() => setImporting({ text: '', errors: [] })}><Upload size={16} /> Import catalog version</button>}</div>
      </div>
      <Callout tone="warn">Demonstration excerpts are short, paraphrased, domain-level references for exercising the workflow. They are not authoritative control text. Import the official, firm-approved catalog content before any client use.</Callout>

      <section className="card" style={{ marginTop: 16 }}>
        {!cats ? <div className="loading">Loading…</div> : cats.length === 0 ? <Empty icon={<BookMarked size={32} />} title="No catalogs" /> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Framework</th><th>Version</th><th>Controls</th><th>Status</th><th>Imported</th><th>Approved</th><th>Hash</th><th /></tr></thead>
            <tbody>
              {cats.map((c) => (
                <tr key={c.id}>
                  <td><strong>{FRAMEWORK_LABELS[c.framework]}</strong> {c.isDemo && <Badge tone="demo">demo excerpt</Badge>}</td>
                  <td>{c.version}</td>
                  <td>{c.controls.length}</td>
                  <td><Badge tone={c.status === 'approved' ? 'ok' : c.status === 'draft' ? 'warn' : 'neutral'}>{c.status}</Badge></td>
                  <td className="small">{userName(c.importedBy)}<br />{fmtDate(c.importedAt)}</td>
                  <td className="small">{c.approvedBy ? <>{userName(c.approvedBy)}<br />{fmtDate(c.approvedAt)}</> : '—'}</td>
                  <td className="mono">{c.contentHash.slice(0, 10)}</td>
                  <td className="nowrap">
                    <button className="btn btn-sm" onClick={() => setView(c)}>View</button>{' '}
                    {c.status === 'draft' && can('catalog:approve') && <button className="btn btn-sm btn-teal" disabled={c.importedBy === session?.user.id} title={c.importedBy === session?.user.id ? 'The importer cannot approve the same version' : ''} onClick={() => act(c, 'approve')}><CheckCircle2 size={14} /> Approve</button>}{' '}
                    {c.status !== 'retired' && can('catalog:import') && <button className="btn btn-sm" onClick={() => act(c, 'retire')}><Archive size={14} /> Retire</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </section>

      {view && (
        <Modal title={`${FRAMEWORK_LABELS[view.framework]} — ${view.version}`} wide onClose={() => setView(null)}>
          <p className="small muted">{view.source}</p>
          <table className="table"><thead><tr><th>ID</th><th>Domain</th><th>Title</th><th>Mapping tags</th></tr></thead><tbody>
            {view.controls.map((c) => <tr key={c.id}><td className="mono">{c.id}</td><td className="small">{c.domain}</td><td>{c.title}</td><td>{c.tags.map((t) => <span key={t} className="chip" style={{ marginRight: 3 }}>{t}</span>)}</td></tr>)}
          </tbody></table>
        </Modal>
      )}
      {importing && (
        <Modal title="Import catalog version (JSON)" wide onClose={() => setImporting(null)} footer={<><button className="btn" onClick={() => setImporting(null)}>Cancel</button><button className="btn btn-primary" onClick={submit}>Validate &amp; import as draft</button></>}>
          <div className="stack">
            <label className="btn" style={{ alignSelf: 'flex-start' }}><Upload size={14} /> Load JSON file<input type="file" accept=".json,application/json" hidden onChange={async (e) => { const f = e.target.files?.[0]; if (f) setImporting({ text: await f.text(), errors: [] }); }} /></label>
            <textarea rows={14} className="mono" value={importing.text} placeholder={EXAMPLE} onChange={(e) => setImporting({ text: e.target.value, errors: [] })} />
            {importing.errors.length > 0 && <Callout tone="danger"><ul className="list-plain">{importing.errors.map((x) => <li key={x}>{x}</li>)}</ul></Callout>}
            <p className="small muted">Allowed mapping tags: {CONTROL_TAGS.join(', ')}.</p>
          </div>
        </Modal>
      )}
    </div>
  );
}
