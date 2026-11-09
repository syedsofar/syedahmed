import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Plus, Copy, Trash2, FolderKanban, Search } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Badge, Empty, Modal, fmtDate, fmtDay, useToast } from '../components/ui';
import { ProjectForm, emptyProjectForm, type ProjectFormValue } from '../components/ProjectForm';
import { STATUS_LABELS } from '@shared/schema';
import type { ProjectData } from '@shared/types';
import { STATUS_TONE, type ProjectSummary } from './DashboardPage';

export function ProjectsPage() {
  const [list, setList] = useState<ProjectSummary[] | null>(null);
  const [params, setParams] = useSearchParams();
  const [form, setForm] = useState<ProjectFormValue>(emptyProjectForm());
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('active');
  const [confirmDelete, setConfirmDelete] = useState<ProjectSummary | null>(null);
  const { can, userName } = useAuth();
  const toast = useToast();
  const nav = useNavigate();
  const creating = params.get('new') === '1';

  const load = () => api.get<ProjectSummary[]>('/projects').then(setList).catch(toast.error);
  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => (list ?? []).filter((p) => {
    if (status === 'active' && p.status === 'archived') return false;
    if (status !== 'active' && status !== 'all' && p.status !== status) return false;
    const s = q.toLowerCase();
    return !s || p.name.toLowerCase().includes(s) || p.clientAlias.toLowerCase().includes(s);
  }).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)), [list, q, status]);

  const create = async () => {
    if (!form.name.trim() || !form.clientAlias.trim()) return toast.error('Assessment name and client alias are required.');
    try {
      const d = await api.post<ProjectData>('/projects', form);
      toast.ok('Assessment created as a draft.');
      setParams({});
      nav(`/projects/${d.project.id}/architecture`);
    } catch (e) { toast.error(e); }
  };
  const clone = async (p: ProjectSummary) => {
    try {
      const d = await api.post<ProjectData>(`/projects/${p.id}/clone`);
      toast.ok('Draft copy created.');
      nav(`/projects/${d.project.id}`);
    } catch (e) { toast.error(e); }
  };
  const remove = async () => {
    if (!confirmDelete) return;
    try {
      await api.del(`/projects/${confirmDelete.id}`);
      toast.ok('Assessment deleted.');
      setConfirmDelete(null);
      load();
    } catch (e) { toast.error(e); }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Assessments</h1><div className="sub">Projects, draft assessments and their history. Drafts can be created from any existing assessment.</div></div>
        <div className="actions">{can('project:create') && <button className="btn btn-primary" onClick={() => { setForm(emptyProjectForm()); setParams({ new: '1' }); }}><Plus size={16} /> New assessment</button>}</div>
      </div>

      <div className="card">
        <div className="card-head">
          <div className="row gap" style={{ flex: 1, minWidth: 220, maxWidth: 360 }}><Search size={16} className="muted" /><input type="search" placeholder="Search name or client alias" value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <div className="seg right" role="tablist">
            {[['active', 'Active'], ['draft', 'Drafts'], ['in_review', 'In review'], ['pending_approval', 'Pending'], ['final', 'Final'], ['archived', 'Archived'], ['all', 'All']].map(([k, l]) => (
              <button key={k} className={status === k ? 'on' : ''} onClick={() => setStatus(k)}>{l}</button>
            ))}
          </div>
        </div>
        {!list ? <div className="loading">Loading…</div> : filtered.length === 0 ? <Empty icon={<FolderKanban size={36} />} title="No assessments match">Adjust the filter or create a new assessment.</Empty> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Assessment</th><th>Client alias</th><th>Status</th><th>Arch. version</th><th>Reviewer</th><th>Review date</th><th>Model</th><th>Updated</th><th /></tr></thead>
              <tbody>
                {filtered.map((p) => (
                  <tr key={p.id}>
                    <td><Link to={`/projects/${p.id}`}><strong>{p.name}</strong></Link> {p.isDemo && <Badge tone="demo">DEMO DATA</Badge>}<div className="muted small">Your role: {p.myRole}</div></td>
                    <td>{p.clientAlias}</td>
                    <td><Badge tone={STATUS_TONE[p.status]}>{STATUS_LABELS[p.status]}</Badge></td>
                    <td>{p.architectureVersion || '—'}</td>
                    <td>{userName(p.reviewerId)}</td>
                    <td className="nowrap">{fmtDay(p.reviewDate)}</td>
                    <td className="nowrap">{p.latestVersion ? `v${p.latestVersion}` : 'no version'}</td>
                    <td className="nowrap small muted">{fmtDate(p.updatedAt)}</td>
                    <td className="nowrap">
                      {can('project:create') && <button className="icon-btn" title="Create draft copy" onClick={() => clone(p)}><Copy size={16} /></button>}
                      {(p.myRole === 'owner' || p.myRole === 'admin') && can('project:delete') && <button className="icon-btn" title="Delete" onClick={() => setConfirmDelete(p)}><Trash2 size={16} /></button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {creating && (
        <Modal title="New assessment" onClose={() => setParams({})} wide footer={<><button className="btn" onClick={() => setParams({})}>Cancel</button><button className="btn btn-primary" onClick={create}>Create draft</button></>}>
          <ProjectForm value={form} onChange={setForm} />
        </Modal>
      )}
      {confirmDelete && (
        <Modal title="Delete assessment" onClose={() => setConfirmDelete(null)} footer={<><button className="btn" onClick={() => setConfirmDelete(null)}>Cancel</button><button className="btn btn-danger" onClick={remove}><Trash2 size={14} /> Delete permanently</button></>}>
          <p>Delete <strong>{confirmDelete.name}</strong>, its model versions, threats, risks and encrypted evidence files? This cannot be undone. The deletion is recorded in the audit trail.</p>
          <p className="muted small">Consider setting the status to Archived instead to keep the record.</p>
        </Modal>
      )}
    </div>
  );
}
