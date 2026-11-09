import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FolderKanban, Plus, AlertTriangle, Activity } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Badge, Empty, Stat, fmtDate, fmtDay, useToast } from '../components/ui';
import { STATUS_LABELS } from '@shared/schema';
import type { AuditEntry, Project } from '@shared/types';

export interface ProjectSummary extends Project {
  myRole: string | null;
  latestVersion: number;
  counts: { components: number; confirmed: number; hypothesis: number; missing_evidence: number; risks: number; risksPendingApproval: number; highRisks: number };
}

interface Dashboard {
  projects: ProjectSummary[];
  riskBands: Record<string, { count: number; color: string }>;
  overdue: { projectId: string; project: string; risk: string; action: string; dueDate: string }[];
  recent: AuditEntry[];
}

export const STATUS_TONE: Record<string, string> = { draft: 'neutral', in_review: 'teal', pending_approval: 'warn', final: 'ok', archived: 'sage' };

export function DashboardPage() {
  const [d, setD] = useState<Dashboard | null>(null);
  const toast = useToast();
  const { can, session } = useAuth();
  useEffect(() => { api.get<Dashboard>('/dashboard').then(setD).catch(toast.error); }, []);
  if (!d) return <div className="page loading">Loading dashboard…</div>;

  const active = d.projects.filter((p) => p.status !== 'archived');
  const tot = (k: keyof ProjectSummary['counts']) => active.reduce((n, p) => n + p.counts[k], 0);
  const bandTotal = Object.values(d.riskBands).reduce((n, b) => n + b.count, 0);
  const upcoming = [...active].filter((p) => p.reviewDate).sort((a, b) => a.reviewDate.localeCompare(b.reviewDate)).slice(0, 5);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Welcome, {session?.user.displayName}</h1>
          <div className="sub">Portfolio view of the assessments you can access.</div>
        </div>
        <div className="actions">
          {can('project:create') && <Link to="/projects?new=1" className="btn btn-primary"><Plus size={16} /> New assessment</Link>}
        </div>
      </div>

      <div className="grid grid-4">
        <Stat label="Active assessments" value={active.length} sub={`${d.projects.length - active.length} archived`} />
        <Stat label="Confirmed findings" value={tot('confirmed')} tone="danger" sub={`${tot('hypothesis')} hypotheses under validation`} />
        <Stat label="Missing evidence items" value={tot('missing_evidence')} tone="warn" sub="Information requests outstanding" />
        <Stat label="Risks awaiting approval" value={tot('risksPendingApproval')} tone="teal" sub={`${tot('risks')} risks registered`} />
      </div>

      <div className="grid grid-3" style={{ marginTop: 16 }}>
        <section className="card span-2">
          <div className="card-head"><FolderKanban size={16} /><h2>Assessments</h2><Link className="right small" to="/projects">View all</Link></div>
          {active.length === 0 ? <Empty title="No active assessments">Create an assessment to begin.</Empty> : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Assessment</th><th>Status</th><th>Model</th><th>Findings</th><th>Risks</th><th>Review date</th></tr></thead>
                <tbody>
                  {active.slice(0, 8).map((p) => (
                    <tr key={p.id}>
                      <td><Link to={`/projects/${p.id}`}><strong>{p.name}</strong></Link><div className="muted small">{p.clientAlias} {p.isDemo && <Badge tone="demo">DEMO DATA</Badge>}</div></td>
                      <td><Badge tone={STATUS_TONE[p.status]}>{STATUS_LABELS[p.status]}</Badge></td>
                      <td className="nowrap">{p.latestVersion ? `v${p.latestVersion}` : 'unsaved'} · {p.counts.components} comp.</td>
                      <td className="nowrap"><Badge tone="danger">{p.counts.confirmed}</Badge> <Badge tone="teal">{p.counts.hypothesis}</Badge> <Badge tone="warn">{p.counts.missing_evidence}</Badge></td>
                      <td>{p.counts.risks}</td>
                      <td className="nowrap">{fmtDay(p.reviewDate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="card">
          <div className="card-head"><h2>Risk profile</h2><span className="muted small right">{bandTotal} risks</span></div>
          <div className="card-body stack">
            {bandTotal === 0 ? <p className="muted">No risks registered yet.</p> : (
              <>
                <div className="bar" style={{ height: 14 }}>
                  {Object.entries(d.riskBands).map(([k, b]) => <span key={k} title={`${k}: ${b.count}`} style={{ width: `${(b.count / bandTotal) * 100}%`, background: b.color }} />)}
                </div>
                {Object.entries(d.riskBands).map(([k, b]) => (
                  <div key={k} className="row gap"><span style={{ width: 12, height: 12, borderRadius: 3, background: b.color }} /><span>{k}</span><strong className="right">{b.count}</strong></div>
                ))}
              </>
            )}
            <h3 style={{ marginTop: 18 }}>Upcoming reviews</h3>
            {upcoming.length ? upcoming.map((p) => <div key={p.id} className="row gap small"><Link to={`/projects/${p.id}`} className="grow ellipsis">{p.name}</Link><span className="muted nowrap">{fmtDay(p.reviewDate)}</span></div>) : <p className="muted small">None scheduled.</p>}
          </div>
        </section>
      </div>

      <div className="grid grid-2" style={{ marginTop: 16 }}>
        <section className="card">
          <div className="card-head"><AlertTriangle size={16} /><h2>Overdue mitigation actions</h2></div>
          {d.overdue.length === 0 ? <Empty title="Nothing overdue" /> : (
            <div className="table-wrap"><table className="table"><tbody>
              {d.overdue.map((o, i) => <tr key={i}><td><Link to={`/projects/${o.projectId}/risks`}>{o.risk}</Link><div className="muted small">{o.project}</div></td><td>{o.action}</td><td className="nowrap"><Badge tone="danger">{fmtDay(o.dueDate)}</Badge></td></tr>)}
            </tbody></table></div>
          )}
        </section>
        <section className="card">
          <div className="card-head"><Activity size={16} /><h2>Recent activity</h2></div>
          {d.recent.length === 0 ? <Empty title="No activity yet" /> : (
            <div className="table-wrap"><table className="table"><tbody>
              {d.recent.map((a) => <tr key={a.seq}><td className="nowrap muted small">{fmtDate(a.at)}</td><td><strong>{a.username}</strong> <span className="muted">{a.action.replace(/_/g, ' ')}</span>{a.detail && <div className="small muted" style={{ overflowWrap: 'anywhere' }}>{a.detail}</div>}</td></tr>)}
            </tbody></table></div>
          )}
        </section>
      </div>
    </div>
  );
}
