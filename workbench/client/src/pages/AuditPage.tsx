import { useEffect, useMemo, useState } from 'react';
import { ShieldCheck, ShieldX } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Badge, fmtDate, useToast } from '../components/ui';
import type { AuditEntry } from '@shared/types';

export function AuditPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [list, setList] = useState<AuditEntry[] | null>(null);
  const [verify, setVerify] = useState<{ ok: boolean; checked: number; brokenAt?: number } | null>(null);
  const [q, setQ] = useState('');
  useEffect(() => { if (can('audit:read_all')) api.get<AuditEntry[]>('/audit').then(setList).catch(toast.error); }, []);
  const filtered = useMemo(() => (list ?? []).filter((a) => !q || `${a.username} ${a.action} ${a.target ?? ''} ${a.detail ?? ''}`.toLowerCase().includes(q.toLowerCase())), [list, q]);
  if (!can('audit:read_all')) return <div className="page"><div className="callout callout-danger">Administrator access required.</div></div>;

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Audit trail</h1><div className="sub">Append-only, hash-chained record of sign-ins, changes, evidence access, approvals and exports. Each entry commits to the hash of the previous one.</div></div>
        <div className="actions">
          {verify && (verify.ok ? <Badge tone="ok"><ShieldCheck size={12} /> Chain intact ({verify.checked} entries)</Badge> : <Badge tone="danger"><ShieldX size={12} /> Chain broken at #{verify.brokenAt}</Badge>)}
          <button className="btn" onClick={() => api.get<typeof verify>('/audit/verify').then(setVerify).catch(toast.error)}>Verify integrity</button>
        </div>
      </div>
      <section className="card">
        <div className="card-head"><input type="search" placeholder="Filter by user, action or detail" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 320 }} /><span className="small muted right">Showing latest {filtered.length}</span></div>
        <div className="table-wrap"><table className="table">
          <thead><tr><th>#</th><th>Time</th><th>User</th><th>Action</th><th>Target / detail</th><th>IP</th><th>Hash</th></tr></thead>
          <tbody>
            {filtered.map((a) => (
              <tr key={a.seq}>
                <td className="mono">{a.seq}</td>
                <td className="small nowrap">{fmtDate(a.at)}</td>
                <td>{a.username}</td>
                <td><Badge tone={a.action.includes('failed') ? 'danger' : a.action.startsWith('auth') ? 'neutral' : 'teal'}>{a.action}</Badge></td>
                <td className="small">{a.target && <strong>{a.target} </strong>}{a.detail}</td>
                <td className="mono small">{a.ip ?? ''}</td>
                <td className="mono small" title={a.hash}>{a.hash.slice(0, 10)}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </section>
    </div>
  );
}
