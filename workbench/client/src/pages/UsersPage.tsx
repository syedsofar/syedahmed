import { useState } from 'react';
import { UserPlus } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Badge, Field, Modal, useToast } from '../components/ui';
import { ROLE_LABELS } from '@shared/schema';
import type { PublicUser, Role } from '@shared/types';

const PERMS: Record<Role, string> = {
  admin: 'Everything, including users, catalogs, audit trail and all projects.',
  lead_reviewer: 'Create assessments, edit content, approve risks and catalogs, finalise assessments, approve documents for AI.',
  analyst: 'Edit models, threats, control reviews and risks; upload evidence; export reports (project membership required).',
  viewer: 'Read-only access to projects they are members of.',
};

export function UsersPage() {
  const { users, refreshUsers, session, can } = useAuth();
  const toast = useToast();
  const [form, setForm] = useState<{ username: string; displayName: string; role: Role; password: string } | null>(null);
  const [reset, setReset] = useState<{ user: PublicUser; password: string } | null>(null);
  if (!can('user:manage')) return <div className="page"><div className="callout callout-danger">Administrator access required.</div></div>;

  const patch = async (u: PublicUser, body: object, msg: string) => {
    try { await api.patch(`/users/${u.id}`, body); toast.ok(msg); refreshUsers(); } catch (e) { toast.error(e); }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Users &amp; roles</h1><div className="sub">Role-based authorisation combined with project-level membership. New and reset accounts must change their password at next sign-in.</div></div>
        <div className="actions"><button className="btn btn-primary" onClick={() => setForm({ username: '', displayName: '', role: 'analyst', password: '' })}><UserPlus size={16} /> New user</button></div>
      </div>
      <div className="grid grid-4" style={{ marginBottom: 16 }}>
        {(Object.keys(PERMS) as Role[]).map((r) => <div key={r} className="card card-pad"><strong>{ROLE_LABELS[r]}</strong><div className="small muted">{PERMS[r]}</div></div>)}
      </div>
      <section className="card"><div className="table-wrap"><table className="table">
        <thead><tr><th>User</th><th>Username</th><th>Role</th><th>Status</th><th /></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td><strong>{u.displayName}</strong>{u.id === session?.user.id && <Badge tone="teal">you</Badge>}</td>
              <td className="mono">{u.username}</td>
              <td>
                <select value={u.role} disabled={u.id === session?.user.id} onChange={(e) => patch(u, { role: e.target.value }, 'Role updated.')} style={{ width: 180 }}>
                  {(Object.keys(ROLE_LABELS) as Role[]).map((r) => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}
                </select>
              </td>
              <td>{u.disabled ? <Badge tone="danger">disabled</Badge> : <Badge tone="ok">active</Badge>}</td>
              <td className="nowrap">
                <button className="btn btn-sm" onClick={() => setReset({ user: u, password: '' })}>Reset password</button>{' '}
                {u.id !== session?.user.id && <button className="btn btn-sm" onClick={() => patch(u, { disabled: !u.disabled }, u.disabled ? 'User enabled.' : 'User disabled and signed out.')}>{u.disabled ? 'Enable' : 'Disable'}</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table></div></section>

      {form && (
        <Modal title="New user" onClose={() => setForm(null)} footer={<><button className="btn" onClick={() => setForm(null)}>Cancel</button><button className="btn btn-primary" onClick={async () => { try { await api.post('/users', form); toast.ok('User created.'); setForm(null); refreshUsers(); } catch (e) { toast.error(e); } }}>Create user</button></>}>
          <div className="form-grid">
            <Field label="Username"><input type="text" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>
            <Field label="Display name"><input type="text" value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} /></Field>
            <Field label="Role"><select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>{(Object.keys(ROLE_LABELS) as Role[]).map((r) => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}</select></Field>
            <Field label="Initial password" hint="≥12 chars, upper, lower, digit. Must be changed at first sign-in."><input type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
          </div>
        </Modal>
      )}
      {reset && (
        <Modal title={`Reset password — ${reset.user.displayName}`} onClose={() => setReset(null)} footer={<><button className="btn" onClick={() => setReset(null)}>Cancel</button><button className="btn btn-primary" onClick={async () => { await patch(reset.user, { password: reset.password }, 'Password reset; existing sessions revoked.'); setReset(null); }}>Reset</button></>}>
          <Field label="Temporary password" hint="The user must change it at next sign-in. All their sessions are revoked."><input type="password" autoComplete="new-password" value={reset.password} onChange={(e) => setReset({ ...reset, password: e.target.value })} /></Field>
        </Modal>
      )}
    </div>
  );
}
