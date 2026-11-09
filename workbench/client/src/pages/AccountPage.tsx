import { useState } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Callout, Field, useToast } from '../components/ui';
import { ROLE_LABELS } from '@shared/schema';

export function AccountPage({ forced }: { forced?: boolean }) {
  const { session, markPasswordChanged, logout } = useAuth();
  const toast = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (next !== confirm) return toast.error('New passwords do not match.');
    setBusy(true);
    try {
      await api.post('/auth/password', { current, next });
      toast.ok('Password changed.');
      setCurrent(''); setNext(''); setConfirm('');
      markPasswordChanged();
    } catch (err) {
      toast.error(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page" style={forced ? { margin: '40px auto', maxWidth: 520 } : undefined}>
      <div className="page-head"><div><h1>Account</h1><div className="sub">{session?.user.displayName} · {ROLE_LABELS[session?.user.role ?? 'viewer']}</div></div></div>
      {forced && <Callout tone="warn">You must set a new password before continuing.</Callout>}
      <form className="card card-pad stack" style={{ maxWidth: 480, marginTop: 12 }} onSubmit={submit}>
        <h2>Change password</h2>
        <Field label="Current password"><input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required /></Field>
        <Field label="New password" hint="At least 12 characters with upper-case, lower-case and a digit."><input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required /></Field>
        <Field label="Confirm new password"><input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required /></Field>
        <div className="row gap">
          <button className="btn btn-primary" disabled={busy}>Update password</button>
          {forced && <button type="button" className="btn" onClick={logout}>Sign out</button>}
        </div>
      </form>
    </div>
  );
}
