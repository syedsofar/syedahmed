import { useState } from 'react';
import { ShieldCheck, LogIn } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { Callout, Field } from '../components/ui';

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <div className="login-art">
        <div className="row gap"><ShieldCheck size={30} color="#46b3a8" /><strong style={{ color: '#fff' }}>Internal use only</strong></div>
        <div>
          <h1>From a rough design to a reviewed, documented and defensible architecture.</h1>
          <ul>
            <li>Capture architecture by drawing it or importing Draw.io, PDF and image diagrams</li>
            <li>Versioned canonical model with reviewer confirmation of every imported element</li>
            <li>STRIDE, PASTA and OCTAVE threat scenarios grounded in confirmed facts</li>
            <li>Control review against approved NCA ECC, SAMA CSF, NIST CSF and ISO 27001 catalogs</li>
            <li>5×5 risk register with ownership and reviewer approval; DOCX / PDF / Excel reporting</li>
          </ul>
        </div>
        <div className="small" style={{ color: '#7f93ab' }}>Access is logged. Unauthorised use is prohibited.</div>
      </div>
      <div className="login-form">
        <form onSubmit={submit} className="card card-pad stack" aria-label="Sign in">
          <h2>Sign in</h2>
          <p className="muted small">Use the account issued by your workbench administrator.</p>
          {error && <Callout tone="danger">{error}</Callout>}
          <Field label="Username"><input type="text" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus /></Field>
          <Field label="Password"><input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></Field>
          <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} disabled={busy}><LogIn size={16} /> {busy ? 'Signing in…' : 'Sign in'}</button>
          <p className="muted small">Demonstration installs create accounts <code>admin</code>, <code>lead</code>, <code>analyst</code> and <code>viewer</code>; the password is written to <code>server/data/DEMO_CREDENTIALS.txt</code> on first start.</p>
        </form>
      </div>
    </div>
  );
}
