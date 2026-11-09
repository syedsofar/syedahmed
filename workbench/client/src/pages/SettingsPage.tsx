import { useEffect, useState } from 'react';
import { Bot, Lock, Server } from 'lucide-react';
import { api } from '../lib/api';
import { Badge, Callout } from '../components/ui';
import type { AiStatus } from '@shared/types';

interface Env { mode: 'demonstration' | 'production'; maxUploadMb: number; ai: AiStatus }

export function SettingsPage() {
  const [env, setEnv] = useState<Env | null>(null);
  useEffect(() => { api.get<Env>('/environment').then(setEnv).catch(() => setEnv(null)); }, []);
  if (!env) return <div className="page loading">Loading…</div>;
  const ai = env.ai;
  const row = (label: string, ok: boolean, detail: string) => (
    <tr><td>{label}</td><td>{ok ? <Badge tone="ok">yes</Badge> : <Badge tone="danger">no</Badge>}</td><td className="small muted">{detail}</td></tr>
  );
  return (
    <div className="page">
      <div className="page-head"><div><h1>Environment &amp; AI services</h1><div className="sub">Read-only view of server configuration. Settings are controlled by environment variables on the server, not from the browser.</div></div></div>
      <div className="grid grid-2">
        <section className="card">
          <div className="card-head"><Server size={16} /><h2>Environment</h2><Badge tone={env.mode === 'production' ? 'teal' : 'warn'}>{env.mode}</Badge></div>
          <div className="card-body stack small">
            {env.mode === 'demonstration'
              ? <Callout tone="warn">Demonstration environment: use synthetic data only. Uploads require a synthetic-data confirmation, demo catalogs and sample data are loaded, and AI processing of documents cannot be approved.</Callout>
              : <Callout>Production-approved environment. Demo content is not loaded and the data-encryption key is supplied by the operator.</Callout>}
            <dl className="kv">
              <dt>Max upload size</dt><dd>{env.maxUploadMb} MB (PDF, PNG, JPEG, Draw.io; content-type verified by signature)</dd>
              <dt>Data at rest</dt><dd>Store and evidence files encrypted with AES-256-GCM (<code>SAWB_DATA_KEY</code>)</dd>
              <dt>Sessions</dt><dd>HttpOnly SameSite=Strict cookie, idle timeout, CSRF token on every change</dd>
              <dt>Passwords</dt><dd>scrypt hashes; lockout after 5 failed attempts for 15 minutes</dd>
            </dl>
          </div>
        </section>
        <section className="card">
          <div className="card-head"><Bot size={16} /><h2>AI provider interface</h2><Badge tone={ai.configured && ai.adapterImplemented ? 'ok' : 'danger'}>{ai.configured && ai.adapterImplemented ? 'operational' : 'not operational'}</Badge></div>
          <div className="card-body stack">
            <p className="small">{ai.message}</p>
            <table className="table"><tbody>
              {row('Production-approved environment', ai.environment === 'production', 'SAWB_ENV=production')}
              {row('Provider configured', ai.configured, `SAWB_AI_PROVIDER / SAWB_AI_ENDPOINT${ai.provider ? ` (${ai.provider})` : ''}`)}
              {row('Adapter implemented', ai.adapterImplemented, 'server/ai.ts — no adapter ships with this build')}
              {row('Document processing enabled', ai.documentProcessingAllowed, 'SAWB_AI_ALLOW_DOCUMENTS=true')}
            </tbody></table>
            <div className="callout callout-info small"><Lock size={14} /><div>Even when operational, a document is only sent after a lead reviewer approves that specific file and the requesting user confirms the individual request. Every request is written to the audit trail.</div></div>
          </div>
        </section>
      </div>
    </div>
  );
}
