import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileUp, CheckCircle2, XCircle, FileImage, Bot, Plus, Download, Trash2, ShieldCheck } from 'lucide-react';
import { api, downloadBlob, uid } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useProject } from '../lib/project';
import { useWorkingModel } from '../lib/model';
import { Badge, Callout, Empty, Field, Modal, fmtDate, useToast } from '../components/ui';
import { DiagramSvg } from '../components/DiagramSvg';
import { extractGraphXml, importDrawioXml, type DrawioImport } from '@shared/drawio';
import { COMPONENTS, COMPONENT_TYPES, ZONES } from '@shared/schema';
import type { AiStatus, ArchitectureModel, ComponentType, EvidenceFile, ProjectData, ZoneType } from '@shared/types';

async function inflateRaw(bytes: Uint8Array): Promise<string> {
  const ds = new DecompressionStream('deflate-raw');
  const stream = new Blob([bytes as Uint8Array<ArrayBuffer>]).stream().pipeThrough(ds);
  return new Response(stream).text();
}

export function ImportsPage() {
  const { data, can, mutate } = useProject();
  const { session, userName } = useAuth();
  const toast = useToast();
  const wm = useWorkingModel();
  const { model, update, editable } = wm;
  const demo = session?.environment === 'demonstration';
  const [preview, setPreview] = useState<(DrawioImport & { fileName: string; file: File }) | null>(null);
  const [mode, setMode] = useState<'append' | 'replace'>('append');
  const [keepEvidence, setKeepEvidence] = useState(false);
  const [synthetic, setSynthetic] = useState(false);
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState<EvidenceFile | null>(null);
  const [ai, setAi] = useState<AiStatus | null>(null);
  const [inference, setInference] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<Set<string>>(new Set());

  useEffect(() => { api.get<AiStatus>('/ai/status').then(setAi).catch(() => setAi(null)); }, []);

  const upload = async (file: File, desc: string) => {
    const form = new FormData();
    form.append('file', file);
    form.append('description', desc);
    form.append('syntheticConfirmed', String(synthetic));
    return api.upload<ProjectData>(`/projects/${data.project.id}/evidence`, form);
  };

  // ---------------------------------------------------------------- draw.io
  const readDrawio = async (file: File) => {
    try {
      if (file.size > 10 * 1024 * 1024) throw new Error('Draw.io file exceeds 10 MB.');
      const { xml, pages } = await extractGraphXml(await file.text(), inflateRaw);
      const r = importDrawioXml(xml, file.name, pages);
      setPreview({ ...r, fileName: file.name, file });
    } catch (e) {
      toast.error(e);
    }
  };

  const applyDrawio = async () => {
    if (!preview) return;
    setBusy(true);
    try {
      if (keepEvidence) {
        if (demo && !synthetic) throw new Error('Confirm the file contains only synthetic data before storing it as evidence.');
        await mutate(() => upload(preview.file, `Draw.io source: ${preview.fileName}`));
      }
      let offsetY = 0;
      if (mode === 'append' && (model.components.length || model.zones.length)) {
        offsetY = Math.max(...model.components.map((c) => c.y + 80), ...model.zones.map((z) => z.y + z.h + 40), 0) + 20;
      }
      const shift = <T extends { y: number }>(x: T) => ({ ...x, y: x.y + offsetY });
      update((m: ArchitectureModel) => mode === 'replace'
        ? { ...m, components: preview.components, flows: preview.flows, zones: preview.zones }
        : { ...m, components: [...m.components, ...preview.components.map(shift)], flows: [...m.flows, ...preview.flows], zones: [...m.zones, ...preview.zones.map(shift)] });
      setInference((i) => ({ ...i, ...preview.inferences }));
      toast.ok(`Imported ${preview.components.length} components, ${preview.flows.length} flows and ${preview.zones.length} zones as UNCONFIRMED. Review them below.`);
      setPreview(null);
    } catch (e) {
      toast.error(e);
    } finally {
      setBusy(false);
    }
  };

  // ---------------------------------------------------------------- confirmation queue
  const queue = useMemo(() => {
    const name = (id: string) => model.components.find((c) => c.id === id)?.name ?? '?';
    return [
      ...model.zones.filter((z) => z.status !== 'confirmed').map((z) => ({ id: z.id, kind: 'zone' as const, label: z.name, detail: `${ZONES[z.zoneType].label} · trust ${z.trustLevel}`, source: z.source })),
      ...model.components.filter((c) => c.status !== 'confirmed').map((c) => ({ id: c.id, kind: 'component' as const, label: c.name, detail: COMPONENTS[c.type].label, source: c.source, type: c.type })),
      ...model.flows.filter((f) => f.status !== 'confirmed').map((f) => ({ id: f.id, kind: 'flow' as const, label: `${name(f.from)} → ${name(f.to)}`, detail: [f.protocol, f.label].filter(Boolean).join(' · ') || 'no protocol / label', source: f.source, blocked: model.components.find((c) => c.id === f.from)?.status !== 'confirmed' || model.components.find((c) => c.id === f.to)?.status !== 'confirmed' })),
    ];
  }, [model]);

  const setStatus = (ids: Set<string>, confirm: boolean) => {
    update((m) => confirm ? {
      ...m,
      components: m.components.map((c) => (ids.has(c.id) ? { ...c, status: 'confirmed' } : c)),
      flows: m.flows.map((f) => (ids.has(f.id) ? { ...f, status: 'confirmed' } : f)),
      zones: m.zones.map((z) => (ids.has(z.id) ? { ...z, status: 'confirmed' } : z)),
    } : {
      ...m,
      components: m.components.filter((c) => !ids.has(c.id)),
      flows: m.flows.filter((f) => !ids.has(f.id) && !ids.has(f.from) && !ids.has(f.to)),
      zones: m.zones.filter((z) => !ids.has(z.id)),
    });
    setSelected(new Set());
  };
  const setType = (id: string, type: ComponentType) => update((m) => ({ ...m, components: m.components.map((c) => (c.id === id ? { ...c, type } : c)) }));

  // ---------------------------------------------------------------- evidence
  const [docFile, setDocFile] = useState<File | null>(null);
  const uploadDoc = async () => {
    if (!docFile) return;
    setBusy(true);
    const ok = await mutate(() => upload(docFile, description), 'Evidence stored (encrypted at rest).');
    setBusy(false);
    if (ok) { setDocFile(null); setDescription(''); }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Imports &amp; evidence</h1><div className="sub">Bring existing diagrams into the canonical model. Every imported or transcribed element is UNCONFIRMED until a reviewer confirms it; unconfirmed elements are never used for analysis.</div></div>
      </div>

      <div className="grid grid-2">
        <section className="card">
          <div className="card-head"><FileUp size={16} /><h2>Structured Draw.io import</h2></div>
          <div className="card-body stack">
            <p className="small muted">Parses <code>.drawio</code> / diagrams.net XML (compressed or plain) in your browser. Shapes are mapped to component types and containers to zones by keyword; connector labels supply protocols. Encryption, authentication and data classification are never inferred.</p>
            {editable ? (
              <label className="btn"><FileUp size={16} /> Choose .drawio / .xml file<input type="file" accept=".drawio,.xml" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) readDrawio(f); e.target.value = ''; }} /></label>
            ) : <Callout>You have read-only access to this model.</Callout>}
          </div>
        </section>

        <section className="card">
          <div className="card-head"><FileImage size={16} /><h2>PDF &amp; image diagrams</h2></div>
          <div className="card-body stack">
            <p className="small muted">Upload a PDF, PNG or JPEG diagram as evidence, then transcribe its components and flows manually with a page/location reference. Files are type-checked, hashed (SHA-256) and stored encrypted (AES-256-GCM).</p>
            {can('evidence:upload') ? (
              <>
                <div className="row gap wrap">
                  <label className="btn"><FileUp size={16} /> {docFile ? docFile.name : 'Choose file'}<input type="file" accept=".pdf,.png,.jpg,.jpeg,.drawio,.xml" hidden onChange={(e) => setDocFile(e.target.files?.[0] ?? null)} /></label>
                  <input type="text" placeholder="Description (e.g. HLD v2.3 p.4)" value={description} onChange={(e) => setDescription(e.target.value)} style={{ flex: 1, minWidth: 160 }} maxLength={500} />
                </div>
                {demo && <label className="check"><input type="checkbox" checked={synthetic} onChange={(e) => setSynthetic(e.target.checked)} /> I confirm this file contains only synthetic or sanitised non-client data (demonstration environment).</label>}
                <div><button className="btn btn-primary" disabled={!docFile || busy || (demo && !synthetic)} onClick={uploadDoc}>Upload evidence</button></div>
              </>
            ) : <Callout>Your role cannot upload evidence on this assessment.</Callout>}
          </div>
        </section>
      </div>

      <section className="card" style={{ marginTop: 16 }}>
        <div className="card-head">
          <h2>Confirmation queue</h2><Badge tone={queue.length ? 'warn' : 'ok'}>{queue.length} unconfirmed</Badge>
          {editable && queue.length > 0 && (
            <div className="right row gap">
              <button className="btn btn-sm btn-teal" disabled={!selected.size} onClick={() => setStatus(selected, true)}><CheckCircle2 size={14} /> Confirm selected ({selected.size})</button>
              <button className="btn btn-sm btn-danger" disabled={!selected.size} onClick={() => setStatus(selected, false)}><XCircle size={14} /> Discard selected</button>
            </div>
          )}
        </div>
        {queue.length === 0 ? <Empty icon={<ShieldCheck size={32} />} title="Nothing awaiting confirmation">All model elements have been confirmed by a reviewer.</Empty> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th style={{ width: 30 }}><input type="checkbox" aria-label="Select all" checked={selected.size === queue.length} onChange={(e) => setSelected(e.target.checked ? new Set(queue.map((q) => q.id)) : new Set())} /></th><th>Element</th><th>Kind / type</th><th>Source</th><th>Why it was classified this way</th><th /></tr></thead>
              <tbody>
                {queue.map((q) => (
                  <tr key={q.id}>
                    <td><input type="checkbox" checked={selected.has(q.id)} onChange={(e) => { const s = new Set(selected); if (e.target.checked) s.add(q.id); else s.delete(q.id); setSelected(s); }} /></td>
                    <td><strong>{q.label}</strong></td>
                    <td>
                      <Badge>{q.kind}</Badge>{' '}
                      {q.kind === 'component' && editable ? (
                        <select value={(q as { type: ComponentType }).type} onChange={(e) => setType(q.id, e.target.value as ComponentType)} style={{ width: 170, marginTop: 4 }}>
                          {COMPONENT_TYPES.map((t) => <option key={t} value={t}>{COMPONENTS[t].label}</option>)}
                        </select>
                      ) : <span className="small">{q.detail}</span>}
                      {q.kind === 'flow' && <div className="small muted">{q.detail}</div>}
                    </td>
                    <td className="small">{q.source.kind}{q.source.ref ? `: ${q.source.ref}` : ''}{q.source.location ? <div className="muted">{q.source.location}</div> : null}</td>
                    <td className="small muted" style={{ maxWidth: 320 }}>{inference[q.id] ?? q.source.note ?? (q.source.kind === 'document' ? 'Manually transcribed from document.' : q.source.kind === 'drawio' ? 'Imported from Draw.io (inference details available in the import session only).' : 'Marked unconfirmed.')}{'blocked' in q && q.blocked && <div><Badge tone="warn">endpoint unconfirmed</Badge></div>}</td>
                    <td className="nowrap">{editable && <>
                      <button className="icon-btn" title="Confirm" onClick={() => setStatus(new Set([q.id]), true)}><CheckCircle2 size={17} color="var(--ok)" /></button>
                      <button className="icon-btn" title="Discard" onClick={() => setStatus(new Set([q.id]), false)}><XCircle size={17} color="var(--danger)" /></button>
                    </>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="card-body small muted">Confirm only what the source evidences. Properties such as encryption and authentication remain “unknown” until set in the <Link to="../architecture">architecture editor</Link>.</div>
      </section>

      <section className="card" style={{ marginTop: 16 }}>
        <div className="card-head"><h2>Evidence register</h2><span className="small muted right">Max upload size enforced server-side · files encrypted at rest</span></div>
        {data.evidence.length === 0 ? <Empty title="No evidence files" /> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Evidence ID</th><th>File</th><th>Description</th><th>Uploaded</th><th>Transcription</th><th>AI processing</th><th /></tr></thead>
            <tbody>
              {data.evidence.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{e.id.slice(0, 8)}</td>
                  <td><strong>{e.fileName}</strong><div className="muted small">{(e.size / 1024).toFixed(0)} KB · sha256 {e.sha256.slice(0, 12)}…</div></td>
                  <td className="small">{e.description || '—'}</td>
                  <td className="small nowrap">{fmtDate(e.uploadedAt)}<br />{userName(e.uploadedBy)}</td>
                  <td><Badge tone={e.confirmation === 'transcribed' ? 'ok' : e.confirmation === 'not_used' ? 'neutral' : 'warn'}>{e.confirmation.replace('_', ' ')}</Badge></td>
                  <td>{e.aiProcessingApproved ? <Badge tone="warn">approved</Badge> : <Badge>not approved</Badge>}</td>
                  <td className="nowrap">
                    {e.mimeType !== 'application/vnd.jgraph.mxfile' && <button className="btn btn-sm" onClick={() => setActive(e)}>Open &amp; transcribe</button>}
                    <button className="icon-btn" title="Download" onClick={async () => { try { downloadBlob(await api.getBlob(`/projects/${data.project.id}/evidence/${e.id}/content?download=1`), e.fileName); } catch (err) { toast.error(err); } }}><Download size={16} /></button>
                    {can('evidence:upload') && <button className="icon-btn" title="Delete" onClick={() => mutate(() => api.del<ProjectData>(`/projects/${data.project.id}/evidence/${e.id}`), 'Evidence deleted.')}><Trash2 size={16} /></button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </section>

      {preview && (
        <Modal title={`Draw.io import preview — ${preview.fileName}`} wide onClose={() => setPreview(null)} footer={<><button className="btn" onClick={() => setPreview(null)}>Cancel</button><button className="btn btn-primary" disabled={busy || !preview.components.length} onClick={applyDrawio}>Import as unconfirmed</button></>}>
          <div className="stack">
            {preview.warnings.map((w, i) => <Callout key={i} tone="warn">{w}</Callout>)}
            <div className="row gap wrap"><Badge tone="teal">{preview.components.length} components</Badge><Badge tone="teal">{preview.flows.length} flows</Badge><Badge tone="teal">{preview.zones.length} zones</Badge></div>
            <div className="canvas-wrap" style={{ maxHeight: 320 }}><DiagramSvg model={{ schema: 'sawb.architecture/1.0', components: preview.components, flows: preview.flows, zones: preview.zones, notes: '' }} scale={0.6} /></div>
            <table className="table"><thead><tr><th>Element</th><th>Inference</th></tr></thead><tbody>
              {[...preview.zones.map((z) => [z.id, `Zone: ${z.name}`]), ...preview.components.map((c) => [c.id, `${COMPONENTS[c.type].label}: ${c.name}`])].map(([id, l]) => <tr key={id}><td>{l}</td><td className="small muted">{preview.inferences[id]}</td></tr>)}
            </tbody></table>
            <div className="row gap wrap">
              <div className="seg"><button className={mode === 'append' ? 'on' : ''} onClick={() => setMode('append')}>Append to model</button><button className={mode === 'replace' ? 'on' : ''} onClick={() => setMode('replace')}>Replace working model</button></div>
              {can('evidence:upload') && <label className="check"><input type="checkbox" checked={keepEvidence} onChange={(e) => setKeepEvidence(e.target.checked)} /> Store the source file as evidence</label>}
            </div>
            {keepEvidence && demo && <label className="check"><input type="checkbox" checked={synthetic} onChange={(e) => setSynthetic(e.target.checked)} /> I confirm this file contains only synthetic or sanitised non-client data.</label>}
          </div>
        </Modal>
      )}

      {active && <TranscribeModal ev={active} onClose={() => setActive(null)} ai={ai} model={model} editable={editable} update={update} />}
    </div>
  );
}

function TranscribeModal({ ev: initial, onClose, ai, model, editable, update }: { ev: EvidenceFile; onClose: () => void; ai: AiStatus | null; model: ArchitectureModel; editable: boolean; update: ReturnType<typeof useWorkingModel>['update'] }) {
  const { data, can, mutate } = useProject();
  const ev = data.evidence.find((x) => x.id === initial.id) ?? initial;
  const toast = useToast();
  const [url, setUrl] = useState('');
  const [kind, setKind] = useState<'component' | 'flow' | 'zone'>('component');
  const [name, setName] = useState('');
  const [type, setType] = useState<ComponentType>('app_server');
  const [zoneType, setZoneType] = useState<ZoneType>('internal');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [protocol, setProtocol] = useState('');
  const [location, setLocation] = useState('');
  const [added, setAdded] = useState<string[]>([]);
  const [aiConfirm, setAiConfirm] = useState(false);

  useEffect(() => {
    let u = '';
    api.getBlob(`/projects/${data.project.id}/evidence/${ev.id}/content`).then((b) => { u = URL.createObjectURL(b); setUrl(u); }).catch(toast.error);
    return () => { if (u) URL.revokeObjectURL(u); };
  }, [ev.id]);

  const source = { kind: 'document' as const, ref: `${ev.fileName} [${ev.id.slice(0, 8)}]`, location: location || undefined };
  const add = () => {
    if (kind === 'component') {
      if (!name.trim()) return toast.error('Name is required.');
      const n = model.components.length;
      update((m) => ({ ...m, components: [...m.components, { id: uid('c'), type, name: name.trim(), x: 60 + (n % 6) * 170, y: 60 + Math.floor(n / 6) * 100, status: 'unconfirmed', source, properties: {} }] }));
      setAdded((a) => [...a, `Component: ${name}`]);
    } else if (kind === 'flow') {
      if (!from || !to || from === to) return toast.error('Choose two different components.');
      update((m) => ({ ...m, flows: [...m.flows, { id: uid('f'), from, to, label: name, protocol, port: '', encrypted: 'unknown', authenticated: 'unknown', dataClassification: 'unknown', bidirectional: false, status: 'unconfirmed', source }] }));
      setAdded((a) => [...a, `Flow: ${model.components.find((c) => c.id === from)?.name} → ${model.components.find((c) => c.id === to)?.name}`]);
    } else {
      if (!name.trim()) return toast.error('Name is required.');
      update((m) => ({ ...m, zones: [...m.zones, { id: uid('z'), name: name.trim(), zoneType, trustLevel: ZONES[zoneType].trust, x: 40, y: 40, w: 400, h: 260, status: 'unconfirmed', source }] }));
      setAdded((a) => [...a, `Zone: ${name}`]);
    }
    setName(''); setProtocol('');
  };

  const aiBlockers = [
    ai?.environment !== 'production' && 'The environment is not production-approved.',
    !ai?.configured && 'No AI provider is configured.',
    ai?.configured && !ai.adapterImplemented && 'No adapter is implemented for the configured provider.',
    !ai?.documentProcessingAllowed && ai?.adapterImplemented && 'Document processing is disabled by configuration.',
    !ev.aiProcessingApproved && 'This document has not been approved for AI processing by a lead reviewer.',
  ].filter(Boolean) as string[];

  const requestAi = async () => {
    try {
      await api.post('/ai/extract', { projectId: data.project.id, evidenceId: ev.id, userConfirmed: aiConfirm });
    } catch (e) { toast.error(e); }
  };

  return (
    <Modal title={`Transcribe: ${ev.fileName}`} wide onClose={onClose} footer={<>
      {editable && <button className="btn" onClick={() => mutate(() => api.patch<ProjectData>(`/projects/${data.project.id}/evidence/${ev.id}`, { confirmation: 'not_used' }), 'Marked as not used.')}>Mark not used</button>}
      {editable && <button className="btn btn-primary" onClick={async () => { if (await mutate(() => api.patch<ProjectData>(`/projects/${data.project.id}/evidence/${ev.id}`, { confirmation: 'transcribed' }), 'Marked as transcribed.')) onClose(); }}>Mark transcription complete</button>}
    </>}>
      <div className="grid grid-2">
        <div style={{ minHeight: 420, border: '1px solid var(--line)', borderRadius: 8, overflow: 'auto', background: '#fafbf8' }}>
          {!url ? <div className="loading">Decrypting…</div> : ev.mimeType === 'application/pdf'
            ? <object data={url} type="application/pdf" width="100%" height="560" aria-label="PDF preview"><p className="card-body">PDF preview is not supported in this browser. Download the file to view it.</p></object>
            : <img src={url} alt={ev.fileName} style={{ width: '100%', display: 'block' }} />}
        </div>
        <div className="stack">
          <Callout>Transcribe only what the document shows. Each element is added as <strong>unconfirmed</strong> with a reference to this evidence file and location, then confirmed in the queue.</Callout>
          {editable ? (
            <>
              <div className="seg">{(['component', 'flow', 'zone'] as const).map((k) => <button key={k} className={kind === k ? 'on' : ''} onClick={() => setKind(k)}><Plus size={12} />{k}</button>)}</div>
              {kind === 'component' && (
                <div className="form-grid">
                  <Field label="Name"><input type="text" value={name} onChange={(e) => setName(e.target.value)} /></Field>
                  <Field label="Type"><select value={type} onChange={(e) => setType(e.target.value as ComponentType)}>{COMPONENT_TYPES.map((t) => <option key={t} value={t}>{COMPONENTS[t].label}</option>)}</select></Field>
                </div>
              )}
              {kind === 'flow' && (
                <div className="form-grid">
                  <Field label="From"><select value={from} onChange={(e) => setFrom(e.target.value)}><option value="">—</option>{model.components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
                  <Field label="To"><select value={to} onChange={(e) => setTo(e.target.value)}><option value="">—</option>{model.components.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
                  <Field label="Label"><input type="text" value={name} onChange={(e) => setName(e.target.value)} /></Field>
                  <Field label="Protocol (as shown)"><input type="text" value={protocol} onChange={(e) => setProtocol(e.target.value)} /></Field>
                </div>
              )}
              {kind === 'zone' && (
                <div className="form-grid">
                  <Field label="Name"><input type="text" value={name} onChange={(e) => setName(e.target.value)} /></Field>
                  <Field label="Zone classification"><select value={zoneType} onChange={(e) => setZoneType(e.target.value as ZoneType)}>{(Object.keys(ZONES) as ZoneType[]).map((z) => <option key={z} value={z}>{ZONES[z].label}</option>)}</select></Field>
                </div>
              )}
              <Field label="Location in document" hint="e.g. page 4, figure 2, top-right"><input type="text" value={location} onChange={(e) => setLocation(e.target.value)} /></Field>
              <div><button className="btn btn-teal" onClick={add}><Plus size={14} /> Add {kind} (unconfirmed)</button></div>
              {added.length > 0 && <ul className="list-plain small">{added.map((a, i) => <li key={i}>{a}</li>)}</ul>}
            </>
          ) : <Callout>Read-only access.</Callout>}

          <div className="card card-pad stack">
            <div className="row gap"><Bot size={16} /><strong>AI-assisted extraction</strong><Badge tone="danger">not operational</Badge></div>
            <p className="small muted">{ai?.message ?? 'Status unavailable.'}</p>
            {aiBlockers.length > 0 && <ul className="list-plain small">{aiBlockers.map((b) => <li key={b}>{b}</li>)}</ul>}
            {can('evidence:approve_ai') && (
              <label className="check small"><input type="checkbox" checked={ev.aiProcessingApproved} disabled={ai?.environment !== 'production'} onChange={(e) => mutate(() => api.patch<ProjectData>(`/projects/${data.project.id}/evidence/${ev.id}`, { aiProcessingApproved: e.target.checked }))} />
                Approve this document for processing by the configured AI provider {ai?.environment !== 'production' && '(unavailable in demonstration environment)'}</label>
            )}
            {aiBlockers.length === 0 && (
              <>
                <label className="check small"><input type="checkbox" checked={aiConfirm} onChange={(e) => setAiConfirm(e.target.checked)} /> I confirm this document may be sent to {ai?.provider} for this request.</label>
                <div><button className="btn" disabled={!aiConfirm} onClick={requestAi}>Request extraction</button></div>
              </>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
}
