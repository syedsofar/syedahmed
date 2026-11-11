import { useEffect, useRef, useState } from 'react';
import { Download, History, Save, Upload } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api, downloadBlob } from '../lib/api';
import { useProject } from '../lib/project';
import { useWorkingModel } from '../lib/model';
import { loadCatalog } from '../lib/catalog';
import { Callout, Modal, fmtDate, useToast } from '../components/ui';
import { canonicalToDesigner, designerToCanonical, type DesignerModel } from '@shared/designer';
import { diffModels } from '@shared/diff';
import type { CatalogItem } from '@shared/catalog';
import { MODEL_SCHEMA, type ArchitectureModel, type ModelVersion, type ProjectData } from '@shared/types';

// Architecture editor: the ArchGuard designer, saving to this project's architecture model.
// Versions, JSON export and JSON import work on the same model that threat analysis uses.
export function ArchitecturePage() {
  const { data, setData, mutate } = useProject();
  const toast = useToast();
  const wm = useWorkingModel();
  const { model, update, editable } = wm;

  const frameRef = useRef<HTMLIFrameElement>(null);
  const [catalog, setCatalog] = useState<CatalogItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const modelRef = useRef(model);
  modelRef.current = model;
  const editableRef = useRef(editable);
  editableRef.current = editable;
  const catalogRef = useRef<CatalogItem[] | null>(null);
  catalogRef.current = catalog;
  const readyRef = useRef(false);
  // JSON of the last model the designer itself saved. A different model means an
  // external change (restore or import), so the designer is reloaded with it.
  const lastFromDesigner = useRef('');

  const [saveOpen, setSaveOpen] = useState(false);
  const [message, setMessage] = useState('');
  const [latestModel, setLatestModel] = useState<ArchitectureModel | null>(null);
  const [versionsOpen, setVersionsOpen] = useState(false);
  const [viewVersion, setViewVersion] = useState<ModelVersion | null>(null);
  const [pendingImport, setPendingImport] = useState<ArchitectureModel | null>(null);

  const latest = data.versions[data.versions.length - 1];
  const unconfirmed = [...model.components, ...model.flows, ...model.zones].filter((x) => x.status === 'unconfirmed').length;

  const sendInit = () => {
    const frame = frameRef.current?.contentWindow;
    const cat = catalogRef.current;
    if (!frame || !cat || !readyRef.current) return;
    const designer: DesignerModel = canonicalToDesigner(modelRef.current, data.project.name, cat[0]?.id ?? '');
    frame.postMessage({ type: 'sawb:designer-init', model: designer }, window.location.origin);
  };

  useEffect(() => {
    loadCatalog().then((c) => setCatalog(c.components)).catch((e) => setError(e instanceof Error ? e.message : 'Could not load the component library.'));
  }, []);

  useEffect(() => { sendInit(); }, [catalog]);

  // External change to the model (restore or import): reload the designer with it.
  useEffect(() => {
    const json = JSON.stringify(model);
    if (lastFromDesigner.current && json !== lastFromDesigner.current) {
      readyRef.current = false;
      setReloadKey((k) => k + 1);
    }
  }, [model]);

  useEffect(() => {
    const onMessage = (ev: MessageEvent) => {
      if (ev.source !== frameRef.current?.contentWindow || ev.origin !== window.location.origin) return;
      const msg = ev.data as { type?: string; model?: DesignerModel } | null;
      if (msg?.type === 'sawb:designer-ready') {
        readyRef.current = true;
        lastFromDesigner.current = JSON.stringify(modelRef.current);
        sendInit();
        return;
      }
      if (msg?.type === 'sawb:designer-save' && msg.model) {
        const cat = catalogRef.current;
        if (!cat || !editableRef.current) return;
        const next = designerToCanonical(msg.model, cat, modelRef.current);
        if (JSON.stringify(next) === JSON.stringify(modelRef.current)) return;
        lastFromDesigner.current = JSON.stringify(next);
        update(() => next);
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
    // The handler reads refs only, so it is attached once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [update]);

  const openSave = () => {
    setSaveOpen(true);
    setLatestModel(null);
    if (latest) api.get<ModelVersion>(`/projects/${data.project.id}/versions/${latest.version}`).then((v) => setLatestModel(v.model)).catch(() => undefined);
  };
  const saveVersion = async () => {
    await wm.flush();
    if (await mutate(() => api.post<ProjectData>(`/projects/${data.project.id}/versions`, { message }), 'Model version saved.')) {
      setSaveOpen(false);
      setMessage('');
    }
  };
  const openVersion = async (v: number) => {
    try { setViewVersion(await api.get<ModelVersion>(`/projects/${data.project.id}/versions/${v}`)); } catch (e) { toast.error(e); }
  };
  const restore = async (v: number) => {
    try {
      await wm.flush();
      const d = await api.post<ProjectData>(`/projects/${data.project.id}/versions/${v}/restore`);
      setData(d);
      wm.reset(d.model);
      setViewVersion(null);
      setVersionsOpen(false);
      toast.ok(`Working model restored from v${v}. Save a new version to record it.`);
    } catch (e) { toast.error(e); }
  };

  const exportJson = () => {
    const doc = { exportedAt: new Date().toISOString(), project: data.project.clientAlias, basedOnVersion: latest?.version ?? null, isDemo: data.project.isDemo, model };
    downloadBlob(new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' }), `${data.project.clientAlias}-architecture-model.json`.replace(/[^\w.-]/g, '_'));
  };
  const pickJson = (file: File) => {
    file.text().then((t) => {
      const parsed = JSON.parse(t);
      const m = (parsed.model ?? parsed) as ArchitectureModel;
      if (m.schema !== MODEL_SCHEMA || !Array.isArray(m.components) || !Array.isArray(m.flows) || !Array.isArray(m.zones)) throw new Error(`Not a canonical model (${MODEL_SCHEMA}).`);
      setPendingImport({ ...m, notes: m.notes ?? '' });
    }).catch((e) => toast.error(e));
  };
  const applyImport = () => {
    if (!pendingImport) return;
    const m = pendingImport;
    // Imported elements are unconfirmed until an analyst confirms them.
    update(() => ({
      ...m,
      components: m.components.map((c) => ({ ...c, status: 'unconfirmed', source: { kind: 'manual', ref: 'imported JSON model' } })),
      flows: m.flows.map((f) => ({ ...f, status: 'unconfirmed' })),
      zones: m.zones.map((z) => ({ ...z, status: 'unconfirmed' })),
    }));
    setPendingImport(null);
    toast.ok('Model imported. Its elements are unconfirmed until reviewed.');
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Architecture</h1>
          <div className="sub">Working model {latest ? `(last saved version v${latest.version})` : '(no saved version yet)'} · canonical schema <code>{MODEL_SCHEMA}</code></div>
        </div>
        <div className="actions">
          <button className="btn" onClick={() => setVersionsOpen(true)}><History size={16} /> Versions ({data.versions.length})</button>
          <button className="btn" onClick={exportJson}><Download size={16} /> JSON</button>
          {editable && <label className="btn"><Upload size={16} /> Import JSON<input type="file" accept="application/json,.json" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) pickJson(f); e.target.value = ''; }} /></label>}
          {editable && <button className="btn btn-primary" onClick={openSave}><Save size={16} /> Save version</button>}
        </div>
      </div>
      {wm.state === 'error' && <Callout tone="danger">The last change was rejected by the server: {wm.error}</Callout>}
      {!editable && <Callout tone="warn">Read-only. Changes made in the editor are not saved.</Callout>}
      {unconfirmed > 0 && <Callout tone="warn">{unconfirmed} unconfirmed element(s) will be excluded from threat analysis. Review them in <Link to="../imports">Imports &amp; evidence</Link>.</Callout>}
      {error && <Callout tone="warn">{error}</Callout>}

      <div className="card" style={{ padding: 0, overflow: 'hidden', marginTop: 10 }}>
        <iframe key={reloadKey} ref={frameRef} src="/designer/index.html" title="Architecture editor"
          style={{ display: 'block', width: '100%', height: '78vh', minHeight: 560, border: 0 }} />
      </div>

      {saveOpen && (
        <Modal title="Save model version" onClose={() => setSaveOpen(false)} footer={<>
          <button className="btn" onClick={() => setSaveOpen(false)}>Cancel</button>
          <button className="btn btn-primary" onClick={saveVersion}>Save version</button>
        </>}>
          <p className="muted small">Saving records an immutable version of the working model. Threat analysis runs on the latest saved version.</p>
          {latest && latestModel && <ChangeList d={diffModels(latestModel, model)} label={`Changes since v${latest.version}`} />}
          {!latest && <p className="small">This is the first version of this project.</p>}
          <label className="field-label" htmlFor="version-message">Version note</label>
          <input id="version-message" value={message} onChange={(e) => setMessage(e.target.value)} maxLength={300} placeholder="What changed and why" style={{ width: '100%' }} />
        </Modal>
      )}

      {versionsOpen && (
        <Modal title="Model versions" wide onClose={() => { setVersionsOpen(false); setViewVersion(null); }} footer={<button className="btn" onClick={() => { setVersionsOpen(false); setViewVersion(null); }}>Close</button>}>
          {!viewVersion && (
            <div className="table-wrap"><table>
              <thead><tr><th>Version</th><th>Saved</th><th>By</th><th>Note</th><th /></tr></thead>
              <tbody>
                {[...data.versions].reverse().map((v) => (
                  <tr key={v.version}>
                    <td>v{v.version}</td><td className="nowrap">{fmtDate(v.savedAt)}</td><td>{v.savedBy}</td><td>{v.message || <span className="muted">none</span>}</td>
                    <td className="nowrap"><button className="btn btn-sm" onClick={() => openVersion(v.version)}>Compare</button></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
          {viewVersion && (
            <div>
              <div className="row gap" style={{ marginBottom: 10 }}>
                <h3 className="grow" style={{ margin: 0 }}>v{viewVersion.version} compared with the working model</h3>
                {editable && <button className="btn btn-sm btn-danger" onClick={() => restore(viewVersion.version)}>Restore v{viewVersion.version} into working model</button>}
                <button className="btn btn-sm" onClick={() => setViewVersion(null)}>Back</button>
              </div>
              <ChangeList d={diffModels(viewVersion.model, model)} label="Working model relative to this version" />
            </div>
          )}
        </Modal>
      )}

      {pendingImport && (
        <Modal title="Import model" onClose={() => setPendingImport(null)} footer={<>
          <button className="btn" onClick={() => setPendingImport(null)}>Cancel</button>
          <button className="btn btn-danger" onClick={applyImport}>Replace working model</button>
        </>}>
          <p className="small">This replaces the working model with {pendingImport.components.length} components, {pendingImport.flows.length} flows and {pendingImport.zones.length} zones. Imported elements are marked unconfirmed. Nothing is saved as a version until you save one.</p>
        </Modal>
      )}
    </div>
  );
}

function ChangeList({ d, label }: { d: ReturnType<typeof diffModels>; label: string }) {
  const total = d.added.length + d.removed.length + d.changed.length;
  return (
    <div className="card card-pad" style={{ margin: '8px 0' }}>
      <div className="field-label">{label}</div>
      {total === 0 ? <div className="muted small">No changes.</div> : (
        <ul className="small" style={{ margin: '6px 0 0', paddingLeft: 18 }}>
          {d.added.map((x) => <li key={'a' + x}>Added: {x}</li>)}
          {d.removed.map((x) => <li key={'r' + x}>Removed: {x}</li>)}
          {d.changed.map((x) => <li key={'c' + x}>Changed: {x}</li>)}
        </ul>
      )}
    </div>
  );
}
