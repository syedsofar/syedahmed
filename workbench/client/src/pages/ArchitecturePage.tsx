import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ZoomIn, ZoomOut, Undo2, Save, History, Download, Upload, SquareDashed, Maximize2 } from 'lucide-react';
import { api, downloadBlob, uid } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useProject } from '../lib/project';
import { useWorkingModel } from '../lib/model';
import { DiagramSvg, type Selection } from '../components/DiagramSvg';
import { Inspector } from '../components/Inspector';
import { Badge, Callout, Field, Modal, fmtDate, useToast } from '../components/ui';
import { COMPONENTS, COMPONENT_TYPES, ZONES } from '@shared/schema';
import { NODE_H, NODE_W } from '@shared/engine';
import { diffModels } from '@shared/diff';
import type { ArchComponent, ArchitectureModel, ComponentType, DataFlow, ModelVersion, ProjectData } from '@shared/types';
import { defaultTypeFor, type CatalogItem } from '@shared/catalog';
import { CatalogPalette } from '../components/CatalogPalette';
import { MODEL_SCHEMA } from '@shared/types';

type Drag =
  | { kind: 'node'; id: string; dx: number; dy: number; snapshot: ArchitectureModel; moved: boolean }
  | { kind: 'zone'; id: string; sx: number; sy: number; ox: number; oy: number; children: { id: string; x: number; y: number }[]; snapshot: ArchitectureModel; moved: boolean }
  | { kind: 'resize'; id: string; sx: number; sy: number; ow: number; oh: number; snapshot: ArchitectureModel }
  | { kind: 'connect'; from: string };

const snap = (n: number) => Math.round(n / 10) * 10;

export function ArchitecturePage() {
  const { data, setData, mutate } = useProject();
  const { userName } = useAuth();
  const toast = useToast();
  const wm = useWorkingModel();
  const { model, update, editable } = wm;
  const [sel, setSel] = useState<Selection>(null);
  const [scale, setScale] = useState(1);
  const [ghost, setGhost] = useState<{ x1: number; y1: number; x2: number; y2: number } | null>(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [message, setMessage] = useState('');
  const [versionsOpen, setVersionsOpen] = useState(false);
  const [viewVersion, setViewVersion] = useState<ModelVersion | null>(null);
  const [importJson, setImportJson] = useState<{ model: ArchitectureModel; unconfirm: boolean } | null>(null);
  const [latestModel, setLatestModel] = useState<ArchitectureModel | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const drag = useRef<Drag | null>(null);
  const modelRef = useRef(model);
  modelRef.current = model;

  const fit = () => {
    if (!wrapRef.current || !svgRef.current) return;
    const w = wrapRef.current.clientWidth - 8;
    const b = svgRef.current.viewBox.baseVal.width;
    setScale(Math.max(0.4, Math.min(1, +(w / b).toFixed(2))));
  };
  useEffect(() => { fit(); }, []);

  const toSvg = (clientX: number, clientY: number) => {
    const r = svgRef.current!.getBoundingClientRect();
    return { x: (clientX - r.left) / scale, y: (clientY - r.top) / scale };
  };

  const hitNode = (x: number, y: number) => [...modelRef.current.components].reverse().find((c) => x >= c.x && x <= c.x + NODE_W && y >= c.y && y <= c.y + NODE_H);

  const onMove = useCallback((e: PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const p = toSvg(e.clientX, e.clientY);
    if (d.kind === 'node') {
      d.moved = true;
      update((m) => ({ ...m, components: m.components.map((c) => (c.id === d.id ? { ...c, x: Math.max(0, snap(p.x - d.dx)), y: Math.max(0, snap(p.y - d.dy)) } : c)) }), { transient: true });
    } else if (d.kind === 'zone') {
      d.moved = true;
      const dx = snap(p.x - d.sx), dy = snap(p.y - d.sy);
      update((m) => ({
        ...m,
        zones: m.zones.map((z) => (z.id === d.id ? { ...z, x: Math.max(0, d.ox + dx), y: Math.max(0, d.oy + dy) } : z)),
        components: m.components.map((c) => { const ch = d.children.find((x) => x.id === c.id); return ch ? { ...c, x: Math.max(0, ch.x + dx), y: Math.max(0, ch.y + dy) } : c; }),
      }), { transient: true });
    } else if (d.kind === 'resize') {
      update((m) => ({ ...m, zones: m.zones.map((z) => (z.id === d.id ? { ...z, w: Math.max(160, snap(d.ow + p.x - d.sx)), h: Math.max(110, snap(d.oh + p.y - d.sy)) } : z)) }), { transient: true });
    } else if (d.kind === 'connect') {
      const from = modelRef.current.components.find((c) => c.id === d.from)!;
      setGhost({ x1: from.x + NODE_W, y1: from.y + NODE_H / 2, x2: p.x, y2: p.y });
    }
  }, [scale, update]);

  const onUp = useCallback((e: PointerEvent) => {
    const d = drag.current;
    drag.current = null;
    window.removeEventListener('pointermove', onMove);
    window.removeEventListener('pointerup', onUp);
    if (!d) return;
    if ((d.kind === 'node' || d.kind === 'zone') && d.moved) wm.pushUndo(d.snapshot);
    if (d.kind === 'resize') wm.pushUndo(d.snapshot);
    if (d.kind === 'connect') {
      setGhost(null);
      const p = toSvg(e.clientX, e.clientY);
      const target = hitNode(p.x, p.y);
      if (target && target.id !== d.from) {
        const f: DataFlow = { id: uid('f'), from: d.from, to: target.id, label: '', protocol: '', port: '', encrypted: 'unknown', authenticated: 'unknown', dataClassification: 'unknown', bidirectional: false, status: 'confirmed', source: { kind: 'manual' } };
        update((m) => ({ ...m, flows: [...m.flows, f] }));
        setSel({ kind: 'flow', id: f.id });
      }
    }
  }, [onMove, update, scale]);

  const begin = (d: Drag) => {
    drag.current = d;
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
  };

  const handlers = editable ? {
    onNodeDown: (e: React.PointerEvent, c: ArchComponent) => {
      e.stopPropagation();
      setSel({ kind: 'component', id: c.id });
      const p = toSvg(e.clientX, e.clientY);
      begin({ kind: 'node', id: c.id, dx: p.x - c.x, dy: p.y - c.y, snapshot: model, moved: false });
    },
    onHandleDown: (e: React.PointerEvent, c: ArchComponent) => { e.stopPropagation(); begin({ kind: 'connect', from: c.id }); },
    onZoneDown: (e: React.PointerEvent, id: string) => {
      e.stopPropagation();
      setSel({ kind: 'zone', id });
      const z = model.zones.find((x) => x.id === id)!;
      const p = toSvg(e.clientX, e.clientY);
      const inside = model.components.filter((c) => { const cx = c.x + NODE_W / 2, cy = c.y + NODE_H / 2; return cx >= z.x && cx <= z.x + z.w && cy >= z.y && cy <= z.y + z.h; });
      begin({ kind: 'zone', id, sx: p.x, sy: p.y, ox: z.x, oy: z.y, children: inside.map((c) => ({ id: c.id, x: c.x, y: c.y })), snapshot: model, moved: false });
    },
    onZoneResizeDown: (e: React.PointerEvent, id: string) => {
      const z = model.zones.find((x) => x.id === id)!;
      const p = toSvg(e.clientX, e.clientY);
      begin({ kind: 'resize', id, sx: p.x, sy: p.y, ow: z.w, oh: z.h, snapshot: model });
    },
    onFlowDown: (e: React.PointerEvent, f: DataFlow) => { e.stopPropagation(); setSel({ kind: 'flow', id: f.id }); },
  } : {
    onNodeDown: (_e: React.PointerEvent, c: ArchComponent) => setSel({ kind: 'component', id: c.id }),
    onZoneDown: (_e: React.PointerEvent, id: string) => setSel({ kind: 'zone', id }),
    onFlowDown: (_e: React.PointerEvent, f: DataFlow) => setSel({ kind: 'flow', id: f.id }),
  };

  const addComponent = (type: ComponentType, x?: number, y?: number, catalog?: CatalogItem) => {
    const wrap = wrapRef.current!;
    const c: ArchComponent = {
      id: uid('c'), type, name: catalog ? catalog.name : `New ${COMPONENTS[type].label}`,
      x: snap(x ?? wrap.scrollLeft / scale + 60 + Math.random() * 60), y: snap(y ?? wrap.scrollTop / scale + 60 + Math.random() * 60),
      status: 'confirmed', source: { kind: 'manual' }, properties: {},
      ...(catalog ? { catalogRef: { id: catalog.id, name: catalog.name, group: catalog.groupId } } : {}),
    };
    update((m) => ({ ...m, components: [...m.components, c] }));
    setSel({ kind: 'component', id: c.id });
  };

  const addZone = () => {
    const wrap = wrapRef.current!;
    const z = { id: uid('z'), name: 'New zone', zoneType: 'internal' as const, trustLevel: ZONES.internal.trust, x: snap(wrap.scrollLeft / scale + 40), y: snap(wrap.scrollTop / scale + 40), w: 360, h: 240, status: 'confirmed' as const, source: { kind: 'manual' as const } };
    update((m) => ({ ...m, zones: [...m.zones, z] }));
    setSel({ kind: 'zone', id: z.id });
  };

  const deleteSel = useCallback(() => {
    if (!sel || !editable) return;
    update((m) => sel.kind === 'component'
      ? { ...m, components: m.components.filter((c) => c.id !== sel.id), flows: m.flows.filter((f) => f.from !== sel.id && f.to !== sel.id) }
      : sel.kind === 'flow' ? { ...m, flows: m.flows.filter((f) => f.id !== sel.id) } : { ...m, zones: m.zones.filter((z) => z.id !== sel.id) });
    setSel(null);
  }, [sel, editable, update]);

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (/INPUT|TEXTAREA|SELECT/.test(t.tagName)) return;
      if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); deleteSel(); }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'z') { e.preventDefault(); wm.undo(); }
      if (e.key === 'Escape') setSel(null);
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [deleteSel, wm]);

  const saveVersion = async () => {
    await wm.flush();
    if (await mutate(() => api.post<ProjectData>(`/projects/${data.project.id}/versions`, { message }), 'Model version saved.')) { setSaveOpen(false); setMessage(''); }
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
    const latest = data.versions[data.versions.length - 1];
    const doc = { exportedAt: new Date().toISOString(), project: data.project.clientAlias, basedOnVersion: latest?.version ?? null, isDemo: data.project.isDemo, model };
    downloadBlob(new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' }), `${data.project.clientAlias}-architecture-model.json`.replace(/[^\w.-]/g, '_'));
  };
  const pickJson = (file: File) => {
    file.text().then((t) => {
      const parsed = JSON.parse(t);
      const m = (parsed.model ?? parsed) as ArchitectureModel;
      if (m.schema !== MODEL_SCHEMA || !Array.isArray(m.components) || !Array.isArray(m.flows) || !Array.isArray(m.zones)) throw new Error(`Not a canonical model (${MODEL_SCHEMA}).`);
      setImportJson({ model: { ...m, notes: m.notes ?? '' }, unconfirm: true });
    }).catch((e) => toast.error(e));
  };
  const applyJson = () => {
    if (!importJson) return;
    const m = importJson.model;
    const st = importJson.unconfirm ? 'unconfirmed' as const : undefined;
    update(() => ({
      ...m,
      components: m.components.map((c) => ({ ...c, status: st ?? c.status, source: st ? { kind: 'manual', ref: 'imported JSON model' } : c.source })),
      flows: m.flows.map((f) => ({ ...f, status: st ?? f.status })),
      zones: m.zones.map((z) => ({ ...z, status: st ?? z.status })),
    }));
    setImportJson(null);
    setSel(null);
  };

  const latest = data.versions[data.versions.length - 1];
  const stateBadge = { saved: <Badge tone="ok">All changes saved</Badge>, pending: <Badge tone="warn">Unsaved changes…</Badge>, saving: <Badge tone="teal">Saving…</Badge>, error: <Badge tone="danger" title={wm.error}>Save failed</Badge>, readonly: <Badge>Read-only</Badge> }[wm.state];
  const counts = { u: model.components.filter((c) => c.status !== 'confirmed').length + model.flows.filter((f) => f.status !== 'confirmed').length + model.zones.filter((z) => z.status !== 'confirmed').length };

  return (
    <div className="page" style={{ maxWidth: 'none' }}>
      <div className="page-head">
        <div>
          <h1>Architecture editor</h1>
          <div className="sub">Working model {latest ? `(last saved version v${latest.version})` : '(no saved version yet)'} · canonical schema <code>{MODEL_SCHEMA}</code></div>
        </div>
        <div className="actions">
          {stateBadge}
          <button className="btn" onClick={() => setVersionsOpen(true)}><History size={16} /> Versions ({data.versions.length})</button>
          <button className="btn" onClick={exportJson}><Download size={16} /> JSON</button>
          {editable && <label className="btn"><Upload size={16} /> Import JSON<input type="file" accept="application/json,.json" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) pickJson(f); e.target.value = ''; }} /></label>}
          {editable && <button className="btn btn-primary" onClick={() => {
            setSaveOpen(true);
            setLatestModel(null);
            const lv = data.versions[data.versions.length - 1];
            if (lv) api.get<ModelVersion>(`/projects/${data.project.id}/versions/${lv.version}`).then((v) => setLatestModel(v.model)).catch(() => undefined);
          }}><Save size={16} /> Save version</button>}
        </div>
      </div>
      {wm.state === 'error' && <Callout tone="danger">The last change was rejected by the server: {wm.error}</Callout>}
      {counts.u > 0 && <Callout tone="warn">{counts.u} unconfirmed element(s) (dashed) will be excluded from threat analysis. Review them here or in <Link to="../imports">Imports &amp; evidence</Link>.</Callout>}

      <div className="editor" style={{ marginTop: 10 }}>
        <div className="palette card card-pad" aria-label="Component palette">
          <div className="field-label" style={{ marginBottom: 8 }}>Components {editable ? <span className="muted small">— drag or click</span> : null}</div>
          {COMPONENT_TYPES.map((t) => (
            <div key={t} className="palette-item" draggable={editable} role="button" tabIndex={0} aria-disabled={!editable}
              onDragStart={(e) => e.dataTransfer.setData('application/x-sawb-type', t)}
              onClick={() => editable && addComponent(t)} onKeyDown={(e) => e.key === 'Enter' && editable && addComponent(t)}>
              <span className="palette-swatch" style={{ background: COMPONENTS[t].color }}>{COMPONENTS[t].short}</span>{COMPONENTS[t].label}
            </div>
          ))}
          <CatalogPalette editable={editable} onAdd={(item) => addComponent(defaultTypeFor(item), undefined, undefined, item)} />
          {editable && <button className="btn btn-sm" style={{ width: '100%', marginTop: 6 }} onClick={addZone}><SquareDashed size={14} /> Add trust zone</button>}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          <div className="canvas-toolbar">
            <button className="btn btn-sm" onClick={() => setScale((s) => Math.max(0.4, +(s - 0.1).toFixed(2)))} aria-label="Zoom out"><ZoomOut size={14} /></button>
            <span className="small muted" style={{ width: 42, textAlign: 'center' }}>{Math.round(scale * 100)}%</span>
            <button className="btn btn-sm" onClick={() => setScale((s) => Math.min(2, +(s + 0.1).toFixed(2)))} aria-label="Zoom in"><ZoomIn size={14} /></button>
            <button className="btn btn-sm" onClick={fit}><Maximize2 size={14} /> Fit</button>
            {editable && <button className="btn btn-sm" onClick={wm.undo} disabled={!wm.canUndo}><Undo2 size={14} /> Undo</button>}
            <span className="small muted right">{model.components.length} components · {model.flows.length} flows · {model.zones.length} zones</span>
          </div>
          <div ref={wrapRef} className={`canvas-wrap ${ghost ? 'connecting' : ''}`} style={{ flex: 1 }}
            onPointerDown={(e) => { if (e.target === e.currentTarget || (e.target as Element).tagName === 'svg') setSel(null); }}
            onDragOver={(e) => editable && e.preventDefault()}
            onDrop={(e) => {
              const t = e.dataTransfer.getData('application/x-sawb-type') as ComponentType;
              if (!t || !editable) return;
              e.preventDefault();
              const p = toSvg(e.clientX, e.clientY);
              addComponent(t, p.x - NODE_W / 2, p.y - NODE_H / 2);
            }}>
            <DiagramSvg ref={svgRef} model={model} selection={sel} scale={scale} interactive ghostLine={ghost} {...handlers} />
            {model.components.length === 0 && model.zones.length === 0 && (
              <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', pointerEvents: 'none' }}>
                <div className="empty"><h3>Empty canvas</h3><div className="muted">Drag components from the palette, add trust zones, or <Link to="../imports" style={{ pointerEvents: 'auto' }}>import a Draw.io diagram</Link>.</div></div>
              </div>
            )}
          </div>
        </div>

        <div className="inspector card card-pad">
          <Inspector model={model} selection={sel} editable={editable} onChange={(fn) => update(fn)} onDelete={deleteSel} />
        </div>
      </div>

      {saveOpen && (
        <Modal title="Save model version" onClose={() => setSaveOpen(false)} footer={<><button className="btn" onClick={() => setSaveOpen(false)}>Cancel</button><button className="btn btn-primary" disabled={!message.trim()} onClick={saveVersion}>Save v{(latest?.version ?? 0) + 1}</button></>}>
          <p className="muted small">A version is an immutable, hashed snapshot of the canonical model. Threat analysis always runs against a saved version, so findings remain traceable.</p>
          <Field label="Version message *"><input type="text" value={message} onChange={(e) => setMessage(e.target.value)} maxLength={300} placeholder="e.g. Added payment partner integration from HLD 2.4" autoFocus /></Field>
          {latest && latestModel && <ChangeList d={diffModels(latestModel, model)} label={`Changes since v${latest.version}`} />}
        </Modal>
      )}
      {versionsOpen && (
        <Modal title="Model versions" wide onClose={() => { setVersionsOpen(false); setViewVersion(null); }}>
          {data.versions.length === 0 ? <p className="muted">No versions saved yet.</p> : (
            <table className="table"><thead><tr><th>Version</th><th>Message</th><th>Saved</th><th>Hash</th><th /></tr></thead><tbody>
              {[...data.versions].reverse().map((v) => (
                <tr key={v.version} className={viewVersion?.version === v.version ? 'selected' : ''}>
                  <td><strong>v{v.version}</strong></td><td>{v.message}</td><td className="small nowrap">{fmtDate(v.savedAt)}<br />{userName(v.savedBy)}</td><td className="mono">{v.hash.slice(0, 12)}</td>
                  <td className="nowrap"><button className="btn btn-sm" onClick={() => openVersion(v.version)}>Compare</button></td>
                </tr>
              ))}
            </tbody></table>
          )}
          {viewVersion && (
            <div className="card card-pad" style={{ marginTop: 14 }}>
              <div className="row gap"><h3 className="grow">v{viewVersion.version} compared with the working model</h3>{editable && <button className="btn btn-sm btn-danger" onClick={() => restore(viewVersion.version)}>Restore v{viewVersion.version} as working model</button>}</div>
              <ChangeList d={diffModels(viewVersion.model, model)} label="Working model relative to this version" />
              <div className="canvas-wrap" style={{ maxHeight: 360, marginTop: 10 }}><DiagramSvg model={viewVersion.model} scale={0.6} /></div>
            </div>
          )}
        </Modal>
      )}
      {importJson && (
        <Modal title="Import canonical model JSON" onClose={() => setImportJson(null)} footer={<><button className="btn" onClick={() => setImportJson(null)}>Cancel</button><button className="btn btn-primary" onClick={applyJson}>Replace working model</button></>}>
          <p>The file contains {importJson.model.components.length} components, {importJson.model.flows.length} flows and {importJson.model.zones.length} zones. It will replace the current working model (saved versions are unaffected and the change can be undone).</p>
          <label className="check"><input type="checkbox" checked={importJson.unconfirm} onChange={(e) => setImportJson({ ...importJson, unconfirm: e.target.checked })} /> Mark all imported elements as unconfirmed so they are reviewed before analysis (recommended)</label>
        </Modal>
      )}
    </div>
  );
}

function ChangeList({ d, label }: { d: ReturnType<typeof diffModels>; label: string }) {
  const total = d.added.length + d.removed.length + d.changed.length;
  return (
    <div className="small" style={{ marginTop: 10 }}>
      <div className="field-label">{label}</div>
      {total === 0 ? <p className="muted">No differences.</p> : (
        <ul className="list-plain">
          {d.added.map((x) => <li key={'a' + x}><Badge tone="ok">added</Badge> {x}</li>)}
          {d.removed.map((x) => <li key={'r' + x}><Badge tone="danger">removed</Badge> {x}</li>)}
          {d.changed.map((x) => <li key={'c' + x}><Badge tone="warn">changed</Badge> {x}</li>)}
        </ul>
      )}
    </div>
  );
}
