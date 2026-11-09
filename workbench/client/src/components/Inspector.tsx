import { Trash2, CheckCircle2, ArrowLeftRight, AlertTriangle } from 'lucide-react';
import type { ArchComponent, ArchitectureModel, ComponentType, DataFlow, Tri, TrustZone, ZoneType } from '@shared/types';
import { COMPONENTS, COMPONENT_TYPES, SECURE_PROTOCOLS, INSECURE_PROTOCOLS, ZONES, protocolSecurity } from '@shared/schema';
import { ModelView } from '@shared/engine';
import { Badge, Field } from './ui';
import type { Selection } from './DiagramSvg';

export function TriToggle({ value, onChange, disabled }: { value: string; onChange: (v: Tri) => void; disabled?: boolean }) {
  const v = (value || 'unknown') as Tri;
  return (
    <div className="tri" role="radiogroup">
      {(['yes', 'no', 'unknown'] as Tri[]).map((o) => (
        <button key={o} type="button" disabled={disabled} className={v === o ? `on-${o}` : ''} aria-pressed={v === o} onClick={() => onChange(o)}>{o === 'unknown' ? '?' : o}</button>
      ))}
    </div>
  );
}

function SourceInfo({ s, status }: { s: ArchComponent['source']; status: string }) {
  return (
    <div className="small muted">
      Source: <strong>{s.kind}</strong>{s.ref ? ` — ${s.ref}` : ''}{s.location ? ` (${s.location})` : ''} · {status === 'confirmed' ? <Badge tone="ok">confirmed</Badge> : <Badge tone="warn">unconfirmed</Badge>}
    </div>
  );
}

interface Props {
  model: ArchitectureModel;
  selection: Selection;
  editable: boolean;
  onChange: (fn: (m: ArchitectureModel) => ArchitectureModel) => void;
  onDelete: () => void;
  inference?: Record<string, string>;
}

export function Inspector({ model, selection, editable, onChange, onDelete, inference }: Props) {
  if (!selection) return <ModelSummary model={model} editable={editable} onChange={onChange} />;
  if (selection.kind === 'component') {
    const c = model.components.find((x) => x.id === selection.id);
    if (!c) return null;
    const setC = (patch: Partial<ArchComponent>) => onChange((m) => ({ ...m, components: m.components.map((x) => (x.id === c.id ? { ...x, ...patch } : x)) }));
    const setProp = (k: string, v: string) => setC({ properties: { ...c.properties, [k]: v } });
    const def = COMPONENTS[c.type];
    const zone = new ModelView({ ...model, components: model.components.map((x) => ({ ...x, status: 'confirmed' as const })), zones: model.zones.map((z) => ({ ...z, status: 'confirmed' as const })) }).zoneOf(c);
    return (
      <div className="stack">
        <div className="row gap"><h3 className="grow">Component</h3>{editable && <button className="icon-btn" title="Delete component" onClick={onDelete}><Trash2 size={16} /></button>}</div>
        <SourceInfo s={c.source} status={c.status} />
        {(inference?.[c.id] ?? c.source.note) && <div className="callout callout-info small">{inference?.[c.id] ?? c.source.note}</div>}
        {editable && c.status !== 'confirmed' && <button className="btn btn-teal btn-sm" onClick={() => setC({ status: 'confirmed' })}><CheckCircle2 size={14} /> Confirm component</button>}
        {editable && c.status === 'confirmed' && <button className="btn btn-sm" onClick={() => setC({ status: 'unconfirmed' })}>Mark unconfirmed</button>}
        <Field label="Name"><input type="text" value={c.name} maxLength={120} disabled={!editable} onChange={(e) => setC({ name: e.target.value })} /></Field>
        <Field label="Type">
          <select value={c.type} disabled={!editable} onChange={(e) => setC({ type: e.target.value as ComponentType })}>
            {COMPONENT_TYPES.map((t) => <option key={t} value={t}>{COMPONENTS[t].label}</option>)}
          </select>
        </Field>
        <div className="small">Security zone: {zone ? <Badge tone="teal">{zone.name} (trust {zone.trustLevel})</Badge> : <Badge tone="warn">not placed in a zone</Badge>} <span className="muted">— determined by position on canvas</span></div>
        <div>
          <div className="field-label" style={{ marginBottom: 4 }}>Properties <span className="muted small">(record only what is evidenced; leave “?” when unknown)</span></div>
          {def.props.map((p) => (
            <div key={p.key} className="prop-row">
              <span>{p.label}</span>
              {p.kind === 'tri' ? <TriToggle value={c.properties[p.key]} disabled={!editable} onChange={(v) => setProp(p.key, v)} />
                : p.kind === 'select' ? (
                  <select value={c.properties[p.key] ?? 'unknown'} disabled={!editable} onChange={(e) => setProp(p.key, e.target.value)}>
                    {p.options!.map((o) => <option key={o} value={o}>{o.replace('_', ' ')}</option>)}
                  </select>
                ) : <input type="text" value={c.properties[p.key] ?? ''} disabled={!editable} maxLength={500} onChange={(e) => setProp(p.key, e.target.value)} />}
            </div>
          ))}
        </div>
      </div>
    );
  }
  if (selection.kind === 'flow') {
    const f = model.flows.find((x) => x.id === selection.id);
    if (!f) return null;
    const setF = (patch: Partial<DataFlow>) => onChange((m) => ({ ...m, flows: m.flows.map((x) => (x.id === f.id ? { ...x, ...patch } : x)) }));
    const name = (id: string) => model.components.find((c) => c.id === id)?.name ?? '?';
    const sec = protocolSecurity(f.protocol);
    return (
      <div className="stack">
        <div className="row gap"><h3 className="grow">Data flow</h3>{editable && <button className="icon-btn" title="Delete flow" onClick={onDelete}><Trash2 size={16} /></button>}</div>
        <SourceInfo s={f.source} status={f.status} />
        {(inference?.[f.id] ?? f.source.note) && <div className="callout callout-info small">{inference?.[f.id] ?? f.source.note}</div>}
        <div className="row gap"><strong className="grow">{name(f.from)} → {name(f.to)}</strong>{editable && <button className="icon-btn" title="Reverse direction" onClick={() => setF({ from: f.to, to: f.from })}><ArrowLeftRight size={16} /></button>}</div>
        {editable && f.status !== 'confirmed' && <button className="btn btn-teal btn-sm" onClick={() => setF({ status: 'confirmed' })}><CheckCircle2 size={14} /> Confirm flow</button>}
        {editable && f.status === 'confirmed' && <button className="btn btn-sm" onClick={() => setF({ status: 'unconfirmed' })}>Mark unconfirmed</button>}
        <Field label="Label / purpose"><input type="text" value={f.label} maxLength={200} disabled={!editable} onChange={(e) => setF({ label: e.target.value })} /></Field>
        <div className="form-grid">
          <Field label="Protocol" hint={sec === 'insecure' ? 'Plaintext protocol' : sec === 'secure' ? 'Recognised secure protocol' : undefined}>
            <input type="text" list="protocols" value={f.protocol} maxLength={40} disabled={!editable} onChange={(e) => setF({ protocol: e.target.value })} />
          </Field>
          <Field label="Port"><input type="text" value={f.port} maxLength={20} disabled={!editable} onChange={(e) => setF({ port: e.target.value })} /></Field>
        </div>
        <datalist id="protocols">{[...SECURE_PROTOCOLS, ...INSECURE_PROTOCOLS, 'jdbc', 'tcp', 'udp', 'rdp', 'kafka'].map((p) => <option key={p} value={p.toUpperCase()} />)}</datalist>
        <div className="prop-row"><span>Encrypted in transit</span><TriToggle value={f.encrypted} disabled={!editable} onChange={(v) => setF({ encrypted: v })} /></div>
        <div className="prop-row"><span>Endpoints authenticated</span><TriToggle value={f.authenticated} disabled={!editable} onChange={(v) => setF({ authenticated: v })} /></div>
        <Field label="Data classification">
          <select value={f.dataClassification} disabled={!editable} onChange={(e) => setF({ dataClassification: e.target.value as DataFlow['dataClassification'] })}>
            {['unknown', 'public', 'internal', 'confidential', 'restricted'].map((o) => <option key={o}>{o}</option>)}
          </select>
        </Field>
        <label className="check"><input type="checkbox" checked={f.bidirectional} disabled={!editable} onChange={(e) => setF({ bidirectional: e.target.checked })} />Bidirectional</label>
        {sec === 'insecure' && f.encrypted === 'yes' && <div className="callout callout-warn small"><AlertTriangle size={14} /> Protocol is normally plaintext but encryption is recorded as yes. Confirm the evidence.</div>}
      </div>
    );
  }
  const z = model.zones.find((x) => x.id === selection.id);
  if (!z) return null;
  const setZ = (patch: Partial<TrustZone>) => onChange((m) => ({ ...m, zones: m.zones.map((x) => (x.id === z.id ? { ...x, ...patch } : x)) }));
  return (
    <div className="stack">
      <div className="row gap"><h3 className="grow">Trust boundary / security zone</h3>{editable && <button className="icon-btn" title="Delete zone" onClick={onDelete}><Trash2 size={16} /></button>}</div>
      <SourceInfo s={z.source} status={z.status} />
      {(inference?.[z.id] ?? z.source.note) && <div className="callout callout-info small">{inference?.[z.id] ?? z.source.note}</div>}
      {editable && z.status !== 'confirmed' && <button className="btn btn-teal btn-sm" onClick={() => setZ({ status: 'confirmed' })}><CheckCircle2 size={14} /> Confirm zone</button>}
      <Field label="Name"><input type="text" value={z.name} maxLength={120} disabled={!editable} onChange={(e) => setZ({ name: e.target.value })} /></Field>
      <Field label="Zone classification">
        <select value={z.zoneType} disabled={!editable} onChange={(e) => { const t = e.target.value as ZoneType; setZ({ zoneType: t, trustLevel: ZONES[t].trust }); }}>
          {(Object.keys(ZONES) as ZoneType[]).map((t) => <option key={t} value={t}>{ZONES[t].label}</option>)}
        </select>
      </Field>
      <Field label={`Trust level: ${z.trustLevel}`} hint="0 = untrusted (internet) … 4 = highly trusted (restricted / management)">
        <input type="range" min={0} max={4} step={1} value={z.trustLevel} disabled={!editable} onChange={(e) => setZ({ trustLevel: Number(e.target.value) })} />
      </Field>
      <p className="muted small">Components whose centre lies inside this rectangle belong to the zone. Any data flow between components in different zones crosses a trust boundary.</p>
    </div>
  );
}

function ModelSummary({ model, editable, onChange }: { model: ArchitectureModel; editable: boolean; onChange: Props['onChange'] }) {
  const v = new ModelView(model);
  const unplaced = v.comps.filter((c) => !v.zoneOf(c)).length;
  const unconf = model.components.filter((c) => c.status !== 'confirmed').length + model.flows.filter((f) => f.status !== 'confirmed').length + model.zones.filter((z) => z.status !== 'confirmed').length;
  return (
    <div className="stack">
      <h3>Model</h3>
      <dl className="kv" style={{ gridTemplateColumns: '1fr auto' }}>
        <dt>Components</dt><dd>{model.components.length}</dd>
        <dt>Data flows</dt><dd>{model.flows.length}</dd>
        <dt>Zones</dt><dd>{model.zones.length}</dd>
        <dt>Unconfirmed elements</dt><dd>{unconf ? <Badge tone="warn">{unconf}</Badge> : 0}</dd>
        <dt>Confirmed comps. outside zones</dt><dd>{unplaced ? <Badge tone="warn">{unplaced}</Badge> : 0}</dd>
      </dl>
      <div>
        <div className="field-label">Legend</div>
        <div className="small stack" style={{ gap: 2 }}>
          <div className="row gap-s"><span style={{ width: 24, borderTop: '2px solid #0f8b8d' }} /> encrypted</div>
          <div className="row gap-s"><span style={{ width: 24, borderTop: '2px solid #c08a2c' }} /> encryption unknown</div>
          <div className="row gap-s"><span style={{ width: 24, borderTop: '2px solid #b5443c' }} /> not encrypted</div>
          <div className="row gap-s"><span style={{ width: 24, borderTop: '2px dashed #9aa5a0' }} /> unconfirmed (excluded from analysis)</div>
        </div>
      </div>
      <Field label="Model notes / assumptions"><textarea rows={5} value={model.notes} maxLength={5000} disabled={!editable} onChange={(e) => onChange((m) => ({ ...m, notes: e.target.value }))} /></Field>
      <p className="muted small">Select a component, flow or zone to edit it. Drag a component's teal handle onto another component to create a data flow. Press Delete to remove the selection.</p>
    </div>
  );
}
