// Two-way conversion between the ArchGuard designer model (as saved by the prototype
// editor) and the workbench's canonical architecture model.
//
// Fields with no canonical equivalent are stored with a "designer." prefix:
//   - component properties: "designer.zone" and "designer.security.<key>"
//   - zone source note: "designer.trust=<label>"
// so that a round trip keeps the designer's data. Analyst-entered canonical fields
// that the designer does not show are kept when the designer saves.
import type { ArchComponent, ArchitectureModel, DataFlow, Tri, TrustZone, ZoneType } from './types';
import { defaultTypeFor, type CatalogItem } from './catalog';

export const DESIGNER_TRUST_OPTIONS = [
  'Unassigned', 'Internet / public', 'Third party', 'DMZ / edge', 'Application zone', 'Data zone', 'Restricted / high trust',
] as const;

export interface DesignerNode {
  id: string;
  componentId: string;
  label: string;
  x: number;
  y: number;
  zone: string;
  security: Record<string, string | number | boolean>;
}
export interface DesignerFlow {
  id: string;
  source: string;
  target: string;
  protocol: string;
  data: string;
  encrypted: string;
  authenticated: string;
  notes: string;
}
export interface DesignerZone { id: string; name: string; trust: string; x: number; y: number; w: number; h: number }
export interface DesignerModel {
  version: 1;
  name: string;
  created: string;
  updated: string;
  nodes: DesignerNode[];
  flows: DesignerFlow[];
  zones: DesignerZone[];
}

const TRUST_TO_ZONE: Record<string, { zoneType: ZoneType; trustLevel: number }> = {
  'Unassigned': { zoneType: 'user_zone', trustLevel: 2 },
  'Internet / public': { zoneType: 'internet', trustLevel: 0 },
  'Third party': { zoneType: 'third_party', trustLevel: 1 },
  'DMZ / edge': { zoneType: 'dmz', trustLevel: 1 },
  'Application zone': { zoneType: 'internal', trustLevel: 3 },
  'Data zone': { zoneType: 'restricted', trustLevel: 4 },
  'Restricted / high trust': { zoneType: 'restricted', trustLevel: 4 },
};

const ZONE_TO_TRUST: Partial<Record<ZoneType, string>> = {
  internet: 'Internet / public',
  third_party: 'Third party',
  dmz: 'DMZ / edge',
  internal: 'Application zone',
  cloud: 'Application zone',
  restricted: 'Data zone',
  management: 'Restricted / high trust',
  user_zone: 'Unassigned',
};

const TRI = ['yes', 'no', 'unknown'] as const;
const tri = (v: string): Tri => ((TRI as readonly string[]).includes(v) ? (v as Tri) : 'unknown');
const DESIGNER_ZONE_NOTE = 'designer.trust=';
const SEC_PREFIX = 'designer.security.';
const clip = (s: string, n: number) => s.slice(0, n);
const FLOW_CLASSES = ['public', 'internal', 'confidential', 'restricted'] as const;
/** The designer's flow "data" field is a sensitivity level (Public, Internal, Confidential, Restricted). */
const classificationOf = (v: string | undefined) => {
  const k = (v ?? '').trim().toLowerCase();
  return (FLOW_CLASSES as readonly string[]).includes(k) ? (k as (typeof FLOW_CLASSES)[number]) : undefined;
};

/** Designer model -> canonical model, keeping canonical fields the designer does not own. */
export function designerToCanonical(d: DesignerModel, catalog: CatalogItem[], base: ArchitectureModel): ArchitectureModel {
  const items = new Map(catalog.map((c) => [c.id, c]));
  const placeholderId = catalog[0]?.id;
  const prevComponents = new Map(base.components.map((c) => [c.id, c]));
  const prevFlows = new Map(base.flows.map((f) => [f.id, f]));
  const prevZones = new Map(base.zones.map((z) => [z.id, z]));

  const components: ArchComponent[] = d.nodes.map((n) => {
    const prev = prevComponents.get(n.id);
    const item = items.get(n.componentId);
    // The designer shows a placeholder catalog item when a component has none. Do not
    // record that placeholder as the component's origin.
    const keepsNoOrigin = prev && !prev.catalogRef && n.componentId === placeholderId;
    const catalogRef = item && !keepsNoOrigin ? { id: item.id, name: item.name, group: item.groupId } : prev?.catalogRef;
    const properties: Record<string, string> = { ...(prev?.properties ?? {}) };
    for (const k of Object.keys(properties)) if (k.startsWith('designer.')) delete properties[k];
    properties['designer.zone'] = clip(n.zone, 500);
    for (const [k, v] of Object.entries(n.security)) properties[SEC_PREFIX + k] = clip(String(v), 500);
    const type = prev && prev.catalogRef?.id === n.componentId && !keepsNoOrigin
      ? prev.type
      : item && !keepsNoOrigin ? defaultTypeFor(item) : prev?.type ?? 'app_server';
    return {
      id: n.id,
      type,
      name: clip(n.label || 'Component', 120),
      x: n.x,
      y: n.y,
      status: prev?.status ?? 'confirmed',
      source: prev?.source ?? { kind: 'manual' },
      properties,
      ...(catalogRef ? { catalogRef } : {}),
    };
  });

  const ids = new Set(components.map((c) => c.id));
  const flows: DataFlow[] = d.flows.filter((f) => ids.has(f.source) && ids.has(f.target)).map((f) => {
    const prev = prevFlows.get(f.id);
    const note = clip(f.notes ?? '', 500);
    return {
      ...(prev ?? {}),
      id: f.id,
      from: f.source,
      to: f.target,
      label: clip(f.data ?? '', 200),
      protocol: clip(f.protocol ?? '', 40),
      port: prev?.port ?? '',
      encrypted: tri(f.encrypted),
      authenticated: tri(f.authenticated),
      dataClassification: classificationOf(f.data) ?? prev?.dataClassification ?? 'unknown',
      bidirectional: prev?.bidirectional ?? false,
      status: prev?.status ?? 'confirmed',
      source: { ...(prev?.source ?? { kind: 'manual' }), ...(note ? { note } : { note: undefined }) },
    } as DataFlow;
  });

  const zones: TrustZone[] = d.zones.map((z) => {
    const prev = prevZones.get(z.id);
    const map = TRUST_TO_ZONE[z.trust] ?? TRUST_TO_ZONE.Unassigned;
    return {
      ...(prev ?? {}),
      id: z.id,
      name: clip(z.name || 'Trust boundary', 120),
      zoneType: map.zoneType,
      trustLevel: map.trustLevel,
      x: z.x,
      y: z.y,
      w: Math.max(180, z.w),
      h: Math.max(100, z.h),
      status: prev?.status ?? 'confirmed',
      source: { ...(prev?.source ?? { kind: 'manual' }), note: DESIGNER_ZONE_NOTE + z.trust },
    } as TrustZone;
  });

  return { ...base, components, flows, zones };
}

/** Canonical model -> designer model. Components with no designer data show as "Unassigned". */
export function canonicalToDesigner(m: ArchitectureModel, projectName: string, fallbackComponentId: string): DesignerModel {
  const nodes: DesignerNode[] = m.components.map((c) => {
    const security: Record<string, string> = {};
    for (const [k, v] of Object.entries(c.properties)) if (k.startsWith(SEC_PREFIX)) security[k.slice(SEC_PREFIX.length)] = v;
    return {
      id: c.id,
      componentId: c.catalogRef?.id ?? fallbackComponentId,
      label: c.name,
      x: c.x,
      y: c.y,
      zone: c.properties['designer.zone'] ?? 'Unassigned',
      security,
    };
  });
  const flows: DesignerFlow[] = m.flows.map((f) => ({
    id: f.id,
    source: f.from,
    target: f.to,
    protocol: f.protocol,
    data: f.label,
    encrypted: f.encrypted,
    authenticated: f.authenticated,
    notes: f.source.note && !f.source.note.startsWith(DESIGNER_ZONE_NOTE) ? f.source.note : '',
  }));
  const zones: DesignerZone[] = m.zones.map((z) => {
    const note = z.source.note ?? '';
    const trust = note.startsWith(DESIGNER_ZONE_NOTE) ? note.slice(DESIGNER_ZONE_NOTE.length) : ZONE_TO_TRUST[z.zoneType] ?? 'Unassigned';
    return { id: z.id, name: z.name, trust, x: z.x, y: z.y, w: z.w, h: z.h };
  });
  return { version: 1, name: projectName, created: new Date().toISOString(), updated: new Date().toISOString(), nodes, flows, zones };
}
