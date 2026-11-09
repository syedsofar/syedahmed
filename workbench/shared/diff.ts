import type { ArchitectureModel } from './types';
import { canonicalJson } from './schema';

export interface ModelDiff {
  added: string[];
  removed: string[];
  changed: string[];
}

/** Human-readable difference between two canonical models (by element id). */
export function diffModels(from: ArchitectureModel, to: ArchitectureModel): ModelDiff {
  const out: ModelDiff = { added: [], removed: [], changed: [] };
  const name = (m: ArchitectureModel, id: string) => m.components.find((c) => c.id === id)?.name ?? '?';
  const sets = [
    { kind: 'Component', a: from.components, b: to.components, label: (x: { name: string }) => x.name },
    { kind: 'Zone', a: from.zones, b: to.zones, label: (x: { name: string }) => x.name },
  ] as const;
  for (const s of sets) {
    const am = new Map(s.a.map((x) => [x.id, x]));
    const bm = new Map(s.b.map((x) => [x.id, x]));
    for (const [id, x] of bm) if (!am.has(id)) out.added.push(`${s.kind}: ${s.label(x)}`);
    for (const [id, x] of am) if (!bm.has(id)) out.removed.push(`${s.kind}: ${s.label(x)}`);
    for (const [id, x] of bm) {
      const prev = am.get(id);
      if (!prev) continue;
      const strip = (o: object) => { const { x: _x, y: _y, ...rest } = o as Record<string, unknown>; return canonicalJson(rest); };
      if (strip(prev) !== strip(x)) out.changed.push(`${s.kind}: ${s.label(x)}`);
    }
  }
  const fa = new Map(from.flows.map((f) => [f.id, f]));
  const fb = new Map(to.flows.map((f) => [f.id, f]));
  for (const [id, f] of fb) if (!fa.has(id)) out.added.push(`Flow: ${name(to, f.from)} → ${name(to, f.to)}`);
  for (const [id, f] of fa) if (!fb.has(id)) out.removed.push(`Flow: ${name(from, f.from)} → ${name(from, f.to)}`);
  for (const [id, f] of fb) if (fa.has(id) && canonicalJson(fa.get(id)) !== canonicalJson(f)) out.changed.push(`Flow: ${name(to, f.from)} → ${name(to, f.to)}`);
  if (from.notes !== to.notes) out.changed.push('Model notes');
  return out;
}
