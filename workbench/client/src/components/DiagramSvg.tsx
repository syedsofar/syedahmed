import { forwardRef } from 'react';
import type { ArchComponent, ArchitectureModel, DataFlow } from '@shared/types';
import { COMPONENTS, ZONES } from '@shared/schema';
import { NODE_H, NODE_W } from '@shared/engine';

// All styling is expressed as SVG attributes (not CSS classes) so the same SVG can be
// serialised to a standalone image for report exports.

export type Selection = { kind: 'component' | 'flow' | 'zone'; id: string } | null;

export interface DiagramHandlers {
  onNodeDown?: (e: React.PointerEvent, c: ArchComponent) => void;
  onHandleDown?: (e: React.PointerEvent, c: ArchComponent) => void;
  onZoneDown?: (e: React.PointerEvent, id: string) => void;
  onZoneResizeDown?: (e: React.PointerEvent, id: string) => void;
  onFlowDown?: (e: React.PointerEvent, f: DataFlow) => void;
}

interface Props extends DiagramHandlers {
  model: ArchitectureModel;
  selection?: Selection;
  scale?: number;
  ghostLine?: { x1: number; y1: number; x2: number; y2: number } | null;
  interactive?: boolean;
  highlight?: Set<string>;
}

const FONT = "Inter, 'Segoe UI', Arial, sans-serif";

export function modelBounds(model: ArchitectureModel) {
  const xs = [...model.components.map((c) => c.x + NODE_W), ...model.zones.map((z) => z.x + z.w), 600];
  const ys = [...model.components.map((c) => c.y + NODE_H), ...model.zones.map((z) => z.y + z.h), 400];
  return { w: Math.max(...xs) + 60, h: Math.max(...ys) + 60 };
}

function clipToRect(cx: number, cy: number, tx: number, ty: number) {
  const dx = tx - cx;
  const dy = ty - cy;
  if (!dx && !dy) return { x: cx, y: cy };
  const sx = NODE_W / 2 / Math.abs(dx || 1e-9);
  const sy = NODE_H / 2 / Math.abs(dy || 1e-9);
  const s = Math.min(sx, sy);
  return { x: cx + dx * s, y: cy + dy * s };
}

function wrap(name: string, max = 19): string[] {
  const words = name.split(/\s+/);
  const lines: string[] = [''];
  for (const w of words) {
    const cur = lines[lines.length - 1];
    if ((cur + ' ' + w).trim().length <= max) lines[lines.length - 1] = (cur + ' ' + w).trim();
    else lines.push(w);
  }
  const out = lines.slice(0, 2);
  if (lines.length > 2 || out[1]?.length > max) out[1] = (out[1] ?? '').slice(0, max - 1) + '…';
  if (out[0].length > max) out[0] = out[0].slice(0, max - 1) + '…';
  return out;
}

export function flowColor(f: DataFlow) {
  if (f.status !== 'confirmed') return '#9aa5a0';
  if (f.encrypted === 'no') return '#b5443c';
  if (f.encrypted === 'unknown') return '#c08a2c';
  return '#0f8b8d';
}

export const DiagramSvg = forwardRef<SVGSVGElement, Props>(function DiagramSvg(props, ref) {
  const { model, selection, scale = 1, ghostLine, interactive, highlight } = props;
  const { w, h } = modelBounds(model);
  const byId = new Map(model.components.map((c) => [c.id, c]));
  const pairCount = new Map<string, number>();

  return (
    <svg ref={ref} xmlns="http://www.w3.org/2000/svg" width={w * scale} height={h * scale} viewBox={`0 0 ${w} ${h}`} fontFamily={FONT} style={{ touchAction: 'none' }}>
      <defs>
        {['#0f8b8d', '#b5443c', '#c08a2c', '#9aa5a0', '#16325c'].map((c) => (
          <marker key={c} id={`arrow-${c.slice(1)}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill={c} />
          </marker>
        ))}
      </defs>
      {!interactive && <rect x={0} y={0} width={w} height={h} fill="#ffffff" />}

      {[...model.zones].sort((a, b) => b.w * b.h - a.w * a.h).map((z) => {
        const color = ZONES[z.zoneType].color;
        const sel = selection?.kind === 'zone' && selection.id === z.id;
        return (
          <g key={z.id} onPointerDown={interactive ? (e) => props.onZoneDown?.(e, z.id) : undefined} style={interactive ? { cursor: 'move' } : undefined}>
            <rect x={z.x} y={z.y} width={z.w} height={z.h} rx={10} fill={color} fillOpacity={0.06} stroke={sel ? '#0d1f3a' : color} strokeWidth={sel ? 2.5 : 1.6} strokeDasharray={z.status === 'confirmed' ? '8 5' : '3 4'} />
            <rect x={z.x} y={z.y} width={Math.min(z.w, 18 + z.name.length * 6.6 + 60)} height={22} rx={6} fill={color} fillOpacity={z.status === 'confirmed' ? 0.9 : 0.45} />
            <text x={z.x + 9} y={z.y + 15} fontSize={11.5} fontWeight={700} fill="#ffffff">{z.name} · T{z.trustLevel}{z.status !== 'confirmed' ? ' (unconfirmed)' : ''}</text>
            {interactive && sel && (
              <rect x={z.x + z.w - 12} y={z.y + z.h - 12} width={14} height={14} fill="#0d1f3a" rx={3} style={{ cursor: 'nwse-resize' }}
                onPointerDown={(e) => { e.stopPropagation(); props.onZoneResizeDown?.(e, z.id); }} />
            )}
          </g>
        );
      })}

      {model.flows.map((f) => {
        const a = byId.get(f.from);
        const b = byId.get(f.to);
        if (!a || !b) return null;
        const key = [f.from, f.to].sort().join('|');
        const idx = pairCount.get(key) ?? 0;
        pairCount.set(key, idx + 1);
        const ax = a.x + NODE_W / 2, ay = a.y + NODE_H / 2, bx = b.x + NODE_W / 2, by = b.y + NODE_H / 2;
        const len = Math.hypot(bx - ax, by - ay) || 1;
        const off = idx === 0 ? 0 : (idx % 2 ? 1 : -1) * Math.ceil(idx / 2) * 26;
        const nx = -(by - ay) / len, ny = (bx - ax) / len;
        const mx = (ax + bx) / 2 + nx * off, my = (ay + by) / 2 + ny * off;
        const p1 = clipToRect(ax, ay, mx, my);
        const p2 = clipToRect(bx, by, mx, my);
        const color = flowColor(f);
        const sel = selection?.kind === 'flow' && selection.id === f.id;
        const d = `M${p1.x},${p1.y} Q${mx},${my} ${p2.x},${p2.y}`;
        const lx = (p1.x + 2 * mx + p2.x) / 4, ly = (p1.y + 2 * my + p2.y) / 4;
        const label = [f.protocol, f.port && `:${f.port}`].filter(Boolean).join('') || (f.label ? '' : '?');
        const text = [label, f.label].filter(Boolean).join(' · ');
        const tw = Math.min(170, text.length * 5.9 + 10);
        return (
          <g key={f.id} onPointerDown={interactive ? (e) => props.onFlowDown?.(e, f) : undefined} style={interactive ? { cursor: 'pointer' } : undefined}>
            {interactive && <path d={d} stroke="transparent" strokeWidth={14} fill="none" />}
            <path d={d} stroke={sel ? '#0d1f3a' : color} strokeWidth={sel ? 3 : 1.8} fill="none" strokeDasharray={f.status === 'confirmed' ? undefined : '5 4'}
              markerEnd={`url(#arrow-${(sel ? '#16325c' : color).slice(1)})`} markerStart={f.bidirectional ? `url(#arrow-${(sel ? '#16325c' : color).slice(1)})` : undefined} />
            {text && (
              <g>
                <rect x={lx - tw / 2} y={ly - 9} width={tw} height={17} rx={8} fill="#ffffff" stroke={color} strokeWidth={0.8} />
                <text x={lx} y={ly + 3.5} fontSize={10} textAnchor="middle" fill="#1d2733">{text.length > 28 ? text.slice(0, 27) + '…' : text}</text>
              </g>
            )}
          </g>
        );
      })}

      {model.components.map((c) => {
        const def = COMPONENTS[c.type];
        const sel = selection?.kind === 'component' && selection.id === c.id;
        const lines = wrap(c.name);
        const hl = highlight?.has(c.id);
        return (
          <g key={c.id} transform={`translate(${c.x},${c.y})`} onPointerDown={interactive ? (e) => props.onNodeDown?.(e, c) : undefined} style={interactive ? { cursor: 'move' } : undefined}>
            <rect width={NODE_W} height={NODE_H} rx={9} fill="#ffffff" stroke={sel ? '#0f8b8d' : hl ? '#b5443c' : c.status === 'confirmed' ? '#b8c4bd' : '#9aa5a0'} strokeWidth={sel || hl ? 2.5 : 1.2} strokeDasharray={c.status === 'confirmed' ? undefined : '4 3'} />
            <rect width={34} height={NODE_H} rx={9} fill={def.color} />
            <rect x={24} width={10} height={NODE_H} fill={def.color} />
            <text x={17} y={NODE_H / 2 + 4} fontSize={10} fontWeight={800} fill="#ffffff" textAnchor="middle">{def.short}</text>
            {lines.map((l, i) => (
              <text key={i} x={42} y={lines.length === 1 ? NODE_H / 2 + 4.5 : 24 + i * 15} fontSize={11.5} fontWeight={600} fill="#13294b">{l}</text>
            ))}
            {c.status !== 'confirmed' && (
              <g><circle cx={NODE_W - 2} cy={2} r={9} fill="#c08a2c" /><text x={NODE_W - 2} y={6} fontSize={12} fontWeight={800} fill="#fff" textAnchor="middle">?</text></g>
            )}
            {interactive && (
              <circle className="handle" cx={NODE_W} cy={NODE_H / 2} r={7} fill="#0f8b8d" stroke="#fff" strokeWidth={2}
                onPointerDown={(e) => { e.stopPropagation(); props.onHandleDown?.(e, c); }}>
                <title>Drag to another component to create a data flow</title>
              </circle>
            )}
          </g>
        );
      })}

      {ghostLine && <line x1={ghostLine.x1} y1={ghostLine.y1} x2={ghostLine.x2} y2={ghostLine.y2} stroke="#0f8b8d" strokeWidth={2} strokeDasharray="6 4" markerEnd="url(#arrow-0f8b8d)" />}
    </svg>
  );
});

/** Serialise an SVG element to a PNG data URL (used for report architecture snapshots). */
export async function svgToPng(svg: SVGSVGElement, scale = 2): Promise<string> {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  const vb = svg.viewBox.baseVal;
  clone.setAttribute('width', String(vb.width));
  clone.setAttribute('height', String(vb.height));
  const xml = new XMLSerializer().serializeToString(clone);
  const url = URL.createObjectURL(new Blob([xml], { type: 'image/svg+xml;charset=utf-8' }));
  try {
    const img = new Image();
    await new Promise<void>((res, rej) => { img.onload = () => res(); img.onerror = () => rej(new Error('Could not render diagram')); img.src = url; });
    const canvas = document.createElement('canvas');
    const maxW = 2400;
    const s = Math.min(scale, maxW / vb.width);
    canvas.width = Math.round(vb.width * s);
    canvas.height = Math.round(vb.height * s);
    const ctx = canvas.getContext('2d')!;
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL('image/png');
  } finally {
    URL.revokeObjectURL(url);
  }
}
