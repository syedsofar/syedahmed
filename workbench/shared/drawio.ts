// Structured import of draw.io / diagrams.net files into the canonical model.
// Everything imported is marked UNCONFIRMED and must be reviewed by an analyst before the
// threat engine will use it. Type and zone inference is reported per element so the analyst
// can see exactly why an element was classified the way it was.

import type { ArchComponent, ComponentType, DataFlow, TrustZone, ZoneType } from './types';
import { ZONES } from './schema';

export interface DrawioImport {
  components: ArchComponent[];
  flows: DataFlow[];
  zones: TrustZone[];
  inferences: Record<string, string>;
  warnings: string[];
  pageCount: number;
}

interface Cell {
  id: string;
  value: string;
  style: string;
  vertex: boolean;
  edge: boolean;
  parent: string;
  source?: string;
  target?: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const code = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

function parseAttrs(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([A-Za-z_:][\w:.-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out[m[1]] = decodeEntities(m[3] ?? m[4] ?? '');
  return out;
}

/** Labels in draw.io are frequently HTML. Reduce to plain text. */
export function plainLabel(v: string): string {
  return decodeEntities(v.replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
}

/** Return the uncompressed <mxGraphModel> XML for the first page and the page count. */
export async function extractGraphXml(fileText: string, inflateRaw: (b: Uint8Array) => Promise<string>): Promise<{ xml: string; pages: number }> {
  const text = fileText.trim();
  if (/^<mxGraphModel/i.test(text)) return { xml: text, pages: 1 };
  if (!/<mxfile/i.test(text)) throw new Error('Not a draw.io file: no <mxfile> or <mxGraphModel> root element found.');
  const diagrams = [...text.matchAll(/<diagram\b[^>]*>([\s\S]*?)<\/diagram>/gi)];
  if (!diagrams.length) throw new Error('The draw.io file contains no diagram pages.');
  const body = diagrams[0][1].trim();
  if (/^<mxGraphModel/i.test(body)) return { xml: body, pages: diagrams.length };
  // Compressed page: base64(deflateRaw(encodeURIComponent(xml)))
  const bin = typeof atob === 'function' ? atob(body) : Buffer.from(body, 'base64').toString('binary');
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const inflated = await inflateRaw(bytes);
  return { xml: decodeURIComponent(inflated), pages: diagrams.length };
}

function parseCells(xml: string): Cell[] {
  if (xml.length > 5_000_000) throw new Error('Diagram is too large to import (limit 5 MB of XML).');
  const cells: Cell[] = [];
  const tagRe = /<(\/?)([A-Za-z][\w:-]*)([^>]*?)(\/?)>/g;
  const stack: { tag: string; attrs: Record<string, string>; cell?: Cell }[] = [];
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(xml))) {
    const [, closing, tag, rawAttrs, selfClose] = m;
    if (closing) {
      while (stack.length && stack[stack.length - 1].tag !== tag) stack.pop();
      stack.pop();
      continue;
    }
    const attrs = parseAttrs(rawAttrs);
    const entry: { tag: string; attrs: Record<string, string>; cell?: Cell } = { tag, attrs };
    if (tag === 'mxCell') {
      const wrapper = stack.length ? stack[stack.length - 1] : undefined;
      const wrapped = wrapper && /^(UserObject|object)$/i.test(wrapper.tag);
      const cell: Cell = {
        id: (wrapped ? wrapper!.attrs.id : undefined) ?? attrs.id ?? '',
        value: plainLabel((wrapped ? wrapper!.attrs.label : undefined) ?? attrs.value ?? ''),
        style: attrs.style ?? '',
        vertex: attrs.vertex === '1',
        edge: attrs.edge === '1',
        parent: attrs.parent ?? '',
        source: attrs.source,
        target: attrs.target,
        x: 0, y: 0, w: 0, h: 0,
      };
      cells.push(cell);
      entry.cell = cell;
    } else if (tag === 'mxGeometry') {
      const owner = [...stack].reverse().find((s) => s.cell)?.cell;
      if (owner && attrs.as !== 'offset') {
        owner.x = Number(attrs.x ?? 0) || 0;
        owner.y = Number(attrs.y ?? 0) || 0;
        owner.w = Number(attrs.width ?? 0) || 0;
        owner.h = Number(attrs.height ?? 0) || 0;
      }
    }
    if (!selfClose) stack.push(entry);
  }
  return cells;
}

const TYPE_RULES: [ComponentType, RegExp][] = [
  ['user', /umlactor|\buser|customer|actor|admin(istrator)?s?\b|employee|person|staff|client user/i],
  ['firewall', /firewall|\bfw\b|fortigate|palo ?alto|checkpoint|\basa\b|ngfw/i],
  ['load_balancer', /load.?balanc|\blb\b|\balb\b|\belb\b|\bf5\b|haproxy|traffic manager/i],
  ['api_gateway', /api.?gateway|\bapigw\b|\bapim\b|api management|kong|apigee/i],
  ['iam', /\biam\b|identity|active directory|\bad\b|ldap|okta|keycloak|\bsso\b|\bidp\b|entra/i],
  ['database', /database|\bdb\b|sql|oracle|postgres|mysql|mongo|redis|data ?store|cylinder|warehouse|\bs3\b|blob storage/i],
  ['third_party', /third.?party|partner|vendor|external|supplier|payment (provider|gateway)|swift|bureau/i],
  ['cloud_service', /\baws\b|azure|\bgcp\b|cloud|lambda|function app|saas|bucket|queue|\bsqs\b|kafka/i],
  ['web_server', /\bweb\b|frontend|front-end|portal|nginx|apache|\biis\b|website|\bcdn\b/i],
  ['endpoint', /laptop|workstation|desktop|mobile|device|endpoint|\bpc\b|tablet/i],
  ['app_server', /\bapp\b|application|service|backend|back-end|micro.?service|middleware|server/i],
];

const ZONE_RULES: [ZoneType, RegExp][] = [
  ['internet', /internet|public|untrusted|external network/i],
  ['dmz', /\bdmz\b|perimeter|edge/i],
  ['management', /management|mgmt|admin(istration)? (zone|network)|bastion|jump/i],
  ['restricted', /restricted|data (zone|tier|layer)|database (zone|tier)|\bpci\b|crown/i],
  ['third_party', /third.?party|partner|vendor|supplier/i],
  ['cloud', /cloud|\bvpc\b|\bvnet\b|aws|azure|gcp|tenant/i],
  ['user_zone', /user|corporate|office|\blan\b|branch|endpoint/i],
  ['internal', /internal|private|app(lication)? (zone|tier)|intranet|trusted|core/i],
];

const PROTO_RE = /\b(https|http|mtls|tls|sftp|ftp|ssh|ldaps|ldap|jdbc|odbc|grpc|amqps|amqp|smtps|smtp|snmpv3|snmpv2|snmpv1|telnet|ipsec|kafka|mqtt|rdp|smb|soap|rest|sql|tcp|udp)\b/i;

export function inferProtocol(label: string): { protocol: string; port: string } {
  const p = PROTO_RE.exec(label);
  const port = /(?::|port\s*)(\d{2,5})\b/i.exec(label);
  return { protocol: p ? p[1].toUpperCase() : '', port: port ? port[1] : '' };
}

let counter = 0;
const rid = (p: string) => `${p}_${Date.now().toString(36)}${(counter++).toString(36)}${Math.random().toString(36).slice(2, 6)}`;

export function importDrawioXml(xml: string, fileName: string, pageCount = 1): DrawioImport {
  const cells = parseCells(xml);
  const byId = new Map(cells.map((c) => [c.id, c]));
  const warnings: string[] = [];
  const inferences: Record<string, string> = {};
  if (pageCount > 1) warnings.push(`File has ${pageCount} pages; only the first page was imported.`);

  // Absolute coordinates: children of groups/containers are relative to their parent.
  const abs = (c: Cell): { x: number; y: number } => {
    let x = c.x, y = c.y;
    let p = byId.get(c.parent);
    let guard = 0;
    while (p && p.vertex && guard++ < 50) { x += p.x; y += p.y; p = byId.get(p.parent); }
    return { x, y };
  };

  const vertices = cells.filter((c) => c.vertex);
  const isZone = (c: Cell) => {
    const s = c.style.toLowerCase();
    if (/swimlane|container=1|shape=group/.test(s) || s.startsWith('group')) return true;
    const large = c.w * c.h >= 60000;
    return large && (/dashed=1/.test(s) || /zone|dmz|boundary|vpc|vnet|subnet|segment|network|tier|tenant/i.test(c.value));
  };

  const zones: TrustZone[] = [];
  const components: ArchComponent[] = [];
  const idMap = new Map<string, string>();
  const ignoredText: string[] = [];

  for (const c of vertices) {
    const pos = abs(c);
    if (isZone(c)) {
      const rule = ZONE_RULES.find(([, re]) => re.test(c.value));
      const zoneType: ZoneType = rule ? rule[0] : 'internal';
      const id = rid('z');
      zones.push({
        id, name: c.value || 'Unnamed zone', zoneType, trustLevel: ZONES[zoneType].trust,
        x: pos.x, y: pos.y, w: Math.max(c.w, 160), h: Math.max(c.h, 120),
        status: 'unconfirmed', source: { kind: 'drawio', ref: fileName, location: `cell ${c.id}` },
      });
      inferences[id] = rule ? `Zone type "${zoneType}" inferred from label keyword (${rule[1].exec(c.value)![0]}).` : 'No zone keyword found; defaulted to "internal". Review required.';
      continue;
    }
    const s = c.style.toLowerCase();
    if (!c.value && !/shape=|image=/.test(s)) continue; // decorative
    if (/^text;|edgelabel/.test(s)) { if (c.value) ignoredText.push(c.value); continue; }
    const hay = `${c.value} ${s}`;
    const rule = TYPE_RULES.find(([, re]) => re.test(hay));
    const type: ComponentType = rule ? rule[0] : 'app_server';
    const id = rid('c');
    idMap.set(c.id, id);
    components.push({
      id, type, name: c.value || `Unnamed ${type}`, x: pos.x + c.w / 2 - 70, y: pos.y + c.h / 2 - 29,
      status: 'unconfirmed', source: { kind: 'drawio', ref: fileName, location: `cell ${c.id}` }, properties: {},
    });
    inferences[id] = rule ? `Type "${type}" inferred from keyword "${rule[1].exec(hay)![0]}".` : 'No type keyword matched; defaulted to Application Server. Review required.';
  }
  if (ignoredText.length) warnings.push(`${ignoredText.length} free-text label(s) were not imported: ${ignoredText.slice(0, 5).join('; ')}${ignoredText.length > 5 ? '…' : ''}`);

  const flows: DataFlow[] = [];
  for (const e of cells.filter((c) => c.edge)) {
    const from = e.source && idMap.get(e.source);
    const to = e.target && idMap.get(e.target);
    if (!from || !to) {
      warnings.push(`Connector ${e.id}${e.value ? ` ("${e.value}")` : ''} skipped: it is not attached to two imported components.`);
      continue;
    }
    // Edge labels are often separate child cells.
    const childLabel = cells.filter((c) => c.parent === e.id && c.value).map((c) => c.value).join(' ');
    const label = [e.value, childLabel].filter(Boolean).join(' ').trim();
    const { protocol, port } = inferProtocol(label);
    const s = e.style.toLowerCase();
    const id = rid('f');
    flows.push({
      id, from, to, label, protocol, port,
      encrypted: 'unknown', authenticated: 'unknown', dataClassification: 'unknown',
      bidirectional: /startarrow=/.test(s) && !/startarrow=none/.test(s),
      status: 'unconfirmed', source: { kind: 'drawio', ref: fileName, location: `edge ${e.id}` },
    });
    inferences[id] = protocol
      ? `Protocol "${protocol}" read from connector label. Encryption, authentication and classification are not inferred.`
      : 'No protocol in connector label. Encryption, authentication and classification are not inferred.';
  }

  // Normalise coordinates into the positive canvas area.
  const all = [...components.map((c) => ({ x: c.x, y: c.y })), ...zones.map((z) => ({ x: z.x, y: z.y }))];
  if (all.length) {
    const dx = 40 - Math.min(...all.map((p) => p.x));
    const dy = 40 - Math.min(...all.map((p) => p.y));
    components.forEach((c) => { c.x = Math.round(c.x + dx); c.y = Math.round(c.y + dy); });
    zones.forEach((z) => { z.x = Math.round(z.x + dx); z.y = Math.round(z.y + dy); });
  }
  for (const el of [...components, ...flows, ...zones]) el.source.note = inferences[el.id];
  if (!components.length) warnings.push('No components were recognised in the diagram.');
  return { components, flows, zones, inferences, warnings, pageCount };
}
