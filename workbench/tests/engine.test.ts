import { describe, expect, it } from 'vitest';
import { deflateRawSync } from 'node:zlib';
import { inflateRawSync } from 'node:zlib';
import { analyzeModel, mergeRun } from '../shared/engine';
import { extractGraphXml, importDrawioXml } from '../shared/drawio';
import { DEMO_CATALOGS, canSetStatus, mapThreatsToControls, suggestedStatus, validateCatalogImport } from '../shared/controls';
import { buildReport } from '../shared/report';
import { defaultRiskMatrix, riskBand } from '../shared/schema';
import { diffModels } from '../shared/diff';
import type { ArchComponent, ArchitectureModel, ControlCatalog, DataFlow, ProjectData, TrustZone } from '../shared/types';
import { MODEL_SCHEMA } from '../shared/types';

const zone = (id: string, trust: number, x: number, zoneType: TrustZone['zoneType'] = 'internal'): TrustZone =>
  ({ id, name: id, zoneType, trustLevel: trust, x, y: 0, w: 300, h: 300, status: 'confirmed', source: { kind: 'manual' } });
const comp = (id: string, type: ArchComponent['type'], x: number, properties: Record<string, string> = {}, status: ArchComponent['status'] = 'confirmed'): ArchComponent =>
  ({ id, type, name: id, x, y: 100, properties, status, source: { kind: 'manual' } });
const flow = (id: string, from: string, to: string, p: Partial<DataFlow> = {}): DataFlow =>
  ({ id, from, to, label: '', protocol: 'HTTPS', port: '', encrypted: 'yes', authenticated: 'yes', dataClassification: 'confidential', bidirectional: false, status: 'confirmed', source: { kind: 'manual' }, ...p });

function model(): ArchitectureModel {
  return {
    schema: MODEL_SCHEMA,
    zones: [zone('internet', 0, 0, 'internet'), zone('dmz', 1, 320, 'dmz'), zone('data', 4, 640, 'restricted')],
    components: [
      comp('user', 'user', 50, { mfa: 'unknown' }),
      comp('web', 'web_server', 370, { authentication: 'yes', mfa: 'no', inputValidation: 'yes', rateLimiting: 'yes', dataClassification: 'confidential' }),
      comp('db', 'database', 700, { encryptionAtRest: 'unknown', authorization: 'yes', dataClassification: 'restricted', criticality: 'critical' }),
      comp('ghost', 'app_server', 900, {}, 'unconfirmed'),
    ],
    flows: [flow('f1', 'user', 'web'), flow('f2', 'web', 'db', { protocol: 'JDBC', encrypted: 'no' }), flow('f3', 'web', 'ghost')],
    notes: '',
  };
}

describe('threat engine', () => {
  const r = analyzeModel(model(), ['STRIDE', 'PASTA', 'OCTAVE'], 3);

  it('excludes unconfirmed elements and counts them', () => {
    expect(r.skippedUnconfirmed).toBe(2); // ghost component + flow to ghost
    expect(r.drafts.some((d) => d.affectedAssets.includes('ghost'))).toBe(false);
  });

  it('classifies an explicit "no" as a confirmed finding', () => {
    const spoof = r.drafts.find((d) => d.key === 'STRIDE-S-PROC:web')!;
    expect(spoof.classification).toBe('confirmed');
    expect(spoof.basis.find((b) => b.fact === 'mfa')?.value).toBe('no');
  });

  it('classifies unknown facts as missing evidence, never as findings', () => {
    const disc = r.drafts.find((d) => d.key === 'STRIDE-I-DS:db')!;
    expect(disc.classification).toBe('missing_evidence');
    expect(disc.missingInformation.join(' ')).toMatch(/Encryption at rest/);
  });

  it('flags an unencrypted boundary-crossing flow as confirmed', () => {
    const t = r.drafts.find((d) => d.key === 'STRIDE-I-FLOW:f2')!;
    expect(t.classification).toBe('confirmed');
  });

  it('detects a direct low-trust to high-trust flow structurally', () => {
    expect(r.drafts.find((d) => d.key === 'STRUCT-SEG:f2')?.classification).toBe('confirmed');
  });

  it('builds PASTA attack paths from entry points to crown jewels', () => {
    const p = r.drafts.find((d) => d.key === 'PASTA-PATH:user>db')!;
    expect(p).toBeTruthy();
    expect(p.attackScenario).toContain('user → web → db');
  });

  it('produces OCTAVE areas of concern for critical assets', () => {
    expect(r.drafts.filter((d) => d.methodology === 'OCTAVE' && d.affectedAssets[0] === 'db').length).toBeGreaterThanOrEqual(3);
  });

  it('stamps drafts with the model version and is deterministic', () => {
    expect(r.drafts.every((d) => d.modelVersion === 3)).toBe(true);
    const again = analyzeModel(model(), ['STRIDE', 'PASTA', 'OCTAVE'], 3);
    expect(again.drafts.map((d) => d.key)).toEqual(r.drafts.map((d) => d.key));
  });

  it('keeps analyst decisions across re-runs and preserves referenced threats', () => {
    let n = 0;
    const ctx = { runId: 'r1', at: 'now', by: 'u', newId: () => `id${n++}`, referenced: new Set<string>() };
    const first = mergeRun([], r.drafts, ctx);
    const target = first.find((t) => t.key === 'STRIDE-S-PROC:web')!;
    target.decision = 'accepted';
    target.analystNotes = 'checked';
    const gone = first.find((t) => t.key === 'STRIDE-I-FLOW:f2')!;
    const second = mergeRun(first, r.drafts.filter((d) => d.key !== gone.key), { ...ctx, runId: 'r2', referenced: new Set([gone.id]) });
    const kept = second.find((t) => t.key === target.key)!;
    expect(kept.id).toBe(target.id);
    expect(kept.decision).toBe('accepted');
    expect(kept.analystNotes).toBe('checked');
    expect(second.find((t) => t.id === gone.id)?.tags).toContain('not-in-latest-run');
  });

  it('reports structural gaps for components outside zones', () => {
    const m = model();
    m.components.push(comp('floating', 'app_server', 2000));
    const res = analyzeModel(m, ['STRIDE'], 1);
    expect(res.structuralGaps.some((g) => g.affectedAssets.includes('floating'))).toBe(true);
  });
});

describe('draw.io import', () => {
  const xml = `<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>
    <mxCell id="z" value="DMZ zone" style="swimlane;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="400" height="300" as="geometry"/></mxCell>
    <mxCell id="a" value="Customer &lt;br&gt;user" style="shape=umlActor;" vertex="1" parent="1"><mxGeometry x="-200" y="40" width="30" height="60" as="geometry"/></mxCell>
    <mxCell id="b" value="Web Portal" style="rounded=1;" vertex="1" parent="z"><mxGeometry x="40" y="60" width="120" height="60" as="geometry"/></mxCell>
    <UserObject label="Orders DB" id="c"><mxCell style="shape=cylinder3;" vertex="1" parent="1"><mxGeometry x="600" y="60" width="60" height="80" as="geometry"/></mxCell></UserObject>
    <mxCell id="e1" value="HTTPS :443" edge="1" source="a" target="b" parent="1"><mxGeometry relative="1" as="geometry"/></mxCell>
    <mxCell id="e2" value="" edge="1" source="b" target="c" parent="1"><mxGeometry relative="1" as="geometry"/></mxCell>
    <mxCell id="e2l" value="JDBC" style="edgeLabel;" vertex="1" connectable="0" parent="e2"><mxGeometry x="0" y="0" as="geometry"/></mxCell>
    <mxCell id="e3" value="dangling" edge="1" source="b" parent="1"><mxGeometry relative="1" as="geometry"/></mxCell>
  </root></mxGraphModel>`;

  it('maps shapes, containers and connectors to unconfirmed model elements', () => {
    const r = importDrawioXml(xml, 'test.drawio');
    expect(r.zones).toHaveLength(1);
    expect(r.zones[0].zoneType).toBe('dmz');
    const types = Object.fromEntries(r.components.map((c) => [c.name, c.type]));
    expect(types).toEqual({ 'Customer user': 'user', 'Web Portal': 'web_server', 'Orders DB': 'database' });
    expect(r.flows).toHaveLength(2);
    expect(r.flows.map((f) => f.protocol).sort()).toEqual(['HTTPS', 'JDBC']);
    expect(r.flows[0].port).toBe('443');
    expect([...r.components, ...r.flows, ...r.zones].every((x) => x.status === 'unconfirmed')).toBe(true);
    expect(r.flows.every((f) => f.encrypted === 'unknown' && f.dataClassification === 'unknown')).toBe(true);
    expect(r.warnings.some((w) => w.includes('dangling'))).toBe(true);
  });

  it('places children of containers using absolute coordinates', () => {
    const r = importDrawioXml(xml, 'test.drawio');
    const web = r.components.find((c) => c.name === 'Web Portal')!;
    const z = r.zones[0];
    expect(web.x + 70).toBeGreaterThan(z.x);
    expect(web.x + 70).toBeLessThan(z.x + z.w);
  });

  it('decompresses compressed diagram pages', async () => {
    const packed = deflateRawSync(Buffer.from(encodeURIComponent(xml))).toString('base64');
    const file = `<mxfile><diagram id="p1" name="Page-1">${packed}</diagram><diagram id="p2">x</diagram></mxfile>`;
    const { xml: out, pages } = await extractGraphXml(file, async (b) => inflateRawSync(Buffer.from(b)).toString('utf8'));
    expect(pages).toBe(2);
    expect(out).toContain('Web Portal');
  });

  it('rejects non-draw.io content', async () => {
    await expect(extractGraphXml('<html></html>', async () => '')).rejects.toThrow(/Not a draw.io file/);
  });
});

describe('controls, risk matrix and reports', () => {
  const cat: ControlCatalog = { ...DEMO_CATALOGS[0], id: 'cat', status: 'approved', isDemo: true, importedBy: 'a', importedAt: '', contentHash: 'x' };
  let n = 0;
  const threats = mergeRun([], analyzeModel(model(), ['STRIDE'], 1).drafts, { runId: 'r', at: '2026-01-01', by: 'u', newId: () => `t${n++}`, referenced: new Set() });

  it('maps findings to controls and never suggests satisfied', () => {
    const maps = mapThreatsToControls(cat, threats);
    const transit = maps.find((m) => m.control.id === 'PR.DS-02')!;
    expect(transit.confirmed.length).toBeGreaterThan(0);
    expect(maps.map(suggestedStatus)).not.toContain('evidence_satisfied');
  });

  it('requires evidence before a control can be marked satisfied', () => {
    expect(canSetStatus('evidence_satisfied', [], '')).toMatch(/evidence reference/);
    expect(canSetStatus('evidence_satisfied', ['EV-1'], '')).toBeNull();
    expect(canSetStatus('not_applicable', [], '')).toMatch(/justification/);
  });

  it('validates catalog imports', () => {
    expect(validateCatalogImport({ framework: 'X' }).ok).toBe(false);
    expect(validateCatalogImport({ ...DEMO_CATALOGS[1] }).ok).toBe(true);
    const bad = validateCatalogImport({ ...DEMO_CATALOGS[1], controls: [{ id: '1', domain: 'd', title: 't', tags: ['nope'] }] });
    expect(bad.ok).toBe(false);
  });

  it('rates risks using configurable bands', () => {
    const m = defaultRiskMatrix();
    expect(riskBand(m, 1, 1).name).toBe('Low');
    expect(riskBand(m, 5, 5).name).toBe('Critical');
    expect(riskBand(m, 3, 3).name).toBe('Medium');
    expect(riskBand({ ...m, bands: [{ name: 'A', min: 1, color: '#000000' }, { name: 'B', min: 9, color: '#ffffff' }] }, 3, 3).name).toBe('B');
  });

  it('builds all four report types with required sections', () => {
    const d: ProjectData = {
      project: { id: 'p', name: 'Demo', clientAlias: 'ALIAS', scope: 's', architectureVersion: '1', reviewerId: '', status: 'draft', reviewDate: '', createdAt: '', createdBy: '', updatedAt: '', isDemo: true, members: [], methodologies: ['STRIDE'], catalogIds: ['cat'], riskMatrix: defaultRiskMatrix(), narrative: { executiveSummary: '', limitations: '', recommendations: '' }, history: [] },
      model: model(), versions: [{ version: 1, savedAt: '', savedBy: '', message: '', hash: 'abc' }], threats,
      runs: [{ id: 'r', at: '2026-01-01T00:00:00Z', by: 'u', provider: 'rules', providerVersion: '1', modelVersion: 1, methodologies: ['STRIDE'], counts: { confirmed: 1, hypothesis: 1, missing_evidence: 1 }, skippedUnconfirmed: 2 }],
      controlReviews: [], risks: [], evidence: [],
    };
    const arch = buildReport('architecture_review', d, [], [cat]);
    const headings = arch.sections.map((s) => s.heading);
    for (const h of ['Executive summary', 'Methodology', 'Architecture snapshot', 'Findings', 'Control review', 'Risk ratings', 'Evidence references', 'Limitations', 'Recommendations']) expect(headings).toContain(h);
    expect(arch.isDemo).toBe(true);
    expect(buildReport('threat_model', d, [], [cat]).sections.length).toBeGreaterThan(3);
    expect(buildReport('risk_register', d, [], [cat]).title).toBe('Risk Register');
    expect(buildReport('remediation_roadmap', d, [], [cat]).sections.some((s) => s.heading.startsWith('Horizon'))).toBe(true);
  });

  it('diffs model versions by element id', () => {
    const a = model();
    const b = model();
    b.components = b.components.filter((c) => c.id !== 'ghost');
    b.components[0] = { ...b.components[0], name: 'renamed' };
    const d = diffModels(a, b);
    expect(d.removed).toContain('Component: ghost');
    expect(d.changed).toContain('Component: renamed');
  });
});
