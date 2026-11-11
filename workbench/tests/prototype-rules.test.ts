import { describe, expect, it } from 'vitest';
import { prototypeDrafts, prototypeFindings } from '../shared/prototype-rules';
import { analyzeModel } from '../shared/engine';
import type { ArchComponent, ArchitectureModel, DataFlow } from '../shared/types';
import { MODEL_SCHEMA } from '../shared/types';

const comp = (id: string, name: string, props: Record<string, string>, extra: Partial<ArchComponent> = {}): ArchComponent => ({
  id, type: 'app_server', name, x: 0, y: 0, status: 'confirmed', source: { kind: 'manual' }, properties: props, ...extra,
});
const flow = (id: string, from: string, to: string, extra: Partial<DataFlow> = {}): DataFlow => ({
  id, from, to, label: '', protocol: 'HTTPS', port: '443', encrypted: 'yes', authenticated: 'yes', dataClassification: 'internal',
  bidirectional: false, status: 'confirmed', source: { kind: 'manual' }, ...extra,
});
const model = (components: ArchComponent[], flows: DataFlow[] = []): ArchitectureModel => ({
  schema: MODEL_SCHEMA, components, flows, zones: [], notes: '',
});

describe('PROTOTYPE rule checks', () => {
  it('gives a confirmed finding for an explicit "no" and a missing-evidence item for "unknown"', () => {
    const m = model([
      comp('a', 'Portal', { internetFacing: 'yes', mfa: 'no' }),
      comp('b', 'Ledger', { internetFacing: 'yes', mfa: 'unknown' }),
    ]);
    const f = prototypeFindings(m);
    expect(f.find((x) => x.target === 'Portal' && x.id === 'IAM-01')).toMatchObject({ sev: 'High' });
    expect(f.find((x) => x.target === 'Ledger' && x.id === 'IAM-01')).toMatchObject({ sev: 'Needs validation' });
    const drafts = prototypeDrafts(m);
    expect(drafts.find((d) => d.affectedAssets[0] === 'Portal' && d.tags[0] === 'IAM-01')?.classification).toBe('confirmed');
    expect(drafts.find((d) => d.affectedAssets[0] === 'Ledger' && d.tags[0] === 'IAM-01')?.classification).toBe('missing_evidence');
  });

  it('uses designer values in preference to canonical properties', () => {
    const m = model([comp('a', 'Store', { dataClassification: 'restricted', encryptedAtRest: 'yes', 'designer.security.encryptedAtRest': 'no', 'designer.security.data': 'Restricted' })]);
    expect(prototypeFindings(m).find((x) => x.id === 'DATA-01')).toMatchObject({ sev: 'High' });
  });

  it('ignores unconfirmed components and flows', () => {
    const m = model([
      comp('a', 'Portal', { internetFacing: 'yes', mfa: 'no' }, { status: 'unconfirmed' }),
      comp('b', 'Ledger', {}),
      comp('c', 'Store', {}),
    ], [flow('f', 'b', 'c', { status: 'unconfirmed', encrypted: 'no', dataClassification: 'restricted' })]);
    expect(prototypeFindings(m)).toHaveLength(0);
    expect(prototypeDrafts(m).filter((d) => d.methodology === 'PROTOTYPE').every((d) => d.classification === 'hypothesis' || d.classification === 'missing_evidence')).toBe(true);
  });

  it('flags unencrypted sensitive flows and unauthenticated cross-zone flows', () => {
    const m = model([
      { ...comp('a', 'Client', {}), properties: { 'designer.zone': 'Internet / public' } },
      { ...comp('b', 'API', {}), properties: { 'designer.zone': 'Application zone' } },
    ], [flow('f', 'a', 'b', { encrypted: 'no', authenticated: 'no', dataClassification: 'confidential' })]);
    const ids = prototypeFindings(m).map((x) => x.id);
    expect(ids).toContain('FLOW-01');
    expect(ids).toContain('FLOW-02');
  });

  it('runs through the engine when PROTOTYPE is selected and not otherwise', () => {
    const m = model([comp('a', 'Portal', { internetFacing: 'yes', mfa: 'no' })]);
    const withProto = analyzeModel(m, ['PROTOTYPE'], 1).drafts.filter((d) => d.methodology === 'PROTOTYPE');
    expect(withProto.length).toBeGreaterThan(0);
    expect(analyzeModel(m, ['STRIDE'], 1).drafts.some((d) => d.methodology === 'PROTOTYPE')).toBe(false);
  });

  it('keeps unverified control references out of approved fields', () => {
    const m = model([comp('a', 'Store', { dataClassification: 'restricted', encryptedAtRest: 'no' })]);
    const d = prototypeDrafts(m).find((x) => x.tags[0] === 'DATA-01')!;
    expect(d.rationale).toContain('not an approved control mapping');
    expect(d.rationale).toContain('STRIDE: Information disclosure');
  });
});
