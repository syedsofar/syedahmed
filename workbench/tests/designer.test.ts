import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalToDesigner, designerToCanonical, type DesignerModel } from '../shared/designer';
import type { CatalogItem } from '../shared/catalog';
import type { ArchitectureModel } from '../shared/types';
import { MODEL_SCHEMA } from '../shared/types';
import { modelSchema } from '../server/validation';

const here = path.dirname(fileURLToPath(import.meta.url));
const catalog: CatalogItem[] = JSON.parse(fs.readFileSync(path.join(here, '..', 'catalog', 'components.json'), 'utf8')).components;
const awsS3 = catalog.find((c) => c.name === 'S3 bucket')!;
const empty: ArchitectureModel = { schema: MODEL_SCHEMA, components: [], flows: [], zones: [], notes: 'keep me' };

const designer: DesignerModel = {
  version: 1, name: 'Test', created: '', updated: '',
  nodes: [
    { id: 'n1', componentId: awsS3.id, label: 'Statements bucket', x: 100, y: 120, zone: 'Data zone', security: { owner: 'Payments', mfa: 'yes', encryptedAtRest: 'no' } },
    { id: 'n2', componentId: awsS3.id, label: 'Portal', x: 300, y: 120, zone: 'DMZ / edge', security: { owner: '', mfa: 'unknown' } },
  ],
  flows: [{ id: 'f1', source: 'n2', target: 'n1', protocol: 'HTTPS', data: 'Statements', encrypted: 'yes', authenticated: 'unknown', notes: 'Batch export' }],
  zones: [{ id: 'z1', name: 'Data', trust: 'Data zone', x: 50, y: 80, w: 400, h: 200 }],
};

describe('designer conversion', () => {
  it('produces a model that passes the server schema', () => {
    const m = designerToCanonical(designer, catalog, empty);
    expect(modelSchema.safeParse(m).success).toBe(true);
    expect(m.components[0].catalogRef?.id).toBe(awsS3.id);
    expect(m.components[0].type).toBe('cloud_service');
    expect(m.flows[0]).toMatchObject({ from: 'n2', to: 'n1', label: 'Statements', encrypted: 'yes' });
    expect(m.flows[0].source.note).toBe('Batch export');
    expect(m.notes).toBe('keep me');
  });

  it('round-trips the designer fields without loss', () => {
    const m = designerToCanonical(designer, catalog, empty);
    const back = canonicalToDesigner(m, 'Test', awsS3.id);
    expect(back.nodes.map(({ id, label, x, y, zone, security }) => ({ id, label, x, y, zone, security })))
      .toEqual(designer.nodes.map(({ id, label, x, y, zone, security }) => ({ id, label, x, y, zone, security })));
    expect(back.flows).toEqual(designer.flows);
    expect(back.zones.map(({ id, name, trust, x, y, w, h }) => ({ id, name, trust, x, y, w, h })))
      .toEqual(designer.zones.map(({ id, name, trust, x, y, w, h }) => ({ id, name, trust, x, y, w, h })));
  });

  it('keeps analyst-entered canonical fields the designer does not show', () => {
    const base = designerToCanonical(designer, catalog, empty);
    base.components[0].properties['owner_contact'] = 'x@example.invalid';
    base.components[0].type = 'database';
    const next = designerToCanonical(designer, catalog, base);
    expect(next.components[0].properties['owner_contact']).toBe('x@example.invalid');
    expect(next.components[0].type).toBe('database');
  });

  it('does not record the placeholder catalog item for components without an origin', () => {
    const plain: DesignerModel = { ...designer, nodes: [{ ...designer.nodes[0], id: 'p1', componentId: catalog[0].id }], flows: [], zones: [] };
    const base: ArchitectureModel = { ...empty, components: [{ id: 'p1', type: 'web_server', name: 'Added in analysis', x: 0, y: 0, status: 'confirmed', source: { kind: 'manual' }, properties: {} }] };
    const m = designerToCanonical(plain, catalog, base);
    expect(m.components[0].catalogRef).toBeUndefined();
    expect(m.components[0].type).toBe('web_server');
  });
});
