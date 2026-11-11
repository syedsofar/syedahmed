import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GROUP_DEFAULT_TYPE, defaultTypeFor, type ComponentCatalog } from '../shared/catalog';
import { FRAMEWORKS } from '../shared/frameworks';
import { COMPONENT_TYPES } from '../shared/schema';
import { modelSchema } from '../server/validation';
import { MODEL_SCHEMA } from '../shared/types';

const here = path.dirname(fileURLToPath(import.meta.url));
const catalog: ComponentCatalog = JSON.parse(
  fs.readFileSync(path.join(here, '..', 'catalog', 'components.json'), 'utf8'),
);

describe('component catalog', () => {
  it('has the reconciled counts from the prototype', () => {
    expect(catalog.components).toHaveLength(2549);
    expect(catalog.groups).toHaveLength(24);
    expect(new Set(catalog.components.map((c) => c.id)).size).toBe(2549);
    for (const g of catalog.groups) {
      expect(catalog.components.filter((c) => c.groupId === g.id)).toHaveLength(g.count);
    }
  });

  it('maps every group to a valid model component type', () => {
    for (const g of catalog.groups) {
      expect(GROUP_DEFAULT_TYPE[g.id]).toBeDefined();
      expect(COMPONENT_TYPES).toContain(GROUP_DEFAULT_TYPE[g.id]);
    }
    const sample = catalog.components.find((c) => c.groupId === 'aws')!;
    expect(defaultTypeFor(sample)).toBe('cloud_service');
  });

  it('accepts a model component that records its catalog origin', () => {
    const model = {
      schema: MODEL_SCHEMA,
      components: [{
        id: 'c1', type: 'cloud_service', name: 'Example', x: 10, y: 10, status: 'confirmed',
        source: { kind: 'manual' }, properties: {},
        catalogRef: { id: 'aws-s3', name: 'Amazon S3', group: 'aws' },
      }],
      flows: [], zones: [], notes: '',
    };
    expect(modelSchema.safeParse(model).success).toBe(true);
  });
});

describe('framework register', () => {
  it('has unique ids and no control text fields', () => {
    expect(new Set(FRAMEWORKS.map((f) => f.id)).size).toBe(FRAMEWORKS.length);
    for (const f of FRAMEWORKS) expect(Object.keys(f)).not.toContain('controls');
  });

  it('covers every framework in the requested list', () => {
    const names = FRAMEWORKS.map((f) => f.name.toLowerCase()).join(' | ');
    for (const needle of [
      'sabsa', 'well-architected', 'togaf', '27001', 'cybersecurity framework 2.0', 'api security top 10',
      'cis critical', 'secure by design', 'cloud controls matrix', 'open security architecture',
      '800-207', 'essential cybersecurity controls', 'sama', 'zero trust maturity',
      'microsoft zero trust', 'cybersecurity reference architectures', 'architecture framework', 'att&ck',
    ]) {
      expect(names).toContain(needle);
    }
  });
});
