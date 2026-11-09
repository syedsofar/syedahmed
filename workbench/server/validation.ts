import { z } from 'zod';
import { COMPONENT_TYPES, ZONES } from '../shared/schema';
import { MODEL_SCHEMA } from '../shared/types';

const str = (max = 500) => z.string().max(max);
const tri = z.enum(['yes', 'no', 'unknown']);
const status = z.enum(['confirmed', 'unconfirmed']);
const source = z.object({ kind: z.enum(['manual', 'drawio', 'document']), ref: str(300).optional(), location: str(300).optional(), note: str(500).optional() });
const coord = z.number().finite().min(-10000).max(20000);

export const modelSchema = z.object({
  schema: z.literal(MODEL_SCHEMA),
  components: z.array(z.object({
    id: str(80), type: z.enum(COMPONENT_TYPES as [string, ...string[]]), name: str(120), x: coord, y: coord, status, source,
    properties: z.record(z.string().max(60), z.string().max(500)),
  })).max(500),
  flows: z.array(z.object({
    id: str(80), from: str(80), to: str(80), label: str(200), protocol: str(40), port: str(20),
    encrypted: tri, authenticated: tri,
    dataClassification: z.enum(['unknown', 'public', 'internal', 'confidential', 'restricted']),
    bidirectional: z.boolean(), status, source,
  })).max(1500),
  zones: z.array(z.object({
    id: str(80), name: str(120), zoneType: z.enum(Object.keys(ZONES) as [string, ...string[]]), trustLevel: z.number().int().min(0).max(4),
    x: coord, y: coord, w: z.number().min(40).max(20000), h: z.number().min(40).max(20000), status, source,
  })).max(100),
  notes: str(5000),
}).superRefine((m, ctx) => {
  const ids = new Set(m.components.map((c) => c.id));
  m.flows.forEach((f, i) => {
    if (!ids.has(f.from) || !ids.has(f.to)) ctx.addIssue({ code: 'custom', message: `Flow ${i} references a missing component.`, path: ['flows', i] });
  });
});

const date = z.union([z.literal(''), z.string().regex(/^\d{4}-\d{2}-\d{2}$/)]);
const matrix = z.object({
  likelihoodLabels: z.tuple([str(40), str(40), str(40), str(40), str(40)]),
  impactLabels: z.tuple([str(40), str(40), str(40), str(40), str(40)]),
  bands: z.array(z.object({ name: str(30), min: z.number().int().min(1).max(25), color: z.string().regex(/^#[0-9a-fA-F]{6}$/) })).min(2).max(6)
    .refine((b) => b.some((x) => x.min === 1), 'One band must start at score 1.'),
});

export const projectCreateSchema = z.object({
  name: str(160).min(1),
  clientAlias: str(120).min(1),
  scope: str(4000),
  architectureVersion: str(60),
  reviewerId: str(80),
  reviewDate: date,
  methodologies: z.array(z.enum(['STRIDE', 'PASTA', 'OCTAVE'])).max(3),
  catalogIds: z.array(str(80)).max(20),
});

export const projectPatchSchema = projectCreateSchema.partial().extend({
  status: z.enum(['draft', 'in_review', 'pending_approval', 'final', 'archived']).optional(),
  riskMatrix: matrix.optional(),
  narrative: z.object({ executiveSummary: str(8000), limitations: str(8000), recommendations: str(8000) }).optional(),
});

export const threatPatchSchema = z.object({
  decision: z.enum(['proposed', 'accepted', 'rejected']).optional(),
  analystNotes: str(4000).optional(),
  evidenceRefs: z.array(str(200)).max(30).optional(),
  likelihood: z.number().int().min(1).max(5).optional(),
  impact: z.number().int().min(1).max(5).optional(),
  // Manual threats only:
  title: str(200).optional(),
  category: str(100).optional(),
  classification: z.enum(['confirmed', 'hypothesis', 'missing_evidence']).optional(),
  affectedAssets: z.array(str(120)).max(30).optional(),
  attackScenario: str(4000).optional(),
  preconditions: z.array(str(500)).max(30).optional(),
  existingControls: z.array(str(500)).max(30).optional(),
  missingInformation: z.array(str(500)).max(30).optional(),
  mitigation: str(4000).optional(),
  tags: z.array(str(40)).max(20).optional(),
});

export const manualThreatSchema = z.object({
  title: str(200).min(1),
  category: str(100).min(1),
  classification: z.enum(['confirmed', 'hypothesis', 'missing_evidence']),
  affectedAssets: z.array(str(120)).max(30),
  attackScenario: str(4000),
  preconditions: z.array(str(500)).max(30),
  existingControls: z.array(str(500)).max(30),
  missingInformation: z.array(str(500)).max(30),
  likelihood: z.number().int().min(1).max(5),
  impact: z.number().int().min(1).max(5),
  mitigation: str(4000),
  tags: z.array(str(40)).max(20),
  evidenceRefs: z.array(str(200)).max(30),
});

export const controlReviewSchema = z.object({
  status: z.enum(['not_assessed', 'information_missing', 'gap_identified', 'evidence_satisfied', 'not_applicable']),
  notes: str(4000),
  evidenceRefs: z.array(str(200)).max(30),
});

const action = z.object({ id: str(80), description: str(1000).min(1), owner: str(120), dueDate: date, done: z.boolean() });

export const riskSchema = z.object({
  title: str(200).min(1),
  description: str(4000),
  threatIds: z.array(str(80)).max(50),
  likelihood: z.number().int().min(1).max(5),
  impact: z.number().int().min(1).max(5),
  residualLikelihood: z.number().int().min(1).max(5),
  residualImpact: z.number().int().min(1).max(5),
  owner: str(120),
  strategy: z.enum(['mitigate', 'accept', 'transfer', 'avoid']),
  status: z.enum(['open', 'in_progress', 'implemented', 'closed']),
  targetDate: date,
  actions: z.array(action).max(50),
});

export function parse<T>(schema: z.ZodType<T>, data: unknown): { ok: true; value: T } | { ok: false; error: string } {
  const r = schema.safeParse(data);
  if (r.success) return { ok: true, value: r.data };
  return { ok: false, error: r.error.issues.slice(0, 5).map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ') };
}
