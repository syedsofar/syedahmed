// Builds report documents as a neutral structure. The same structure drives the in-browser
// preview and the server-side DOCX / PDF / XLSX renderers, so previews match exports.

import type { ControlCatalog, ProjectData, PublicUser, Risk, Threat } from './types';
import { COMPONENTS, ZONES, riskBand, STATUS_LABELS } from './schema';
import { FRAMEWORK_LABELS, mapThreatsToControls, REVIEW_STATUS_LABELS } from './controls';
import { ENGINE_NAME, ENGINE_VERSION } from './engine';

export type ReportType = 'architecture_review' | 'threat_model' | 'risk_register' | 'remediation_roadmap';

export const REPORT_TYPES: Record<ReportType, { title: string; description: string }> = {
  architecture_review: { title: 'Security Architecture Review', description: 'Full review: scope, methodology, architecture snapshot, findings, control review, risks, limitations and recommendations.' },
  threat_model: { title: 'Threat Model', description: 'STRIDE / PASTA / OCTAVE scenarios with preconditions, existing controls, ratings and mitigations.' },
  risk_register: { title: 'Risk Register', description: 'Rated risks with owners, treatment, target dates, approvals and residual ratings.' },
  remediation_roadmap: { title: 'Remediation Roadmap', description: 'Prioritised mitigation actions grouped into delivery horizons.' },
};

export type Block =
  | { type: 'p'; text: string }
  | { type: 'bullets'; items: string[] }
  | { type: 'table'; columns: string[]; rows: string[][]; sheet?: string }
  | { type: 'kv'; rows: [string, string][] }
  | { type: 'callout'; tone: 'info' | 'warn'; text: string }
  | { type: 'image'; ref: 'architecture'; caption: string };

export interface Section { heading: string; blocks: Block[] }

export interface ReportDoc {
  type: ReportType;
  title: string;
  subtitle: string;
  generatedAt: string;
  isDemo: boolean;
  meta: [string, string][];
  sections: Section[];
}

const CLASS_LABEL = { confirmed: 'Confirmed finding', hypothesis: 'Hypothesis', missing_evidence: 'Missing evidence' } as const;

function liveThreats(d: ProjectData) {
  return d.threats.filter((t) => t.decision !== 'rejected');
}

function threatRef(d: ProjectData, t: Threat) {
  const i = d.threats.findIndex((x) => x.id === t.id);
  return `T-${String(i + 1).padStart(3, '0')}`;
}

function ratingText(d: ProjectData, l: number, i: number) {
  const b = riskBand(d.project.riskMatrix, l, i);
  return `${b.name} (${b.score})`;
}

function decisionNote(t: Threat) {
  return t.decision === 'proposed' ? ' [pending analyst review]' : '';
}

function metaRows(d: ProjectData, users: PublicUser[]): [string, string][] {
  const p = d.project;
  const reviewer = users.find((u) => u.id === p.reviewerId)?.displayName ?? 'Unassigned';
  const latest = d.versions[d.versions.length - 1];
  return [
    ['Client (alias)', p.clientAlias],
    ['Assessment', p.name],
    ['Scope', p.scope || 'Not recorded'],
    ['Architecture version (client)', p.architectureVersion || 'Not recorded'],
    ['Canonical model version', latest ? `v${latest.version} (${latest.hash.slice(0, 12)})` : 'No saved version'],
    ['Reviewer', reviewer],
    ['Review date', p.reviewDate || 'Not recorded'],
    ['Assessment status', STATUS_LABELS[p.status]],
  ];
}

function demoCallout(d: ProjectData): Block[] {
  return d.project.isDemo
    ? [{ type: 'callout', tone: 'warn', text: 'DEMONSTRATION DATA — This assessment uses synthetic data created to demonstrate the workbench. It does not describe any real organisation or system.' }]
    : [];
}

function architectureSection(d: ProjectData): Section {
  const comps = d.model.components;
  const byId = new Map(comps.map((c) => [c.id, c]));
  const unconfirmed = comps.filter((c) => c.status !== 'confirmed').length + d.model.flows.filter((f) => f.status !== 'confirmed').length;
  return {
    heading: 'Architecture snapshot',
    blocks: [
      { type: 'image', ref: 'architecture', caption: `Architecture model${d.versions.length ? ` v${d.versions[d.versions.length - 1].version}` : ' (unsaved draft)'}` },
      ...(unconfirmed ? [{ type: 'callout' as const, tone: 'warn' as const, text: `${unconfirmed} element(s) are unconfirmed and were excluded from analysis.` }] : []),
      {
        type: 'table', sheet: 'Components', columns: ['Component', 'Type', 'Status', 'Classification', 'Internet facing', 'Source'],
        rows: comps.map((c) => [c.name, COMPONENTS[c.type].label, c.status, c.properties.dataClassification || 'unknown', c.properties.internetFacing || 'unknown', `${c.source.kind}${c.source.ref ? `: ${c.source.ref}` : ''}`]),
      },
      {
        type: 'table', sheet: 'Data flows', columns: ['From', 'To', 'Label', 'Protocol', 'Encrypted', 'Authenticated', 'Classification', 'Status'],
        rows: d.model.flows.map((f) => [byId.get(f.from)?.name ?? '?', byId.get(f.to)?.name ?? '?', f.label, `${f.protocol}${f.port ? `:${f.port}` : ''}`, f.encrypted, f.authenticated, f.dataClassification, f.status]),
      },
      {
        type: 'table', sheet: 'Zones', columns: ['Zone / trust boundary', 'Type', 'Trust level', 'Status'],
        rows: d.model.zones.map((z) => [z.name, ZONES[z.zoneType].label, String(z.trustLevel), z.status]),
      },
    ],
  };
}

function threatTable(d: ProjectData, list: Threat[], sheet: string): Block {
  return {
    type: 'table', sheet,
    columns: ['Ref', 'Method', 'Category', 'Title', 'Assets', 'L', 'I', 'Rating', 'Status'],
    rows: list.map((t) => [threatRef(d, t), t.methodology, t.category, t.title, t.affectedAssets.join(', '), String(t.likelihood), String(t.impact), ratingText(d, t.likelihood, t.impact), t.decision]),
  };
}

function threatDetail(d: ProjectData, t: Threat): Block[] {
  return [
    { type: 'p', text: `${threatRef(d, t)} — ${t.title}${decisionNote(t)}` },
    {
      type: 'kv', rows: [
        ['Classification', CLASS_LABEL[t.classification]],
        ['Methodology / category', `${t.methodology} — ${t.category}`],
        ['Affected assets', t.affectedAssets.join(', ')],
        ['Attack scenario', t.attackScenario],
        ['Preconditions', t.preconditions.join('; ') || 'None recorded'],
        ['Existing controls', t.existingControls.join('; ') || 'None recorded'],
        ['Missing information', t.missingInformation.join('; ') || 'None'],
        ['Rating', `Likelihood ${t.likelihood} × Impact ${t.impact} = ${ratingText(d, t.likelihood, t.impact)}`],
        ['Mitigation', t.mitigation],
        ['Basis (model facts)', t.basis.map((b) => `${b.elementKind}:${b.fact}=${b.value}`).join('; ') || '—'],
        ['Evidence references', t.evidenceRefs.join('; ') || 'None'],
        ...(t.analystNotes ? [['Analyst notes', t.analystNotes] as [string, string]] : []),
      ],
    },
  ];
}

function sortByRating(list: Threat[]) {
  return [...list].sort((a, b) => b.likelihood * b.impact - a.likelihood * a.impact);
}

function riskTable(d: ProjectData, users: PublicUser[], risks: Risk[]): Block {
  return {
    type: 'table', sheet: 'Risk register',
    columns: ['Ref', 'Risk', 'Owner', 'Inherent', 'Residual', 'Strategy', 'Status', 'Target date', 'Approval'],
    rows: risks.map((r) => [
      r.ref, r.title, r.owner || 'Unassigned', ratingText(d, r.likelihood, r.impact), ratingText(d, r.residualLikelihood, r.residualImpact),
      r.strategy, r.status.replace('_', ' '), r.targetDate || '—',
      r.approval.state === 'approved' ? `Approved by ${users.find((u) => u.id === r.approval.by)?.displayName ?? r.approval.by} ${r.approval.at?.slice(0, 10) ?? ''}` : r.approval.state.replace('_', ' '),
    ]),
  };
}

function heatmap(d: ProjectData, risks: Risk[]): Block {
  const m = d.project.riskMatrix;
  const rows: string[][] = [];
  for (let l = 5; l >= 1; l--) {
    const row = [`${l} ${m.likelihoodLabels[l - 1]}`];
    for (let i = 1; i <= 5; i++) {
      const n = risks.filter((r) => r.likelihood === l && r.impact === i).length;
      row.push(`${riskBand(m, l, i).name}${n ? ` • ${n}` : ''}`);
    }
    rows.push(row);
  }
  return { type: 'table', sheet: 'Heatmap', columns: ['Likelihood \\ Impact', ...m.impactLabels.map((x, i) => `${i + 1} ${x}`)], rows };
}

function controlSection(d: ProjectData, catalogs: ControlCatalog[]): Section {
  const blocks: Block[] = [
    { type: 'callout', tone: 'info', text: 'Control mappings show which findings are relevant to each control. Compliance is not inferred from architecture diagrams; a control is reported as satisfied only where a reviewer has recorded supporting evidence.' },
  ];
  const selected = catalogs.filter((c) => d.project.catalogIds.includes(c.id) && c.status === 'approved');
  if (!selected.length) blocks.push({ type: 'p', text: 'No approved control catalog was selected for this assessment.' });
  for (const cat of selected) {
    const maps = mapThreatsToControls(cat, d.threats);
    blocks.push({ type: 'p', text: `${FRAMEWORK_LABELS[cat.framework]} — ${cat.version}${cat.isDemo ? ' (demonstration excerpt)' : ''}` });
    blocks.push({
      type: 'table', sheet: `Controls ${cat.framework}`.slice(0, 31),
      columns: ['Control', 'Title', 'Review status', 'Confirmed', 'Hypotheses', 'Missing info', 'Evidence'],
      rows: maps.map((m) => {
        const rv = d.controlReviews.find((r) => r.catalogId === cat.id && r.controlId === m.control.id);
        return [m.control.id, m.control.title, REVIEW_STATUS_LABELS[rv?.status ?? 'not_assessed'], String(m.confirmed.length), String(m.hypotheses.length), String(m.missing.length), rv?.evidenceRefs.join('; ') || '—'];
      }),
    });
  }
  return { heading: 'Control review', blocks };
}

function evidenceSection(d: ProjectData): Section {
  return {
    heading: 'Evidence references',
    blocks: d.evidence.length
      ? [{ type: 'table', sheet: 'Evidence', columns: ['Evidence ID', 'File', 'Uploaded', 'SHA-256', 'Description'], rows: d.evidence.map((e) => [e.id, e.fileName, e.uploadedAt.slice(0, 10), e.sha256.slice(0, 16) + '…', e.description || '—']) }]
      : [{ type: 'p', text: 'No evidence files have been registered for this assessment.' }],
  };
}

function limitations(d: ProjectData): Section {
  const items = [
    'Findings are derived from the architecture model as confirmed by the reviewer; they are not the result of technical testing.',
    'Compliance with control frameworks is not inferred from diagrams. Controls are only reported as satisfied where evidence was reviewed.',
    `Threat scenarios were generated by the ${ENGINE_NAME} v${ENGINE_VERSION} from confirmed model facts and reviewed by an analyst; no AI provider was used unless explicitly recorded.`,
    'Items classified as "Missing evidence" could not be evaluated and should be resolved before conclusions are relied upon.',
  ];
  const unconf = d.model.components.filter((c) => c.status !== 'confirmed').length;
  if (unconf) items.push(`${unconf} component(s) remained unconfirmed and were excluded from the analysis.`);
  const pending = d.threats.filter((t) => t.decision === 'proposed').length;
  if (pending) items.push(`${pending} generated threat(s) had not yet been reviewed by an analyst at the time of generation.`);
  return {
    heading: 'Limitations',
    blocks: [...(d.project.narrative.limitations.trim() ? [{ type: 'p' as const, text: d.project.narrative.limitations }] : []), { type: 'bullets', items }],
  };
}

function summaryStats(d: ProjectData): Block {
  const live = liveThreats(d);
  const m = d.project.riskMatrix;
  const confirmed = live.filter((t) => t.classification === 'confirmed');
  const bandCounts = new Map<string, number>();
  for (const t of confirmed) {
    const b = riskBand(m, t.likelihood, t.impact).name;
    bandCounts.set(b, (bandCounts.get(b) ?? 0) + 1);
  }
  return {
    type: 'kv', rows: [
      ['Confirmed findings', `${confirmed.length}${bandCounts.size ? ` (${[...bandCounts].map(([k, v]) => `${v} ${k}`).join(', ')})` : ''}`],
      ['Hypotheses', String(live.filter((t) => t.classification === 'hypothesis').length)],
      ['Missing evidence items', String(live.filter((t) => t.classification === 'missing_evidence').length)],
      ['Risks in register', String(d.risks.length)],
      ['Risks approved by reviewer', String(d.risks.filter((r) => r.approval.state === 'approved').length)],
    ],
  };
}

function autoSummary(d: ProjectData): string {
  const live = liveThreats(d);
  const confirmed = sortByRating(live.filter((t) => t.classification === 'confirmed'));
  if (!d.runs.length) return 'No threat analysis has been run against a saved architecture version yet.';
  const top = confirmed.slice(0, 3).map((t) => `${t.title} (${ratingText(d, t.likelihood, t.impact)})`);
  return `The review analysed ${d.model.components.filter((c) => c.status === 'confirmed').length} confirmed components and ${d.model.flows.filter((f) => f.status === 'confirmed').length} confirmed data flows. ${confirmed.length} confirmed finding(s) were identified${top.length ? `; the highest rated are: ${top.join('; ')}` : ''}. ${live.filter((t) => t.classification === 'missing_evidence').length} item(s) require additional information from the client before they can be assessed.`;
}

function recommendations(d: ProjectData): Section {
  const confirmed = sortByRating(liveThreats(d).filter((t) => t.classification === 'confirmed'));
  const seen = new Set<string>();
  const recs: string[] = [];
  for (const t of confirmed) {
    if (seen.has(t.mitigation)) continue;
    seen.add(t.mitigation);
    recs.push(`${t.mitigation} (addresses ${confirmed.filter((x) => x.mitigation === t.mitigation).map((x) => threatRef(d, x)).join(', ')})`);
  }
  const missing = liveThreats(d).filter((t) => t.classification === 'missing_evidence');
  if (missing.length) recs.push(`Provide the ${missing.reduce((n, t) => n + t.missingInformation.length, 0)} outstanding information item(s) listed under "Missing evidence" so the related threats can be evaluated.`);
  return {
    heading: 'Recommendations',
    blocks: [...(d.project.narrative.recommendations.trim() ? [{ type: 'p' as const, text: d.project.narrative.recommendations }] : []), recs.length ? { type: 'bullets', items: recs.slice(0, 20) } : { type: 'p', text: 'No confirmed findings require remediation.' }],
  };
}

function methodology(d: ProjectData, catalogs: ControlCatalog[]): Section {
  const cats = catalogs.filter((c) => d.project.catalogIds.includes(c.id)).map((c) => `${FRAMEWORK_LABELS[c.framework]} ${c.version}`);
  const lastRun = d.runs[d.runs.length - 1];
  return {
    heading: 'Methodology',
    blocks: [
      { type: 'bullets', items: [
        'Architecture captured as a versioned canonical JSON model (components, data flows, trust zones and properties). Imported elements were confirmed by the reviewer before use.',
        `Threat modelling methodologies: ${d.project.methodologies.join(', ') || 'none selected'}. STRIDE applied per element; PASTA used to model attack paths from entry points to critical assets; OCTAVE Allegro used for information-asset areas of concern.`,
        'Each generated item is classified as a Confirmed finding (explicit fact shows a control gap), Hypothesis (structurally applicable, controls recorded but unverified) or Missing evidence (required facts unknown).',
        `Risk rated on a 5×5 likelihood × impact matrix with bands: ${d.project.riskMatrix.bands.map((b) => `${b.name} ≥ ${b.min}`).join(', ')}.`,
        `Control frameworks referenced: ${cats.join('; ') || 'none'}.`,
        lastRun ? `Latest analysis run: ${lastRun.at.slice(0, 16).replace('T', ' ')} UTC by ${lastRun.provider} v${lastRun.providerVersion} on model v${lastRun.modelVersion}.` : 'No analysis run recorded.',
      ] },
    ],
  };
}

function roadmap(d: ProjectData, users: PublicUser[]): Section[] {
  const m = d.project.riskMatrix;
  const now = Date.now();
  const horizon = (date: string, score: number) => {
    if (!date) return score >= 17 ? '0–30 days' : score >= 10 ? '31–90 days' : '91–180 days';
    const days = (new Date(date).getTime() - now) / 86400000;
    return days <= 30 ? '0–30 days' : days <= 90 ? '31–90 days' : days <= 180 ? '91–180 days' : '180+ days';
  };
  const rows: { h: string; cells: string[]; score: number }[] = [];
  for (const r of d.risks.filter((r) => r.status !== 'closed')) {
    const b = riskBand(m, r.likelihood, r.impact);
    const acts = r.actions.length ? r.actions.filter((a) => !a.done) : [{ id: '', description: '(no actions defined)', owner: r.owner, dueDate: r.targetDate, done: false }];
    for (const a of acts) rows.push({ h: horizon(a.dueDate || r.targetDate, b.score), score: b.score, cells: [r.ref, a.description, a.owner || r.owner || 'Unassigned', a.dueDate || r.targetDate || '—', `${b.name} (${b.score})`, r.strategy] });
  }
  const covered = new Set(d.risks.flatMap((r) => r.threatIds));
  for (const t of liveThreats(d).filter((t) => t.classification === 'confirmed' && !covered.has(t.id))) {
    const b = riskBand(m, t.likelihood, t.impact);
    rows.push({ h: horizon('', b.score), score: b.score, cells: [threatRef(d, t), t.mitigation, 'Not yet assigned (no risk entry)', '—', `${b.name} (${b.score})`, 'mitigate (proposed)'] });
  }
  const order = ['0–30 days', '31–90 days', '91–180 days', '180+ days'];
  const sections: Section[] = [];
  for (const h of order) {
    const list = rows.filter((r) => r.h === h).sort((a, b) => b.score - a.score);
    if (!list.length) continue;
    sections.push({ heading: `Horizon: ${h}`, blocks: [{ type: 'table', sheet: `Roadmap ${h}`.slice(0, 31), columns: ['Ref', 'Action', 'Owner', 'Due', 'Priority', 'Treatment'], rows: list.map((r) => r.cells) }] });
  }
  if (!sections.length) sections.push({ heading: 'Actions', blocks: [{ type: 'p', text: 'No open remediation actions.' }] });
  void users;
  return sections;
}

export function buildReport(type: ReportType, d: ProjectData, users: PublicUser[], catalogs: ControlCatalog[], now = new Date()): ReportDoc {
  const live = liveThreats(d);
  const confirmed = sortByRating(live.filter((t) => t.classification === 'confirmed'));
  const hyps = sortByRating(live.filter((t) => t.classification === 'hypothesis'));
  const missing = live.filter((t) => t.classification === 'missing_evidence');
  const exec: Section = {
    heading: 'Executive summary',
    blocks: [
      ...demoCallout(d),
      ...(d.project.narrative.executiveSummary.trim() ? [{ type: 'p' as const, text: d.project.narrative.executiveSummary }] : []),
      { type: 'p', text: autoSummary(d) },
      summaryStats(d),
    ],
  };
  const sections: Section[] = [];
  if (type === 'architecture_review') {
    sections.push(exec, { heading: 'Scope', blocks: [{ type: 'p', text: d.project.scope || 'Scope not recorded.' }] }, methodology(d, catalogs), architectureSection(d),
      { heading: 'Findings', blocks: confirmed.length ? [threatTable(d, confirmed, 'Findings'), ...confirmed.flatMap((t) => threatDetail(d, t))] : [{ type: 'p', text: 'No confirmed findings.' }] },
      { heading: 'Hypotheses requiring validation', blocks: hyps.length ? [threatTable(d, hyps, 'Hypotheses')] : [{ type: 'p', text: 'None.' }] },
      { heading: 'Missing evidence / information requests', blocks: missing.length ? [{ type: 'table', sheet: 'Information requests', columns: ['Ref', 'Topic', 'Information required'], rows: missing.flatMap((t) => t.missingInformation.map((mi) => [threatRef(d, t), t.title, mi])) }] : [{ type: 'p', text: 'None.' }] },
      controlSection(d, catalogs),
      { heading: 'Risk ratings', blocks: d.risks.length ? [heatmap(d, d.risks), riskTable(d, users, d.risks)] : [{ type: 'p', text: 'No risks have been registered.' }] },
      evidenceSection(d), limitations(d), recommendations(d));
  } else if (type === 'threat_model') {
    sections.push(exec, methodology(d, catalogs), architectureSection(d));
    for (const meth of ['STRIDE', 'PASTA', 'OCTAVE', 'PROTOTYPE', 'MANUAL'] as const) {
      const list = sortByRating(live.filter((t) => t.methodology === meth && t.classification !== 'missing_evidence'));
      if (!list.length) continue;
      sections.push({ heading: `${meth === 'MANUAL' ? 'Analyst-authored' : meth} threat scenarios`, blocks: [threatTable(d, list, `${meth} threats`), ...list.flatMap((t) => threatDetail(d, t))] });
    }
    sections.push({ heading: 'Missing evidence', blocks: missing.length ? [{ type: 'table', sheet: 'Missing evidence', columns: ['Ref', 'Topic', 'Information required'], rows: missing.flatMap((t) => t.missingInformation.map((mi) => [threatRef(d, t), t.title, mi])) }] : [{ type: 'p', text: 'None.' }] }, evidenceSection(d), limitations(d));
  } else if (type === 'risk_register') {
    sections.push(exec, { heading: 'Risk matrix', blocks: [heatmap(d, d.risks), { type: 'kv', rows: d.project.riskMatrix.bands.map((b) => [b.name, `score ≥ ${b.min}`] as [string, string]) }] },
      { heading: 'Risk register', blocks: d.risks.length ? [riskTable(d, users, d.risks)] : [{ type: 'p', text: 'No risks have been registered.' }] },
      { heading: 'Risk details', blocks: d.risks.flatMap((r) => [
        { type: 'p' as const, text: `${r.ref} — ${r.title}` },
        { type: 'kv' as const, rows: [
          ['Description', r.description || '—'], ['Linked threats', r.threatIds.map((id) => { const t = d.threats.find((x) => x.id === id); return t ? threatRef(d, t) : id; }).join(', ') || '—'],
          ['Owner', r.owner || 'Unassigned'], ['Treatment', `${r.strategy} / ${r.status.replace('_', ' ')}`], ['Target date', r.targetDate || '—'],
          ['Actions', r.actions.map((a) => `${a.done ? '[done] ' : ''}${a.description} (${a.owner || 'unassigned'}, ${a.dueDate || 'no date'})`).join('; ') || '—'],
          ['Approval', `${r.approval.state.replace('_', ' ')}${r.approval.comment ? ` — ${r.approval.comment}` : ''}`],
        ] as [string, string][] },
      ]) }, limitations(d));
  } else {
    sections.push(exec, ...roadmap(d, users), recommendations(d), limitations(d));
  }
  return {
    type,
    title: REPORT_TYPES[type].title,
    subtitle: `${d.project.clientAlias} — ${d.project.name}`,
    generatedAt: now.toISOString(),
    isDemo: d.project.isDemo,
    meta: metaRows(d, users),
    sections,
  };
}
