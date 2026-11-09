// First-start seeding. In DEMONSTRATION mode this creates demo users, demonstration control
// catalog excerpts and a synthetic sample assessment. The sample's threats are produced by
// running the real analysis engine over the synthetic model, not hardcoded.
// In PRODUCTION mode only a bootstrap administrator is created; no demo content is loaded.

import fs from 'node:fs';
import path from 'node:path';
import { config } from './config';
import { hashPassword, newId, sha256, token } from './crypto';
import { getDb, persist, type StoredProject, type StoredUser } from './store';
import { audit } from './audit';
import { DEMO_CATALOGS } from '../shared/controls';
import { analyzeModel, ENGINE_NAME, ENGINE_VERSION, mergeRun } from '../shared/engine';
import { canonicalJson, defaultRiskMatrix } from '../shared/schema';
import type { ArchComponent, ArchitectureModel, DataFlow, Role, TrustZone } from '../shared/types';
import { MODEL_SCHEMA } from '../shared/types';

function mkUser(username: string, displayName: string, role: Role, password: string): StoredUser {
  return { id: newId(), username, displayName, role, disabled: false, passwordHash: hashPassword(password), createdAt: new Date().toISOString(), mustChangePassword: false };
}

export function seed() {
  const db = getDb();
  if (db.users.length) return;
  const system = { id: 'system', username: 'system' };

  if (config.mode === 'production') {
    const pw = process.env.SAWB_BOOTSTRAP_ADMIN_PASSWORD;
    if (!pw) throw new Error('Production first start requires SAWB_BOOTSTRAP_ADMIN_PASSWORD to create the initial administrator.');
    const admin = mkUser('admin', 'Administrator', 'admin', pw);
    admin.mustChangePassword = true;
    db.users.push(admin);
    audit(system, 'system.bootstrap', { detail: 'Created bootstrap administrator (production mode, no demo content).' });
    persist(true);
    return;
  }

  const password = config.demoPassword ?? `Demo-${token(9)}1a`;
  const users = [
    mkUser('admin', 'Demo Administrator', 'admin', password),
    mkUser('lead', 'Demo Lead Reviewer', 'lead_reviewer', password),
    mkUser('analyst', 'Demo Security Analyst', 'analyst', password),
    mkUser('viewer', 'Demo Viewer', 'viewer', password),
  ];
  db.users.push(...users);
  const credFile = path.join(config.dataDir, 'DEMO_CREDENTIALS.txt');
  fs.writeFileSync(credFile, `Demonstration accounts (synthetic environment only)\nusernames: admin, lead, analyst, viewer\npassword: ${password}\n`, { mode: 0o600 });
  console.log(`\n[demo] Demonstration users created: admin, lead, analyst, viewer`);
  console.log(`[demo] Shared demo password written to ${credFile}${config.demoPassword ? ' (from SAWB_DEMO_PASSWORD)' : ''}\n`);

  const [admin, lead, analyst, viewer] = users;
  const now = new Date().toISOString();
  for (const c of DEMO_CATALOGS) {
    db.catalogs.push({
      id: newId(), framework: c.framework, name: c.name, version: c.version, status: 'approved', source: c.source, isDemo: true,
      importedBy: admin.id, importedAt: now, approvedBy: lead.id, approvedAt: now,
      contentHash: sha256(canonicalJson(c.controls)), controls: c.controls,
    });
  }

  // ---------------------------------------------------------------- synthetic sample assessment
  const zone = (name: string, zoneType: TrustZone['zoneType'], trustLevel: number, x: number, y: number, w: number, h: number): TrustZone =>
    ({ id: newId(), name, zoneType, trustLevel, x, y, w, h, status: 'confirmed', source: { kind: 'manual' } });
  const zones = [
    zone('Internet', 'internet', 0, 20, 20, 200, 560),
    zone('DMZ', 'dmz', 1, 250, 20, 360, 400),
    zone('Internal application zone', 'internal', 3, 640, 20, 360, 400),
    zone('Restricted data zone', 'restricted', 4, 1030, 20, 220, 400),
    zone('Management zone', 'management', 4, 640, 450, 610, 160),
    zone('Payment partner network', 'third_party', 1, 250, 450, 360, 160),
  ];
  const comp = (name: string, type: ArchComponent['type'], x: number, y: number, properties: Record<string, string>, status: ArchComponent['status'] = 'confirmed'): ArchComponent =>
    ({ id: newId(), name, type, x, y, properties, status, source: status === 'confirmed' ? { kind: 'manual' } : { kind: 'drawio', ref: 'demo-legacy-segment.drawio', location: 'cell 7' } });
  const customer = comp('Retail customer', 'user', 50, 240, { population: 'customers', mfa: 'unknown' });
  const fw = comp('Edge firewall', 'firewall', 270, 60, { defaultDeny: 'yes', ruleReview: 'unknown', mgmtIsolated: 'yes', logging: 'yes', internetFacing: 'yes' });
  const lb = comp('Load balancer / WAF', 'load_balancer', 450, 60, { waf: 'yes', ddosProtection: 'unknown', tlsTermination: 'yes', internetFacing: 'yes', logging: 'yes' });
  const web = comp('Online banking web portal', 'web_server', 360, 240, { authentication: 'yes', mfa: 'no', authorization: 'yes', inputValidation: 'unknown', securityHeaders: 'unknown', rateLimiting: 'no', waf: 'yes', logging: 'yes', patching: 'yes', hardening: 'unknown', dataClassification: 'confidential', criticality: 'high' });
  const api = comp('API gateway', 'api_gateway', 660, 100, { authentication: 'yes', mfa: 'unknown', authorization: 'yes', rateLimiting: 'yes', schemaValidation: 'unknown', waf: 'no', logging: 'yes', dataClassification: 'confidential' });
  const app = comp('Core banking application', 'app_server', 840, 240, { authentication: 'yes', authorization: 'yes', mfa: 'unknown', secretsManagement: 'no', hardening: 'unknown', inputValidation: 'yes', logging: 'unknown', patching: 'yes', rateLimiting: 'unknown', dataClassification: 'restricted', criticality: 'critical' });
  const report = comp('Reporting service', 'app_server', 660, 300, { authentication: 'yes', authorization: 'unknown', logging: 'no', patching: 'unknown', dataClassification: 'confidential', criticality: 'medium' });
  const db1 = comp('Customer accounts database', 'database', 1070, 200, { authentication: 'yes', authorization: 'yes', mfa: 'unknown', encryptionAtRest: 'yes', backups: 'unknown', activityMonitoring: 'no', leastPrivilegeAccounts: 'unknown', logging: 'yes', dataClassification: 'restricted', criticality: 'critical' });
  const iam = comp('Identity provider (IAM)', 'iam', 700, 500, { authentication: 'yes', mfa: 'yes', authorization: 'yes', pam: 'no', accessReviews: 'unknown', federation: 'oidc', logging: 'yes', dataClassification: 'confidential', criticality: 'high' });
  const adminWs = comp('Administrator workstation', 'endpoint', 1050, 500, { edr: 'yes', diskEncryption: 'yes', managed: 'yes', patching: 'yes', logging: 'yes' });
  const psp = comp('Payment service provider', 'third_party', 360, 520, { contractSecurityClauses: 'yes', vendorAssessment: 'unknown', authentication: 'yes', dataClassification: 'confidential' });
  const legacy = comp('Legacy file transfer server', 'app_server', 1060, 330, {}, 'unconfirmed');
  const components = [customer, fw, lb, web, api, app, report, db1, iam, adminWs, psp, legacy];

  const flow = (from: ArchComponent, to: ArchComponent, label: string, protocol: string, port: string, encrypted: DataFlow['encrypted'], authenticated: DataFlow['authenticated'], cls: DataFlow['dataClassification'], status: DataFlow['status'] = 'confirmed'): DataFlow =>
    ({ id: newId(), from: from.id, to: to.id, label, protocol, port, encrypted, authenticated, dataClassification: cls, bidirectional: false, status, source: status === 'confirmed' ? { kind: 'manual' } : { kind: 'drawio', ref: 'demo-legacy-segment.drawio' } });
  const flows = [
    flow(customer, fw, 'Banking session', 'HTTPS', '443', 'yes', 'unknown', 'confidential'),
    flow(fw, lb, 'Permitted web traffic', 'HTTPS', '443', 'yes', 'unknown', 'confidential'),
    flow(lb, web, 'Offloaded HTTP', 'HTTP', '8080', 'no', 'no', 'confidential'),
    flow(web, api, 'Account API calls', 'HTTPS', '443', 'yes', 'unknown', 'confidential'),
    flow(api, app, 'Service requests', 'mTLS', '8443', 'yes', 'yes', 'restricted'),
    flow(app, db1, 'Account queries', 'JDBC', '1521', 'unknown', 'yes', 'restricted'),
    flow(web, db1, 'Balance widget direct query', 'TCP', '1521', 'unknown', 'unknown', 'restricted'),
    flow(report, db1, 'Nightly extract', 'JDBC', '1521', 'unknown', 'yes', 'restricted'),
    flow(app, iam, 'Token validation', 'HTTPS', '443', 'yes', 'yes', 'internal'),
    flow(app, psp, 'Payment initiation', 'HTTPS', '443', 'yes', 'unknown', 'confidential'),
    flow(adminWs, app, 'Administration', 'SSH', '22', 'yes', 'yes', 'restricted'),
    flow(app, legacy, 'Statement files', 'FTP', '21', 'no', 'unknown', 'confidential', 'unconfirmed'),
  ];

  const model: ArchitectureModel = {
    schema: MODEL_SCHEMA, components, flows, zones,
    notes: 'SYNTHETIC DEMONSTRATION MODEL. Fictitious retail banking portal used to demonstrate the workbench. The legacy file transfer server and its flow are deliberately left unconfirmed to show that unconfirmed elements are excluded from analysis.',
  };
  const projectId = newId();
  const hash = sha256(canonicalJson(model));
  const p: StoredProject = {
    project: {
      id: projectId, name: 'Online Banking Portal — Architecture Review (DEMO)', clientAlias: 'DEMO-CLIENT-ALPHA',
      scope: 'Synthetic demonstration scope: customer-facing online banking portal, API tier, core application, customer data store, identity provider and payment partner integration. Excludes mobile apps and branch systems.',
      architectureVersion: 'HLD 2.3 (synthetic)', reviewerId: lead.id, status: 'in_review', reviewDate: now.slice(0, 10),
      createdAt: now, createdBy: lead.id, updatedAt: now, isDemo: true,
      members: [{ userId: lead.id, role: 'owner' }, { userId: analyst.id, role: 'editor' }, { userId: viewer.id, role: 'viewer' }],
      methodologies: ['STRIDE', 'PASTA', 'OCTAVE'],
      catalogIds: db.catalogs.map((c) => c.id),
      riskMatrix: defaultRiskMatrix(),
      narrative: { executiveSummary: '', limitations: '', recommendations: '' },
      history: [{ at: now, by: lead.id, action: 'Created demonstration assessment' }, { at: now, by: lead.id, action: 'Saved model version 1', detail: 'Initial HLD capture' }],
    },
    model,
    versions: [{ version: 1, savedAt: now, savedBy: lead.id, message: 'Initial HLD capture (synthetic)', hash, model: JSON.parse(JSON.stringify(model)) }],
    threats: [], runs: [], controlReviews: [], risks: [], evidence: [],
  };

  const result = analyzeModel(model, p.project.methodologies, 1);
  const runId = newId();
  p.threats = mergeRun([], result.drafts, { runId, at: now, by: analyst.id, newId, referenced: new Set() });
  p.runs.push({
    id: runId, at: now, by: analyst.id, provider: ENGINE_NAME, providerVersion: ENGINE_VERSION, modelVersion: 1, methodologies: p.project.methodologies,
    counts: { confirmed: p.threats.filter((t) => t.classification === 'confirmed').length, hypothesis: p.threats.filter((t) => t.classification === 'hypothesis').length, missing_evidence: p.threats.filter((t) => t.classification === 'missing_evidence').length },
    skippedUnconfirmed: result.skippedUnconfirmed,
  });

  // Promote the three highest-rated confirmed findings into the risk register (status: pending approval).
  const top = p.threats.filter((t) => t.classification === 'confirmed').sort((a, b) => b.likelihood * b.impact - a.likelihood * a.impact).slice(0, 3);
  top.forEach((t, i) => {
    t.decision = 'accepted';
    p.risks.push({
      id: newId(), ref: `R-${String(i + 1).padStart(3, '0')}`, title: t.title, description: t.attackScenario, threatIds: [t.id],
      likelihood: t.likelihood, impact: t.impact, residualLikelihood: Math.max(1, t.likelihood - 2), residualImpact: t.impact,
      owner: '', strategy: 'mitigate', status: 'open', targetDate: '',
      actions: [{ id: newId(), description: t.mitigation, owner: '', dueDate: '', done: false }],
      approval: { state: 'pending' }, createdBy: analyst.id, createdAt: now, updatedAt: now,
    });
  });

  db.projects[projectId] = p;
  audit(system, 'system.seed', { projectId, detail: 'Created demonstration users, demo catalog excerpts and synthetic sample assessment.' });
  persist(true);
}
