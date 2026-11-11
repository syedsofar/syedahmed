// Port of the ArchGuard prototype's rule checks (computeReview and computeThreats in
// app.js) into the workbench engine, as the PROTOTYPE method.
//
// Changes from the prototype, required by the workbench's rules:
//   - Only confirmed components and flows are analysed. Unconfirmed elements are excluded.
//   - Explicit "no" results give confirmed findings. Unknown results give missing-evidence items.
//     Generic threat scenarios are hypotheses, never confirmed findings.
//   - Control mappings in the prototype (for example "NIST SP 800-53 SC-28") are not approved
//     catalog content. They are kept only as unverified references in the rationale.
//   - Likelihood and impact are set from the prototype severity (see SEVERITY_RATING). These
//     are defaults for the workbench's risk matrix, not values from the prototype.
import type { ArchComponent, ArchitectureModel, DataFlow, FactRef, ThreatClass } from './types';
import type { ThreatDraft } from './engine';

type Sev = 'High' | 'Medium' | 'Needs validation';

/** Default likelihood/impact per prototype severity. Assumption; adjust in the risk matrix. */
export const SEVERITY_RATING: Record<Sev, { likelihood: number; impact: number; classification: ThreatClass }> = {
  'High': { likelihood: 3, impact: 4, classification: 'confirmed' },
  'Medium': { likelihood: 2, impact: 3, classification: 'hypothesis' },
  'Needs validation': { likelihood: 1, impact: 1, classification: 'missing_evidence' },
};

const CATEGORY: Record<string, string> = {
  'IAM-01': 'Identity and access', 'DATA-01': 'Data protection', 'MON-01': 'Monitoring and logging',
  'RES-01': 'Resilience and recovery', 'AI-01': 'AI safety', 'FLOW-01': 'Transport security',
  'FLOW-02': 'Trust boundary authentication',
  'T-S01': 'Spoofing', 'T-T01': 'Tampering', 'T-R01': 'Repudiation', 'T-I01': 'Information disclosure',
  'T-D01': 'Denial of service', 'T-E01': 'Elevation of privilege', 'T-S02': 'Spoofing',
};

const norm = (v: string | undefined) => (v ?? '').trim().toLowerCase();
const SENSITIVE = ['confidential', 'restricted'];

interface Facts {
  internet: string; mfa: string; encryptedAtRest: string; logging: string; backups: string;
  aiGuardrails: string; data: string; criticality: string; zone: string; group: string;
}

/** Facts for one component: designer values when present, otherwise the canonical property. */
function facts(c: ArchComponent): Facts {
  const p = c.properties;
  const get = (designerKey: string, canonicalKey?: string) =>
    norm(p['designer.security.' + designerKey] ?? (canonicalKey ? p[canonicalKey] : undefined) ?? 'unknown');
  return {
    internet: get('internet', 'internetFacing'),
    mfa: get('mfa', 'mfa'),
    encryptedAtRest: get('encryptedAtRest', 'encryptedAtRest'),
    logging: get('logging', 'logging'),
    backups: get('backups', 'backups'),
    aiGuardrails: get('aiGuardrails'),
    data: get('data', 'dataClassification'),
    criticality: get('criticality', 'criticality'),
    zone: p['designer.zone'] ?? 'Unassigned',
    group: c.catalogRef?.group ?? '',
  };
}

interface Finding { id: string; sev: Sev; title: string; target: string; details: string; recommendation: string; reference: string; basis: FactRef[] }

/** Port of computeReview: component and flow checks on confirmed elements. */
export function prototypeFindings(model: ArchitectureModel): Finding[] {
  const out: Finding[] = [];
  const comps = model.components.filter((c) => c.status === 'confirmed');
  const ids = new Set(comps.map((c) => c.id));
  const flows = model.flows.filter((f) => f.status === 'confirmed' && ids.has(f.from) && ids.has(f.to));
  const byId = new Map(model.components.map((c) => [c.id, c]));
  const fact = (elementId: string, kind: 'component' | 'flow', name: string, value: string): FactRef => ({ elementId, elementKind: kind, fact: name, value });

  for (const c of comps) {
    const f = facts(c);
    const t = c.name;
    const sensitive = SENSITIVE.includes(f.data);
    const critical = ['high', 'critical'].includes(f.criticality);
    const push = (id: string, sev: Sev, title: string, details: string, recommendation: string, reference: string, name: string, value: string) =>
      out.push({ id, sev, title, target: t, details, recommendation, reference, basis: [fact(c.id, 'component', name, value)] });

    if (f.internet === 'yes' && f.mfa === 'no') push('IAM-01', 'High', 'Internet-facing component without confirmed MFA', 'Internet exposure is explicitly Yes while MFA is No. Validate whether the relevant human access path requires MFA.', 'Enforce phishing-resistant MFA where applicable; confirm service identity controls and document approved exceptions.', 'STRIDE: Spoofing', 'mfa', 'no');
    else if (f.internet === 'yes' && f.mfa === 'unknown') push('IAM-01', 'Needs validation', 'MFA coverage requires confirmation', 'Internet-facing component has no verified MFA or identity-control evidence.', 'Confirm identity architecture, users and service access; record applicable MFA requirements.', 'STRIDE: Spoofing', 'mfa', 'unknown');
    if (sensitive && f.encryptedAtRest === 'no') push('DATA-01', 'High', 'Sensitive data not encrypted at rest', `${f.data} data is declared and encryption at rest is marked No.`, 'Enable suitable at-rest encryption and centrally managed keys; document justified exceptions.', 'STRIDE: Information disclosure', 'encryptedAtRest', 'no');
    else if (sensitive && f.encryptedAtRest === 'unknown') push('DATA-01', 'Needs validation', 'Encryption at rest requires confirmation', `Data classified ${f.data}; at-rest encryption is not confirmed.`, 'Validate encryption settings, key ownership and evidence for the relevant storage/service.', '', 'encryptedAtRest', 'unknown');
    if (critical && f.logging === 'no') push('MON-01', 'High', 'Critical component missing centralized security logging', 'Criticality is High/Critical and centralized security logging is marked No.', 'Forward audit/security events to central monitoring with retention and access protections.', 'STRIDE: Repudiation', 'logging', 'no');
    else if (critical && f.logging === 'unknown') push('MON-01', 'Needs validation', 'Critical-system logging requires confirmation', 'Security-event collection, monitoring or retention is not verified.', 'Validate log coverage, use cases, alert ownership and retention.', '', 'logging', 'unknown');
    if (critical && f.backups === 'no') push('RES-01', 'High', 'Critical service lacks recovery capability', 'Backups/recovery is explicitly No for a critical or high-importance component.', 'Define and test recovery arrangements against approved RTO/RPO and ransomware resilience objectives.', '', 'backups', 'no');
    else if (critical && f.backups === 'unknown') push('RES-01', 'Needs validation', 'Critical-service recovery requires confirmation', 'Recovery arrangements are not verified.', 'Validate backups, recovery tests, dependency mapping and recovery objectives.', '', 'backups', 'unknown');
    if (f.group === 'ai' && f.data === 'restricted' && f.aiGuardrails === 'no') push('AI-01', 'High', 'AI component lacks recorded safety controls', 'Restricted-data AI component has AI safety controls explicitly marked No.', 'Introduce data protection, prompt-injection defenses, output evaluation, and human oversight proportional to the use case.', 'OWASP LLM Top 10', 'aiGuardrails', 'no');
  }

  for (const fl of flows) {
    const a = byId.get(fl.from)!;
    const b = byId.get(fl.to)!;
    const target = `${a.name} → ${b.name}`;
    const sensitive = SENSITIVE.includes(norm(fl.dataClassification));
    const cross = facts(a).zone !== facts(b).zone;
    const push = (id: string, sev: Sev, title: string, details: string, recommendation: string, reference: string, name: string, value: string) =>
      out.push({ id, sev, title, target, details, recommendation, reference, basis: [fact(fl.id, 'flow', name, value)] });

    if (fl.encrypted === 'no' && sensitive) push('FLOW-01', 'High', 'Sensitive data transmitted without encryption', `Flow carrying ${fl.dataClassification} data is explicitly recorded as unencrypted.`, 'Use appropriately configured transport encryption and validate protocol/certificate settings.', 'STRIDE: Information disclosure', 'encrypted', 'no');
    else if (fl.encrypted === 'unknown' && sensitive) push('FLOW-01', 'Needs validation', 'Transport encryption requires confirmation', `Encryption for ${fl.dataClassification} data flow has not been confirmed.`, 'Validate TLS/mTLS, certificate lifecycle and any applicable end-to-end encryption.', '', 'encrypted', 'unknown');
    if (cross && fl.authenticated === 'no') push('FLOW-02', 'High', 'Unauthenticated cross-boundary connection', 'Data crosses explicitly different trust zones and service authentication is set to No.', 'Implement service-to-service authentication, scoped authorization and boundary controls.', 'STRIDE: Spoofing', 'authenticated', 'no');
    else if (cross && fl.authenticated === 'unknown') push('FLOW-02', 'Needs validation', 'Cross-boundary authentication requires confirmation', 'Service authentication is not verified for a flow crossing trust zones.', 'Validate workload identity, authentication, authorization, and third-party integration requirements.', '', 'authenticated', 'unknown');
  }
  return out;
}

/** Port of computeThreats: generic scenarios, emitted when their triggering elements exist. */
export function prototypeThreats(model: ArchitectureModel): Array<{ id: string; stride: string; title: string; asset: string; description: string; recommendation: string; severity: Sev }> {
  const comps = model.components.filter((c) => c.status === 'confirmed');
  const ids = new Set(comps.map((c) => c.id));
  const flows = model.flows.filter((f) => f.status === 'confirmed' && ids.has(f.from) && ids.has(f.to));
  const byId = new Map(comps.map((c) => [c.id, c]));
  const internet = comps.filter((c) => facts(c).internet === 'yes');
  const sensitive = comps.filter((c) => SENSITIVE.includes(facts(c).data));
  const crossing = flows.some((f) => facts(byId.get(f.from)!).zone !== facts(byId.get(f.to)!).zone);
  const out: ReturnType<typeof prototypeThreats> = [];
  const push = (id: string, stride: string, title: string, asset: string, description: string, recommendation: string, severity: Sev) =>
    out.push({ id, stride, title, asset, description, recommendation, severity });

  if (internet.length) push('T-S01', 'Spoofing', 'Credential theft or session impersonation', internet.map((c) => c.name).slice(0, 2).join(', '), 'An attacker could attempt account takeover or stolen-token use at internet-facing entry points.', 'Validate MFA, token lifetimes, secure session handling, and identity monitoring.', 'High');
  if (flows.length) push('T-T01', 'Tampering', 'Manipulation of application requests or integration payloads', 'Data flows', 'An attacker or compromised intermediary could alter request parameters, messages, or business transactions.', 'Validate message integrity, input validation, signing where appropriate and transaction integrity monitoring.', 'High');
  if (comps.length) push('T-R01', 'Repudiation', 'Insufficient evidence to attribute privileged or sensitive actions', 'Confirmed components', 'Weak, incomplete, or unprotected audit trails may obstruct incident reconstruction and accountability.', 'Verify security log coverage, time synchronization, retention and tamper protections.', 'Medium');
  if (sensitive.length) push('T-I01', 'Information disclosure', 'Exposure of confidential or restricted information', sensitive.map((c) => c.name).slice(0, 2).join(', '), 'Sensitive data may be disclosed through inadequate access controls, encryption, or third-party connections.', 'Validate classification, encryption, secrets management, least privilege and outbound data controls.', 'High');
  if (comps.length) push('T-D01', 'Denial of service', 'Unavailability of a critical dependency', 'Confirmed components', 'Resource exhaustion, provider failure or ransomware may interrupt a business service or its upstream dependency.', 'Validate rate limits, resiliency architecture, backup and recovery tests and provider concentration.', 'High');
  if (comps.length) push('T-E01', 'Elevation of privilege', 'Privilege escalation through misconfigured identities', 'Confirmed components', 'Excessively privileged service accounts, admin paths or unpatched services could enable unauthorized access.', 'Validate least-privilege RBAC, PAM, secure build baselines, segmentation and patching.', 'High');
  if (crossing) push('T-S02', 'Spoofing', 'Third-party API or service impersonation', 'Cross-boundary integrations', 'A compromised third-party credential or endpoint could impersonate a trusted integration.', 'Verify certificate-based identity, scoped credentials, key rotation and vendor security monitoring.', 'High');
  return out;
}

/** Draft threats for the PROTOTYPE method. modelVersion is set by the caller. */
export function prototypeDrafts(model: ArchitectureModel): ThreatDraft[] {
  const drafts: ThreatDraft[] = [];
  const base = (id: string, sev: Sev, title: string, target: string, details: string, rec: string, reference: string, basis: FactRef[], classification?: ThreatClass): ThreatDraft => {
    const r = SEVERITY_RATING[sev];
    const cls = classification ?? r.classification;
    return {
      key: `PROTO:${id}:${target}`.slice(0, 300),
      methodology: 'PROTOTYPE',
      category: CATEGORY[id] ?? 'General',
      title,
      classification: cls,
      affectedAssets: [target],
      attackScenario: details,
      preconditions: [],
      existingControls: [],
      missingInformation: cls === 'missing_evidence' ? [details] : [],
      likelihood: r.likelihood,
      impact: r.impact,
      mitigation: rec,
      rationale: `Prototype rule ${id}.${reference ? ` Reference (unverified, not an approved control mapping): ${reference}.` : ''}`,
      basis,
      tags: [id],
      modelVersion: 0,
    };
  };
  for (const f of prototypeFindings(model)) {
    drafts.push(base(f.id, f.sev, f.title, f.target, f.details, f.recommendation, f.reference, f.basis));
  }
  for (const t of prototypeThreats(model)) {
    drafts.push(base(t.id, t.severity, t.title, t.asset, t.description, t.recommendation, '', [], 'hypothesis'));
  }
  return drafts;
}
