import type { CatalogControl, ControlCatalog, ControlReview, Framework, Threat } from './types';

export const FRAMEWORK_LABELS: Record<Framework, string> = {
  NCA_ECC: 'NCA Essential Cybersecurity Controls',
  SAMA_CSF: 'SAMA Cyber Security Framework',
  NIST_CSF: 'NIST Cybersecurity Framework',
  ISO_27001: 'ISO/IEC 27001 Annex A',
};

/** Tags threats and controls share. Catalog importers must use these values. */
export const CONTROL_TAGS = [
  'asset-management', 'authentication', 'identity', 'access-control', 'privileged-access',
  'encryption-transit', 'encryption-rest', 'cryptography', 'data-protection', 'logging', 'monitoring',
  'network-segmentation', 'network-security', 'availability', 'resilience', 'backup',
  'vulnerability-management', 'hardening', 'configuration-management', 'secure-development',
  'input-validation', 'third-party', 'cloud', 'endpoint-security',
] as const;

export interface ControlMapping {
  control: CatalogControl;
  confirmed: Threat[];
  hypotheses: Threat[];
  missing: Threat[];
}

/**
 * Map threats to controls by shared topic tags. Rejected threats are excluded. The mapping says
 * which findings are RELEVANT to a control. It never concludes that a control is satisfied:
 * that needs reviewed evidence (see canSetStatus).
 */
export function mapThreatsToControls(catalog: ControlCatalog, threats: Threat[]): ControlMapping[] {
  const live = threats.filter((t) => t.decision !== 'rejected');
  return catalog.controls.map((control) => {
    const rel = live.filter((t) => t.tags.some((tag) => control.tags.includes(tag)));
    return {
      control,
      confirmed: rel.filter((t) => t.classification === 'confirmed'),
      hypotheses: rel.filter((t) => t.classification === 'hypothesis'),
      missing: rel.filter((t) => t.classification === 'missing_evidence'),
    };
  });
}

/** Suggested status derived from mapped findings. Never suggests "satisfied". */
export function suggestedStatus(m: ControlMapping): ControlReview['status'] {
  if (m.confirmed.length) return 'gap_identified';
  if (m.missing.length) return 'information_missing';
  return 'not_assessed';
}

export function canSetStatus(status: ControlReview['status'], evidenceRefs: string[], notes: string): string | null {
  if (status === 'evidence_satisfied' && evidenceRefs.length === 0) {
    return 'A control can only be marked "Evidence reviewed — satisfied" when at least one evidence reference is attached. Compliance is never inferred from the architecture diagram alone.';
  }
  if (status === 'not_applicable' && !notes.trim()) {
    return 'A justification note is required to mark a control not applicable.';
  }
  return null;
}

export const REVIEW_STATUS_LABELS: Record<ControlReview['status'], string> = {
  not_assessed: 'Not assessed',
  information_missing: 'Information missing',
  gap_identified: 'Gap identified',
  evidence_satisfied: 'Evidence reviewed — satisfied',
  not_applicable: 'Not applicable',
};

// ------------------------------------------------------------------ catalog validation

export interface CatalogImport {
  framework: Framework;
  name: string;
  version: string;
  source: string;
  controls: CatalogControl[];
}

export function validateCatalogImport(input: unknown): { ok: true; value: CatalogImport } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  const o = input as Record<string, unknown>;
  if (!o || typeof o !== 'object') return { ok: false, errors: ['Catalog must be a JSON object.'] };
  if (!['NCA_ECC', 'SAMA_CSF', 'NIST_CSF', 'ISO_27001'].includes(o.framework as string)) errors.push('framework must be one of NCA_ECC, SAMA_CSF, NIST_CSF, ISO_27001.');
  for (const k of ['name', 'version', 'source']) if (typeof o[k] !== 'string' || !(o[k] as string).trim()) errors.push(`${k} is required.`);
  if (!Array.isArray(o.controls) || o.controls.length === 0) errors.push('controls must be a non-empty array.');
  const seen = new Set<string>();
  (Array.isArray(o.controls) ? o.controls : []).forEach((c: Record<string, unknown>, i: number) => {
    if (typeof c?.id !== 'string' || !c.id.trim()) errors.push(`controls[${i}].id is required.`);
    else if (seen.has(c.id)) errors.push(`controls[${i}].id "${c.id}" is duplicated.`);
    else seen.add(c.id);
    if (typeof c?.title !== 'string' || !c.title.trim()) errors.push(`controls[${i}].title is required.`);
    if (typeof c?.domain !== 'string') errors.push(`controls[${i}].domain is required.`);
    if (!Array.isArray(c?.tags)) errors.push(`controls[${i}].tags must be an array.`);
    else for (const t of c.tags as string[]) if (!(CONTROL_TAGS as readonly string[]).includes(t)) errors.push(`controls[${i}] has unknown tag "${t}".`);
  });
  if (errors.length) return { ok: false, errors: errors.slice(0, 25) };
  return { ok: true, value: o as unknown as CatalogImport };
}

// ------------------------------------------------------------------ demonstration catalogs

const DEMO_SOURCE =
  'DEMONSTRATION EXCERPT — domain/sub-domain level references with paraphrased titles, provided only to demonstrate the workflow. Not authoritative. Import and approve the official catalog content before any client use.';

type Row = [string, string, string, string[]];
const rows = (r: Row[]): CatalogControl[] => r.map(([id, domain, title, tags]) => ({ id, domain, title, tags }));

export const DEMO_CATALOGS: CatalogImport[] = [
  {
    framework: 'NIST_CSF', name: 'NIST CSF', version: '2.0 (demo excerpt)', source: DEMO_SOURCE,
    controls: rows([
      ['ID.AM-03', 'Identify', 'Network communication and data flows are represented and maintained', ['asset-management']],
      ['ID.RA-01', 'Identify', 'Vulnerabilities in assets are identified and recorded', ['vulnerability-management']],
      ['PR.AA-03', 'Protect', 'Users, services and hardware are authenticated', ['authentication', 'identity']],
      ['PR.AA-05', 'Protect', 'Access permissions follow least privilege and separation of duties', ['access-control', 'privileged-access']],
      ['PR.DS-01', 'Protect', 'Confidentiality and integrity of data-at-rest are protected', ['encryption-rest', 'data-protection']],
      ['PR.DS-02', 'Protect', 'Confidentiality and integrity of data-in-transit are protected', ['encryption-transit', 'cryptography']],
      ['PR.DS-11', 'Protect', 'Backups of data are created, protected, maintained and tested', ['backup']],
      ['PR.PS-01', 'Protect', 'Configuration management practices are applied', ['configuration-management', 'hardening']],
      ['PR.PS-04', 'Protect', 'Log records are generated and made available for monitoring', ['logging']],
      ['PR.PS-06', 'Protect', 'Secure software development practices are integrated', ['secure-development', 'input-validation']],
      ['PR.IR-01', 'Protect', 'Networks and environments are protected from unauthorised logical access', ['network-segmentation', 'network-security']],
      ['PR.IR-03', 'Protect', 'Mechanisms are implemented to achieve resilience requirements', ['resilience', 'availability']],
      ['DE.CM-01', 'Detect', 'Networks and network services are monitored', ['monitoring', 'network-security']],
      ['GV.SC-07', 'Govern', 'Supplier risks are identified, assessed and responded to', ['third-party']],
    ]),
  },
  {
    framework: 'ISO_27001', name: 'ISO/IEC 27001 Annex A', version: '2022 (demo excerpt)', source: DEMO_SOURCE,
    controls: rows([
      ['5.9', 'Organizational', 'Inventory of information and other associated assets', ['asset-management']],
      ['5.15', 'Organizational', 'Access control', ['access-control']],
      ['5.17', 'Organizational', 'Authentication information', ['authentication', 'identity']],
      ['5.19', 'Organizational', 'Information security in supplier relationships', ['third-party']],
      ['5.23', 'Organizational', 'Information security for use of cloud services', ['cloud']],
      ['8.1', 'Technological', 'User endpoint devices', ['endpoint-security']],
      ['8.2', 'Technological', 'Privileged access rights', ['privileged-access']],
      ['8.5', 'Technological', 'Secure authentication', ['authentication']],
      ['8.8', 'Technological', 'Management of technical vulnerabilities', ['vulnerability-management', 'hardening']],
      ['8.9', 'Technological', 'Configuration management', ['configuration-management']],
      ['8.13', 'Technological', 'Information backup', ['backup']],
      ['8.15', 'Technological', 'Logging', ['logging']],
      ['8.16', 'Technological', 'Monitoring activities', ['monitoring']],
      ['8.20', 'Technological', 'Networks security', ['network-security']],
      ['8.22', 'Technological', 'Segregation of networks', ['network-segmentation']],
      ['8.24', 'Technological', 'Use of cryptography', ['cryptography', 'encryption-transit', 'encryption-rest']],
      ['8.26', 'Technological', 'Application security requirements', ['secure-development', 'input-validation']],
      ['8.14', 'Technological', 'Redundancy of information processing facilities', ['availability', 'resilience']],
    ]),
  },
  {
    framework: 'NCA_ECC', name: 'NCA ECC', version: 'ECC-1:2018 (demo excerpt)', source: DEMO_SOURCE,
    controls: rows([
      ['2-1', 'Cybersecurity Defense', 'Asset management', ['asset-management']],
      ['2-2', 'Cybersecurity Defense', 'Identity and access management', ['authentication', 'identity', 'access-control', 'privileged-access']],
      ['2-3', 'Cybersecurity Defense', 'Information system and processing facilities protection', ['hardening', 'endpoint-security', 'configuration-management']],
      ['2-5', 'Cybersecurity Defense', 'Networks security management', ['network-segmentation', 'network-security']],
      ['2-7', 'Cybersecurity Defense', 'Data and information protection', ['data-protection']],
      ['2-8', 'Cybersecurity Defense', 'Cryptography', ['cryptography', 'encryption-transit', 'encryption-rest']],
      ['2-9', 'Cybersecurity Defense', 'Backup and recovery management', ['backup']],
      ['2-10', 'Cybersecurity Defense', 'Vulnerabilities management', ['vulnerability-management']],
      ['2-12', 'Cybersecurity Defense', 'Cybersecurity event logs and monitoring management', ['logging', 'monitoring']],
      ['2-15', 'Cybersecurity Defense', 'Web application security', ['secure-development', 'input-validation']],
      ['3-1', 'Cybersecurity Resilience', 'Cybersecurity resilience aspects of business continuity', ['resilience', 'availability']],
      ['4-1', 'Third-Party and Cloud Computing Cybersecurity', 'Third-party cybersecurity', ['third-party']],
      ['4-2', 'Third-Party and Cloud Computing Cybersecurity', 'Cloud computing and hosting cybersecurity', ['cloud']],
    ]),
  },
  {
    framework: 'SAMA_CSF', name: 'SAMA CSF', version: '1.0 (demo excerpt)', source: DEMO_SOURCE,
    controls: rows([
      ['3.3.3', 'Cyber Security Operations and Technology', 'Asset management', ['asset-management']],
      ['3.3.4', 'Cyber Security Operations and Technology', 'Cyber security architecture', ['network-segmentation']],
      ['3.3.5', 'Cyber Security Operations and Technology', 'Identity and access management', ['authentication', 'identity', 'access-control', 'privileged-access']],
      ['3.3.6', 'Cyber Security Operations and Technology', 'Application security', ['secure-development', 'input-validation']],
      ['3.3.8', 'Cyber Security Operations and Technology', 'Infrastructure security', ['network-security', 'hardening', 'availability']],
      ['3.3.9', 'Cyber Security Operations and Technology', 'Cryptography', ['cryptography', 'encryption-transit', 'encryption-rest']],
      ['3.3.14', 'Cyber Security Operations and Technology', 'Cyber security event management', ['logging', 'monitoring']],
      ['3.3.17', 'Cyber Security Operations and Technology', 'Vulnerability management', ['vulnerability-management']],
      ['3.4.1', 'Third Party Cyber Security', 'Contract and vendor management', ['third-party']],
      ['3.4.3', 'Third Party Cyber Security', 'Cloud computing', ['cloud']],
    ]),
  },
];
