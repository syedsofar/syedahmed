// Register of security frameworks and reference architectures the workbench is asked to
// support. Entries record what is known about each source. They contain NO control text.
// Control text is only usable after a versioned, approved catalog import (see controls.ts).
//
// "version" and "source" must be verified against the publisher before any import.
// Licence status reflects whether the text can be loaded without a licence the firm must supply.

export type FrameworkRole =
  | 'control_catalog'     // enumerable controls that can be mapped to threats
  | 'methodology'         // architecture method or matrix
  | 'reference_model'     // architecture pattern or reference design
  | 'technique_matrix'    // adversary technique knowledge base
  | 'checklist';          // review checklist or best-practice questions

export type LicenceStatus = 'public' | 'licence_required' | 'vendor_terms' | 'to_confirm';

export interface FrameworkEntry {
  id: string;
  name: string;
  publisher: string;
  role: FrameworkRole;
  version: string;
  source: string;
  licence: LicenceStatus;
  /** Scope or size as stated in the requirement. Not yet verified against the source. */
  stated_scope?: string;
  notes: string;
}

export const FRAMEWORKS: FrameworkEntry[] = [
  { id: 'sabsa', name: 'SABSA (matrix, attribute classes, control strategy)', publisher: 'SABSA Institute', role: 'methodology', version: 'to confirm', source: 'https://sabsa.org', licence: 'licence_required', notes: 'Matrix and attribute classes are the SABSA Institute\'s copyright. Import licensed material only.' },
  { id: 'aws-wa-security', name: 'AWS Well-Architected Framework: Security pillar', publisher: 'Amazon Web Services', role: 'checklist', version: 'current at import', source: 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/', licence: 'vendor_terms', stated_scope: '11 questions, 63 best practices', notes: 'Check the question and best-practice counts against the current edition on import.' },
  { id: 'togaf-security', name: 'TOGAF security domain (artefacts by ADM phase)', publisher: 'The Open Group', role: 'methodology', version: 'to confirm', source: 'https://www.opengroup.org/togaf', licence: 'licence_required', notes: 'TOGAF is The Open Group\'s copyright. Import licensed material only.' },
  { id: 'iso27001-2022-annex-a', name: 'ISO/IEC 27001:2022 Annex A', publisher: 'ISO/IEC', role: 'control_catalog', version: '2022', source: 'https://www.iso.org/standard/27001', licence: 'licence_required', notes: 'Annex A control text is paid ISO content. Import the firm\'s licensed copy only.' },
  { id: 'nist-csf-2', name: 'NIST Cybersecurity Framework 2.0', publisher: 'NIST', role: 'control_catalog', version: '2.0', source: 'https://www.nist.gov/cyberframework', licence: 'public', notes: 'US government publication.' },
  { id: 'owasp-api-2023', name: 'OWASP API Security Top 10', publisher: 'OWASP', role: 'control_catalog', version: '2023', source: 'https://owasp.org/API-Security/', licence: 'public', stated_scope: '10 risks', notes: 'Community publication. Check the licence terms on the OWASP site before import.' },
  { id: 'cis-v81', name: 'CIS Critical Security Controls', publisher: 'Center for Internet Security', role: 'control_catalog', version: 'v8.1', source: 'https://www.cisecurity.org/controls', licence: 'vendor_terms', notes: 'CIS terms apply to reproduction. Check them before import.' },
  { id: 'owasp-sbd-checklist', name: 'OWASP Secure by Design Framework: review checklist', publisher: 'OWASP', role: 'checklist', version: 'to confirm', source: 'https://owasp.org/', licence: 'to_confirm', notes: 'Confirm the current document and its licence before import.' },
  { id: 'csa-ccm-v4', name: 'CSA Cloud Controls Matrix v4', publisher: 'Cloud Security Alliance', role: 'control_catalog', version: 'v4', source: 'https://cloudsecurityalliance.org/research/cloud-controls-matrix', licence: 'vendor_terms', stated_scope: '17 domains, 197 controls', notes: 'Check the control and domain counts on import.' },
  { id: 'osa-patterns', name: 'Open Security Architecture patterns (SP-xxx)', publisher: 'Open Security Architecture', role: 'reference_model', version: 'current at import', source: 'https://www.opensecurityarchitecture.org', licence: 'to_confirm', notes: 'Confirm the pattern licence before import.' },
  { id: 'nist-sp-800-207', name: 'NIST SP 800-207: Zero Trust Architecture', publisher: 'NIST', role: 'reference_model', version: '2020', source: 'https://csrc.nist.gov/pubs/sp/800/207/final', licence: 'public', notes: 'Used as the architecture foundation for zero-trust checks.' },
  { id: 'nca-ecc-2024', name: 'NCA Essential Cybersecurity Controls (ECC) 2024', publisher: 'National Cybersecurity Authority (Saudi Arabia)', role: 'control_catalog', version: '2024', source: 'https://nca.gov.sa', licence: 'public', notes: 'Use the official publication. Confirm the version before import.' },
  { id: 'sama-csf', name: 'SAMA Cybersecurity Framework', publisher: 'Saudi Central Bank (SAMA)', role: 'control_catalog', version: 'to confirm', source: 'https://www.sama.gov.sa', licence: 'public', notes: 'Use the official publication. Confirm the version before import.' },
  { id: 'cisa-ztmm', name: 'CISA Zero Trust Maturity Model', publisher: 'CISA', role: 'reference_model', version: 'v2.0', source: 'https://www.cisa.gov/zero-trust-maturity-model', licence: 'public', notes: 'US government publication.' },
  { id: 'ms-zero-trust', name: 'Microsoft Zero Trust guidance', publisher: 'Microsoft', role: 'reference_model', version: 'current at import', source: 'https://learn.microsoft.com/security/zero-trust/', licence: 'vendor_terms', notes: 'Check the Microsoft documentation terms before import.' },
  { id: 'ms-cra', name: 'Microsoft Cybersecurity Reference Architectures', publisher: 'Microsoft', role: 'reference_model', version: 'current at import', source: 'https://learn.microsoft.com/security/cybersecurity-reference-architecture', licence: 'vendor_terms', notes: 'Check the Microsoft documentation terms before import.' },
  { id: 'gcp-caf-security', name: 'Google Cloud Architecture Framework: Security', publisher: 'Google Cloud', role: 'reference_model', version: 'current at import', source: 'https://cloud.google.com/architecture/framework', licence: 'vendor_terms', notes: 'Check the Google Cloud documentation terms before import.' },
  { id: 'mitre-attack', name: 'MITRE ATT&CK', publisher: 'MITRE', role: 'technique_matrix', version: 'to set on import', source: 'https://attack.mitre.org', licence: 'public', notes: 'Free to use under MITRE\'s terms. Record the ATT&CK version used in each assessment.' },
];

export const LICENCE_LABELS: Record<LicenceStatus, string> = {
  public: 'Public',
  licence_required: 'Licence required',
  vendor_terms: 'Vendor terms',
  to_confirm: 'To confirm',
};

export const ROLE_LABELS: Record<FrameworkRole, string> = {
  control_catalog: 'Control catalog',
  methodology: 'Methodology',
  reference_model: 'Reference model',
  technique_matrix: 'Technique matrix',
  checklist: 'Checklist',
};
