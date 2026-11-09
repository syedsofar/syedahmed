import type {
  ArchitectureModel,
  ComponentType,
  DataClassification,
  RiskMatrixConfig,
  ZoneType,
} from './types';
import { MODEL_SCHEMA } from './types';

export type PropKind = 'tri' | 'text' | 'select';

export interface PropDef {
  key: string;
  label: string;
  kind: PropKind;
  options?: string[];
  help?: string;
}

/** STRIDE element categories (Microsoft SDL STRIDE-per-element). */
export type ElementCategory = 'external_entity' | 'process' | 'data_store';

export interface ComponentDef {
  type: ComponentType;
  label: string;
  short: string;
  category: ElementCategory;
  color: string;
  props: PropDef[];
}

const CLASS_OPTIONS: DataClassification[] = ['unknown', 'public', 'internal', 'confidential', 'restricted'];

const common: PropDef[] = [
  { key: 'owner', label: 'Asset owner', kind: 'text' },
  { key: 'hosting', label: 'Hosting', kind: 'select', options: ['unknown', 'on_premises', 'iaas', 'paas', 'saas'] },
  { key: 'dataClassification', label: 'Highest data classification', kind: 'select', options: CLASS_OPTIONS },
  { key: 'criticality', label: 'Business criticality', kind: 'select', options: ['unknown', 'low', 'medium', 'high', 'critical'] },
  { key: 'internetFacing', label: 'Internet facing', kind: 'tri' },
  { key: 'logging', label: 'Security logging to SIEM', kind: 'tri' },
  { key: 'patching', label: 'Patch / vulnerability management', kind: 'tri' },
];

const authProps: PropDef[] = [
  { key: 'authentication', label: 'Authentication enforced', kind: 'tri' },
  { key: 'mfa', label: 'MFA for privileged / remote access', kind: 'tri' },
  { key: 'authorization', label: 'Role-based authorisation', kind: 'tri' },
];

const hardening: PropDef[] = [
  { key: 'hardening', label: 'Hardened baseline applied', kind: 'tri' },
  { key: 'inputValidation', label: 'Input validation / output encoding', kind: 'tri' },
];

export const COMPONENTS: Record<ComponentType, ComponentDef> = {
  user: {
    type: 'user', label: 'User / Actor', short: 'USR', category: 'external_entity', color: '#3d6b8f',
    props: [
      { key: 'population', label: 'User population', kind: 'select', options: ['unknown', 'public', 'customers', 'employees', 'administrators', 'partners'] },
      { key: 'mfa', label: 'MFA enrolled', kind: 'tri' },
      { key: 'notes', label: 'Notes', kind: 'text' },
    ],
  },
  endpoint: {
    type: 'endpoint', label: 'Endpoint / Device', short: 'END', category: 'process', color: '#4f7a8c',
    props: [...common, { key: 'edr', label: 'EDR / anti-malware', kind: 'tri' }, { key: 'diskEncryption', label: 'Disk encryption', kind: 'tri' }, { key: 'managed', label: 'Corporate managed (MDM)', kind: 'tri' }],
  },
  firewall: {
    type: 'firewall', label: 'Firewall', short: 'FW', category: 'process', color: '#b5543c',
    props: [...common, { key: 'defaultDeny', label: 'Default-deny rule base', kind: 'tri' }, { key: 'ruleReview', label: 'Periodic rule review', kind: 'tri' }, { key: 'mgmtIsolated', label: 'Management plane isolated', kind: 'tri' }],
  },
  load_balancer: {
    type: 'load_balancer', label: 'Load Balancer', short: 'LB', category: 'process', color: '#5b7c6a',
    props: [...common, { key: 'tlsTermination', label: 'TLS terminated here', kind: 'tri' }, { key: 'waf', label: 'WAF enabled', kind: 'tri' }, { key: 'ddosProtection', label: 'DDoS protection', kind: 'tri' }],
  },
  api_gateway: {
    type: 'api_gateway', label: 'API Gateway', short: 'API', category: 'process', color: '#0f8b8d',
    props: [...common, ...authProps, { key: 'rateLimiting', label: 'Rate limiting / throttling', kind: 'tri' }, { key: 'schemaValidation', label: 'Request schema validation', kind: 'tri' }, { key: 'waf', label: 'WAF enabled', kind: 'tri' }],
  },
  web_server: {
    type: 'web_server', label: 'Web Server', short: 'WEB', category: 'process', color: '#2f6f9f',
    props: [...common, ...authProps, ...hardening, { key: 'waf', label: 'Protected by WAF', kind: 'tri' }, { key: 'securityHeaders', label: 'Security headers (CSP, HSTS)', kind: 'tri' }, { key: 'rateLimiting', label: 'Rate limiting', kind: 'tri' }],
  },
  app_server: {
    type: 'app_server', label: 'Application Server', short: 'APP', category: 'process', color: '#33557a',
    props: [...common, ...authProps, ...hardening, { key: 'secretsManagement', label: 'Secrets in vault (not config files)', kind: 'tri' }, { key: 'rateLimiting', label: 'Rate limiting', kind: 'tri' }],
  },
  database: {
    type: 'database', label: 'Database / Data Store', short: 'DB', category: 'data_store', color: '#7a5c99',
    props: [...common, ...authProps, { key: 'encryptionAtRest', label: 'Encryption at rest', kind: 'tri' }, { key: 'backups', label: 'Tested backups', kind: 'tri' }, { key: 'activityMonitoring', label: 'Database activity monitoring', kind: 'tri' }, { key: 'leastPrivilegeAccounts', label: 'Least-privilege service accounts', kind: 'tri' }],
  },
  iam: {
    type: 'iam', label: 'Identity / IAM', short: 'IAM', category: 'process', color: '#a07a2c',
    props: [...common, ...authProps, { key: 'pam', label: 'Privileged access management', kind: 'tri' }, { key: 'accessReviews', label: 'Periodic access reviews', kind: 'tri' }, { key: 'federation', label: 'Federation protocol', kind: 'select', options: ['unknown', 'none', 'saml', 'oidc', 'ldap', 'kerberos'] }],
  },
  cloud_service: {
    type: 'cloud_service', label: 'Cloud Service', short: 'CLD', category: 'process', color: '#3f8f7a',
    props: [...common, ...authProps, { key: 'encryptionAtRest', label: 'Encryption at rest', kind: 'tri' }, { key: 'cspmMonitoring', label: 'Cloud posture monitoring', kind: 'tri' }, { key: 'dataResidency', label: 'Data residency confirmed', kind: 'tri' }],
  },
  third_party: {
    type: 'third_party', label: 'Third Party', short: '3P', category: 'external_entity', color: '#8c6d5a',
    props: [
      { key: 'owner', label: 'Relationship owner', kind: 'text' },
      { key: 'dataClassification', label: 'Data shared (classification)', kind: 'select', options: CLASS_OPTIONS },
      { key: 'contractSecurityClauses', label: 'Contractual security clauses', kind: 'tri' },
      { key: 'vendorAssessment', label: 'Third-party risk assessment done', kind: 'tri' },
      { key: 'authentication', label: 'Authenticates to our services', kind: 'tri' },
    ],
  },
};

export const COMPONENT_TYPES = Object.keys(COMPONENTS) as ComponentType[];

export const ZONES: Record<ZoneType, { label: string; trust: number; color: string }> = {
  internet: { label: 'Internet (untrusted)', trust: 0, color: '#c0504d' },
  third_party: { label: 'Third-party network', trust: 1, color: '#b07a3c' },
  user_zone: { label: 'User / corporate LAN', trust: 2, color: '#6b8fb3' },
  dmz: { label: 'DMZ', trust: 1, color: '#d08c3a' },
  cloud: { label: 'Cloud tenancy', trust: 2, color: '#3f8f7a' },
  internal: { label: 'Internal application zone', trust: 3, color: '#0f8b8d' },
  restricted: { label: 'Restricted data zone', trust: 4, color: '#16325c' },
  management: { label: 'Management zone', trust: 4, color: '#5a4f8c' },
};

export const INSECURE_PROTOCOLS = ['http', 'ftp', 'telnet', 'ldap', 'snmpv1', 'snmpv2', 'smbv1', 'tftp', 'rsh', 'pop3', 'imap', 'smtp'];
export const SECURE_PROTOCOLS = ['https', 'tls', 'mtls', 'sftp', 'ssh', 'ldaps', 'snmpv3', 'ipsec', 'jdbc+tls', 'grpc+tls', 'amqps', 'smtps'];

export function protocolSecurity(protocol: string): 'secure' | 'insecure' | 'unknown' {
  const p = protocol.trim().toLowerCase();
  if (!p) return 'unknown';
  if (SECURE_PROTOCOLS.includes(p)) return 'secure';
  if (INSECURE_PROTOCOLS.includes(p)) return 'insecure';
  return 'unknown';
}

export const CLASSIFICATION_RANK: Record<DataClassification, number> = {
  unknown: 0, public: 1, internal: 2, confidential: 4, restricted: 5,
};

export function emptyModel(): ArchitectureModel {
  return { schema: MODEL_SCHEMA, components: [], flows: [], zones: [], notes: '' };
}

export function defaultRiskMatrix(): RiskMatrixConfig {
  return {
    likelihoodLabels: ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost certain'],
    impactLabels: ['Insignificant', 'Minor', 'Moderate', 'Major', 'Severe'],
    bands: [
      { name: 'Low', min: 1, color: '#8fb3a0' },
      { name: 'Medium', min: 5, color: '#e3c565' },
      { name: 'High', min: 10, color: '#e08a4f' },
      { name: 'Critical', min: 17, color: '#c0504d' },
    ],
  };
}

export function riskBand(cfg: RiskMatrixConfig, likelihood: number, impact: number) {
  const score = likelihood * impact;
  const bands = [...cfg.bands].sort((a, b) => a.min - b.min);
  let band = bands[0];
  for (const b of bands) if (score >= b.min) band = b;
  return { score, ...band };
}

/** Stable JSON serialisation (sorted keys) used for hashing canonical models. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return '{' + Object.keys(obj).sort().filter((k) => obj[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export const STATUS_LABELS: Record<string, string> = {
  draft: 'Draft', in_review: 'In review', pending_approval: 'Pending approval', final: 'Final', archived: 'Archived',
};

export const ROLE_LABELS: Record<string, string> = {
  admin: 'Administrator', lead_reviewer: 'Lead reviewer', analyst: 'Security analyst', viewer: 'Viewer',
};
