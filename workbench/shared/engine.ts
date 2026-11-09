// Deterministic, rule-based threat analysis engine.
//
// Principles:
//  * Only CONFIRMED components, flows and zones are analysed. Unconfirmed (imported but not
//    yet reviewed) elements are skipped and counted so the analyst can see what was excluded.
//  * The engine never creates or assumes architecture facts. Every output cites the facts it
//    used (FactRef). Where a fact needed to evaluate a threat is unknown, the output is
//    classified as MISSING EVIDENCE rather than guessed.
//  * Classification:
//      confirmed        - an explicit confirmed fact shows the control is absent / weak.
//      hypothesis       - the threat is structurally applicable; recorded controls reportedly
//                         exist but are unverified, so residual threat remains a hypothesis.
//      missing_evidence - a fact needed to evaluate the threat is unknown.

import type {
  ArchComponent,
  ArchitectureModel,
  ComponentType,
  DataFlow,
  FactRef,
  Methodology,
  Threat,
  ThreatClass,
  TrustZone,
} from './types';
import { CLASSIFICATION_RANK, COMPONENTS, protocolSecurity } from './schema';

export const ENGINE_NAME = 'Deterministic rule engine';
export const ENGINE_VERSION = '1.0.0';
export const NODE_W = 140;
export const NODE_H = 58;

export type ThreatDraft = Omit<
  Threat,
  'id' | 'decision' | 'analystNotes' | 'evidenceRefs' | 'runId' | 'createdAt' | 'updatedAt' | 'updatedBy'
>;

export interface AnalysisResult {
  drafts: ThreatDraft[];
  skippedUnconfirmed: number;
  structuralGaps: ThreatDraft[];
}

// ------------------------------------------------------------------ model helpers

export class ModelView {
  readonly comps: ArchComponent[];
  readonly flows: DataFlow[];
  readonly zones: TrustZone[];
  readonly byId = new Map<string, ArchComponent>();
  readonly skipped: number;

  constructor(model: ArchitectureModel) {
    this.zones = model.zones.filter((z) => z.status === 'confirmed');
    this.comps = model.components.filter((c) => c.status === 'confirmed');
    this.comps.forEach((c) => this.byId.set(c.id, c));
    this.flows = model.flows.filter((f) => f.status === 'confirmed' && this.byId.has(f.from) && this.byId.has(f.to));
    this.skipped =
      model.components.length - this.comps.length +
      (model.flows.length - this.flows.length) +
      (model.zones.length - this.zones.length);
  }

  /** Smallest confirmed zone containing the component's centre point. */
  zoneOf(c: ArchComponent): TrustZone | undefined {
    const cx = c.x + NODE_W / 2;
    const cy = c.y + NODE_H / 2;
    let best: TrustZone | undefined;
    for (const z of this.zones) {
      if (cx >= z.x && cx <= z.x + z.w && cy >= z.y && cy <= z.y + z.h) {
        if (!best || z.w * z.h < best.w * best.h) best = z;
      }
    }
    return best;
  }

  prop(c: ArchComponent, key: string): string {
    const v = c.properties[key];
    return v === undefined || v === '' ? 'unknown' : v;
  }

  hasProp(c: ArchComponent, key: string) {
    return COMPONENTS[c.type].props.some((p) => p.key === key);
  }

  /** Trust level of the component, or undefined when it is not placed in a zone. */
  trust(c: ArchComponent): number | undefined {
    return this.zoneOf(c)?.trustLevel;
  }

  crossesBoundary(f: DataFlow): boolean | 'unknown' {
    const a = this.zoneOf(this.byId.get(f.from)!);
    const b = this.zoneOf(this.byId.get(f.to)!);
    if (!a || !b) return 'unknown';
    return a.id !== b.id;
  }

  inbound(c: ArchComponent) {
    return this.flows.filter((f) => f.to === c.id || (f.bidirectional && f.from === c.id));
  }

  /** Lowest trust level of any component sending data to c. */
  lowestInboundTrust(c: ArchComponent): number | undefined {
    let min: number | undefined;
    for (const f of this.inbound(c)) {
      const other = this.byId.get(f.to === c.id ? f.from : f.to)!;
      const t = this.trust(other);
      if (t !== undefined) min = min === undefined ? t : Math.min(min, t);
    }
    return min;
  }

  isExposed(c: ArchComponent): boolean | 'unknown' {
    if (this.prop(c, 'internetFacing') === 'yes') return true;
    const t = this.trust(c);
    if (t !== undefined && t <= 1) return true;
    const inT = this.lowestInboundTrust(c);
    if (inT !== undefined && inT <= 1) return true;
    if (t === undefined && this.prop(c, 'internetFacing') === 'unknown') return 'unknown';
    return false;
  }

  classificationOf(c: ArchComponent): number {
    return CLASSIFICATION_RANK[(this.prop(c, 'dataClassification') as keyof typeof CLASSIFICATION_RANK)] ?? 0;
  }

  neighbours(id: string): string[] {
    const out: string[] = [];
    for (const f of this.flows) {
      if (f.from === id) out.push(f.to);
      if (f.bidirectional && f.to === id) out.push(f.from);
    }
    return out;
  }
}

const clamp = (n: number) => Math.max(1, Math.min(5, Math.round(n)));

function describe(c: ArchComponent) {
  return `${c.name} (${COMPONENTS[c.type].label})`;
}

function impactFor(v: ModelView, c: ArchComponent, missing: string[]): number {
  const cls = v.classificationOf(c);
  const crit = { critical: 5, high: 4, medium: 3, low: 2 }[v.prop(c, 'criticality')] ?? 0;
  const best = Math.max(cls, crit);
  if (best === 0) {
    missing.push(`Data classification / criticality of ${c.name} is not recorded; impact provisionally rated moderate (3).`);
    return 3;
  }
  return clamp(best);
}

function baseLikelihood(v: ModelView, c: ArchComponent): number {
  const exposed = v.isExposed(c);
  const t = v.trust(c);
  let l = t === undefined ? 3 : [4, 4, 3, 2, 2][t] ?? 3;
  if (exposed === true) l += 1;
  return l;
}

function classify(values: { label: string; value: string }[]): { cls: ThreatClass; existing: string[]; missing: string[]; weak: string[] } {
  const existing = values.filter((v) => v.value === 'yes').map((v) => `${v.label} (recorded as present, not verified)`);
  const weak = values.filter((v) => v.value === 'no').map((v) => `${v.label}: recorded as NOT in place`);
  const missing = values.filter((v) => v.value === 'unknown').map((v) => `${v.label}: not recorded`);
  const cls: ThreatClass = weak.length ? 'confirmed' : missing.length ? 'missing_evidence' : 'hypothesis';
  return { cls, existing, missing, weak };
}

// ------------------------------------------------------------------ STRIDE component rules

interface ComponentRule {
  id: string;
  category: string;
  title: string;
  types: ComponentType[];
  controls: string[];
  /** Additional applicability test; returning false skips the rule. */
  applies?: (v: ModelView, c: ArchComponent) => boolean;
  scenario: (c: ArchComponent) => string;
  preconditions: string[];
  mitigation: string;
  tags: string[];
}

const PROCESS_TYPES: ComponentType[] = ['web_server', 'app_server', 'api_gateway', 'cloud_service', 'iam'];

const exposedOrUnknown = (v: ModelView, c: ArchComponent) => v.isExposed(c) !== false;

export const COMPONENT_RULES: ComponentRule[] = [
  {
    id: 'STRIDE-S-PROC', category: 'Spoofing', title: 'Impersonation of a legitimate client or user',
    types: [...PROCESS_TYPES, 'database'], controls: ['authentication', 'mfa'],
    scenario: (c) => `An attacker presents stolen, guessed or forged credentials/tokens to ${describe(c)} and is treated as a legitimate principal.`,
    preconditions: ['Attacker can reach the service interface', 'Credentials or session tokens can be obtained or forged'],
    mitigation: 'Enforce strong authentication on every interface, require MFA for privileged and remote access, bind and expire session tokens.',
    tags: ['authentication', 'identity'],
  },
  {
    id: 'STRIDE-S-EXT', category: 'Spoofing', title: 'Account takeover of external actor',
    types: ['user'], controls: ['mfa'],
    scenario: (c) => `Credentials of ${describe(c)} are phished or stuffed, allowing an attacker to act as that actor.`,
    preconditions: ['Actor authenticates with reusable secrets', 'Attacker obtains credentials (phishing, reuse, malware)'],
    mitigation: 'Enrol the population in phishing-resistant MFA; apply credential-stuffing detection and account lockout.',
    tags: ['authentication', 'identity'],
  },
  {
    id: 'STRIDE-S-3P', category: 'Spoofing', title: 'Impersonation of third-party integration',
    types: ['third_party'], controls: ['authentication'],
    scenario: (c) => `An attacker impersonates ${describe(c)} to submit or retrieve data through the integration.`,
    preconditions: ['Integration endpoint reachable by attacker', 'Weak or shared integration credentials'],
    mitigation: 'Use mutually authenticated channels (mTLS / signed tokens) with per-partner credentials and rotation.',
    tags: ['authentication', 'third-party'],
  },
  {
    id: 'STRIDE-T-PROC', category: 'Tampering', title: 'Injection or request tampering',
    types: ['web_server', 'app_server', 'api_gateway'], controls: ['inputValidation', 'schemaValidation', 'waf'],
    applies: exposedOrUnknown,
    scenario: (c) => `Crafted input sent to ${describe(c)} alters application behaviour or downstream queries (e.g. injection, parameter tampering).`,
    preconditions: ['Component accepts input from a lower-trust zone', 'Input is not validated or encoded'],
    mitigation: 'Apply allow-list input validation, parameterised queries, output encoding and a tuned WAF in blocking mode.',
    tags: ['secure-development', 'input-validation'],
  },
  {
    id: 'STRIDE-T-DS', category: 'Tampering', title: 'Unauthorised modification of stored data',
    types: ['database', 'cloud_service'], controls: ['authorization', 'leastPrivilegeAccounts', 'activityMonitoring'],
    scenario: (c) => `A compromised or over-privileged account modifies records held in ${describe(c)}.`,
    preconditions: ['Attacker controls an account or service with write access'],
    mitigation: 'Use least-privilege service accounts, segregate write paths, and monitor data-modifying activity.',
    tags: ['access-control', 'data-protection', 'monitoring'],
  },
  {
    id: 'STRIDE-T-FW', category: 'Tampering', title: 'Segmentation bypass through permissive rules',
    types: ['firewall'], controls: ['defaultDeny', 'ruleReview', 'mgmtIsolated'],
    scenario: (c) => `Overly permissive or stale rules on ${describe(c)}, or access to its management plane, allow traffic between zones that should be isolated.`,
    preconditions: ['Rule base contains broad or obsolete permits, or management interface is reachable'],
    mitigation: 'Enforce default-deny, review rules periodically, and isolate firewall management to a dedicated management zone.',
    tags: ['network-segmentation', 'network-security'],
  },
  {
    id: 'STRIDE-R', category: 'Repudiation', title: 'Actions cannot be attributed or reconstructed',
    types: [...PROCESS_TYPES, 'database', 'firewall', 'load_balancer'], controls: ['logging'],
    scenario: (c) => `Security-relevant actions on ${describe(c)} are not logged centrally, so malicious activity cannot be detected, attributed or investigated.`,
    preconditions: ['Insufficient or local-only logging', 'No log integrity protection'],
    mitigation: 'Forward authentication, administrative and data-access events to the SIEM with integrity protection and defined retention.',
    tags: ['logging', 'monitoring'],
  },
  {
    id: 'STRIDE-I-DS', category: 'Information disclosure', title: 'Disclosure of stored data',
    types: ['database', 'cloud_service'], controls: ['encryptionAtRest', 'authorization'],
    scenario: (c) => `Data held in ${describe(c)} is exposed through excessive access rights, stolen media/snapshots or backups.`,
    preconditions: ['Attacker obtains storage, snapshot or query access'],
    mitigation: 'Encrypt data at rest with managed keys, restrict query access by role, and protect backups and snapshots.',
    tags: ['encryption-rest', 'data-protection', 'access-control'],
  },
  {
    id: 'STRIDE-I-END', category: 'Information disclosure', title: 'Data loss from lost or compromised endpoint',
    types: ['endpoint'], controls: ['diskEncryption', 'managed'],
    scenario: (c) => `Data cached on ${describe(c)} is disclosed when the device is lost, stolen or compromised.`,
    preconditions: ['Sensitive data stored locally', 'Device leaves controlled premises'],
    mitigation: 'Enforce full-disk encryption and MDM enrolment with remote wipe.',
    tags: ['endpoint-security', 'encryption-rest'],
  },
  {
    id: 'STRIDE-I-3P', category: 'Information disclosure', title: 'Disclosure through supplier',
    types: ['third_party'], controls: ['contractSecurityClauses', 'vendorAssessment'],
    scenario: (c) => `Data shared with ${describe(c)} is disclosed due to weaknesses in the supplier's environment.`,
    preconditions: ['Data is transferred to or processed by the supplier'],
    mitigation: 'Perform third-party risk assessments, include security and breach-notification clauses, minimise data shared.',
    tags: ['third-party', 'data-protection'],
  },
  {
    id: 'STRIDE-D', category: 'Denial of service', title: 'Service exhaustion',
    types: ['web_server', 'app_server', 'api_gateway', 'load_balancer'], controls: ['rateLimiting', 'ddosProtection'],
    applies: exposedOrUnknown,
    scenario: (c) => `Volumetric or application-layer floods exhaust ${describe(c)}, making the service unavailable.`,
    preconditions: ['Component is reachable from an untrusted zone'],
    mitigation: 'Apply upstream DDoS protection, rate limiting / throttling and autoscaling with capacity alerts.',
    tags: ['availability', 'resilience'],
  },
  {
    id: 'STRIDE-D-DS', category: 'Denial of service', title: 'Loss or unavailability of data',
    types: ['database'], controls: ['backups'],
    scenario: (c) => `Data in ${describe(c)} is destroyed or encrypted (e.g. ransomware) and cannot be restored within tolerance.`,
    preconditions: ['Attacker or failure affects primary data and reachable backups'],
    mitigation: 'Maintain immutable, offline-segregated backups and test restoration against RTO/RPO.',
    tags: ['backup', 'resilience', 'availability'],
  },
  {
    id: 'STRIDE-E-PROC', category: 'Elevation of privilege', title: 'Privilege escalation on host or application',
    types: ['web_server', 'app_server', 'api_gateway', 'cloud_service', 'endpoint'], controls: ['authorization', 'hardening', 'patching', 'secretsManagement', 'edr'],
    scenario: (c) => `An attacker with a foothold exploits unpatched software, weak authorisation or exposed secrets on ${describe(c)} to gain higher privileges.`,
    preconditions: ['Initial foothold or authenticated low-privilege access'],
    mitigation: 'Apply hardened baselines, timely patching, enforce authorisation checks server-side and store secrets in a vault.',
    tags: ['access-control', 'vulnerability-management', 'hardening'],
  },
  {
    id: 'STRIDE-E-IAM', category: 'Elevation of privilege', title: 'Abuse of privileged identities',
    types: ['iam'], controls: ['pam', 'accessReviews', 'mfa'],
    scenario: (c) => `Privileged accounts managed by ${describe(c)} are abused or accumulate excessive rights, enabling broad compromise.`,
    preconditions: ['Standing privileged access', 'Infrequent access recertification'],
    mitigation: 'Introduce PAM with just-in-time elevation, MFA, session recording and periodic access reviews.',
    tags: ['privileged-access', 'identity', 'access-control'],
  },
  {
    id: 'STRIDE-E-CLOUD', category: 'Elevation of privilege', title: 'Cloud control-plane misconfiguration',
    types: ['cloud_service'], controls: ['cspmMonitoring', 'dataResidency'],
    scenario: (c) => `Misconfigured policies or public exposure in ${describe(c)} grant unintended access, or data is processed outside approved jurisdictions.`,
    preconditions: ['Configuration drift without posture monitoring'],
    mitigation: 'Enable cloud security posture management, guardrail policies and confirm data residency obligations.',
    tags: ['cloud', 'configuration-management'],
  },
];

// ------------------------------------------------------------------ analysis

function stride(v: ModelView): ThreatDraft[] {
  const out: ThreatDraft[] = [];
  for (const c of v.comps) {
    for (const r of COMPONENT_RULES) {
      if (!r.types.includes(c.type)) continue;
      if (r.applies && !r.applies(v, c)) continue;
      const controls = r.controls.filter((k) => v.hasProp(c, k));
      if (!controls.length) continue;
      const defs = COMPONENTS[c.type].props;
      const values = controls.map((k) => ({ key: k, label: defs.find((d) => d.key === k)!.label, value: v.prop(c, k) }));
      const { cls, existing, missing, weak } = classify(values);
      const missingInfo = [...missing];
      const impact = impactFor(v, c, missingInfo);
      let likelihood = baseLikelihood(v, c) + (cls === 'confirmed' ? 1 : cls === 'hypothesis' ? -1 : 0);
      const exposure = v.isExposed(c);
      if (exposure === 'unknown') missingInfo.push(`Zone placement / internet exposure of ${c.name} not recorded.`);
      const zone = v.zoneOf(c);
      out.push({
        key: `${r.id}:${c.id}`,
        methodology: 'STRIDE',
        category: r.category,
        title: `${r.title} — ${c.name}`,
        classification: cls,
        affectedAssets: [c.name],
        attackScenario: r.scenario(c),
        preconditions: [...r.preconditions, ...weak],
        existingControls: existing,
        missingInformation: missingInfo,
        likelihood: clamp(likelihood),
        impact,
        mitigation: r.mitigation,
        rationale: `STRIDE-per-element (${COMPONENTS[c.type].category.replace('_', ' ')}). Zone: ${zone ? `${zone.name} (trust ${zone.trustLevel})` : 'not placed'}; exposure: ${String(exposure)}.`,
        basis: values.map((x) => ({ elementId: c.id, elementKind: 'component' as const, fact: x.key, value: x.value })),
        tags: r.tags,
        modelVersion: 0,
      });
    }
  }

  for (const f of v.flows) {
    const a = v.byId.get(f.from)!;
    const b = v.byId.get(f.to)!;
    const crosses = v.crossesBoundary(f);
    const cls = CLASSIFICATION_RANK[f.dataClassification];
    const sensitive = cls >= 4;
    if (crosses === false && !sensitive && f.dataClassification !== 'unknown') continue;
    const proto = protocolSecurity(f.protocol);
    const name = `${a.name} → ${b.name}${f.label ? ` (${f.label})` : ''}`;
    const basis: FactRef[] = [
      { elementId: f.id, elementKind: 'flow', fact: 'protocol', value: f.protocol || 'unknown' },
      { elementId: f.id, elementKind: 'flow', fact: 'encrypted', value: f.encrypted },
      { elementId: f.id, elementKind: 'flow', fact: 'crosses-boundary', value: String(crosses) },
      { elementId: f.id, elementKind: 'flow', fact: 'dataClassification', value: f.dataClassification },
    ];
    const missingBase: string[] = [];
    if (crosses === 'unknown') missingBase.push('Zone placement of one or both endpoints not recorded; boundary crossing cannot be determined.');
    if (f.dataClassification === 'unknown') missingBase.push('Data classification of the flow is not recorded.');
    const impact = cls ? clamp(cls) : 3;
    const lowTrust = Math.min(v.trust(a) ?? 3, v.trust(b) ?? 3);
    const baseL = lowTrust <= 1 ? 4 : 3;

    // Information disclosure in transit
    {
      const values = [
        { label: 'Encryption in transit', value: f.encrypted },
        { label: `Protocol security (${f.protocol || 'not stated'})`, value: proto === 'secure' ? 'yes' : proto === 'insecure' ? 'no' : 'unknown' },
      ];
      // An explicitly encrypted flow over an unrecognised protocol is not a gap.
      if (f.encrypted === 'yes' && proto === 'unknown') values.pop();
      const r = classify(values);
      out.push({
        key: `STRIDE-I-FLOW:${f.id}`,
        methodology: 'STRIDE', category: 'Information disclosure',
        title: `Interception of data in transit — ${name}`,
        classification: r.cls,
        affectedAssets: [name],
        attackScenario: `An attacker positioned on the network path between ${a.name} and ${b.name} captures ${f.dataClassification !== 'unknown' ? f.dataClassification + ' ' : ''}data in transit.`,
        preconditions: ['Attacker can observe traffic on the path', ...r.weak],
        existingControls: r.existing,
        missingInformation: [...r.missing, ...missingBase],
        likelihood: clamp(baseL + (r.cls === 'confirmed' ? 1 : r.cls === 'hypothesis' ? -2 : 0)),
        impact,
        mitigation: 'Use TLS 1.2+ (mTLS for service-to-service) with certificate validation; disable plaintext protocols.',
        rationale: `STRIDE-per-element (data flow). Crosses trust boundary: ${String(crosses)}.`,
        basis, tags: ['encryption-transit', 'cryptography'], modelVersion: 0,
      });
    }
    // Spoofing / tampering of flow
    if (crosses !== false) {
      const values = [
        { label: 'Flow authentication', value: f.authenticated },
        { label: 'Encryption / integrity protection', value: f.encrypted },
      ];
      const r = classify(values);
      out.push({
        key: `STRIDE-T-FLOW:${f.id}`,
        methodology: 'STRIDE', category: 'Tampering',
        title: `Man-in-the-middle / message tampering — ${name}`,
        classification: r.cls,
        affectedAssets: [name],
        attackScenario: `Messages crossing the trust boundary between ${a.name} and ${b.name} are injected, replayed or altered because the channel lacks authentication or integrity protection.`,
        preconditions: ['Attacker can reach or intercept the channel', ...r.weak],
        existingControls: r.existing,
        missingInformation: [...r.missing, ...missingBase],
        likelihood: clamp(baseL + (r.cls === 'confirmed' ? 1 : r.cls === 'hypothesis' ? -2 : 0)),
        impact,
        mitigation: 'Authenticate both endpoints (mTLS or signed tokens), protect message integrity and reject replays.',
        rationale: 'STRIDE-per-element (data flow crossing a trust boundary).',
        basis: [...basis, { elementId: f.id, elementKind: 'flow', fact: 'authenticated', value: f.authenticated }],
        tags: ['authentication', 'encryption-transit', 'network-security'], modelVersion: 0,
      });
    }
    // Structural: direct untrusted -> highly trusted
    const ta = v.trust(a);
    const tb = v.trust(b);
    if (ta !== undefined && tb !== undefined && Math.abs(ta - tb) >= 3) {
      const low = ta < tb ? a : b;
      const high = ta < tb ? b : a;
      const za = v.zoneOf(low)!;
      const zb = v.zoneOf(high)!;
      out.push({
        key: `STRUCT-SEG:${f.id}`,
        methodology: 'STRIDE', category: 'Elevation of privilege',
        title: `Direct flow from low-trust to high-trust zone — ${name}`,
        classification: 'confirmed',
        affectedAssets: [high.name],
        attackScenario: `${low.name} in "${za.name}" (trust ${za.trustLevel}) communicates directly with ${high.name} in "${zb.name}" (trust ${zb.trustLevel}) with no intermediate tier recorded in the model; compromise of the low-trust side gives a direct path to the high-trust asset.`,
        preconditions: ['Compromise of the lower-trust component'],
        existingControls: [], missingInformation: [],
        likelihood: clamp(baseL), impact: Math.max(impact, impactFor(v, high, [])),
        mitigation: 'Introduce an intermediary tier (proxy / API gateway / application layer) and restrict the flow at a firewall with explicit rules.',
        rationale: `Structural fact from confirmed model: zone trust difference of ${Math.abs(ta - tb)} levels on a single flow.`,
        basis: [
          { elementId: za.id, elementKind: 'zone', fact: 'trustLevel', value: String(za.trustLevel) },
          { elementId: zb.id, elementKind: 'zone', fact: 'trustLevel', value: String(zb.trustLevel) },
          { elementId: f.id, elementKind: 'flow', fact: 'endpoints', value: `${low.name} → ${high.name}` },
        ],
        tags: ['network-segmentation', 'network-security'], modelVersion: 0,
      });
    }
  }

  // Structural: data store marked internet facing
  for (const c of v.comps.filter((c) => c.type === 'database' && v.prop(c, 'internetFacing') === 'yes')) {
    out.push({
      key: `STRUCT-DBEXP:${c.id}`, methodology: 'STRIDE', category: 'Information disclosure',
      title: `Data store directly exposed to the internet — ${c.name}`,
      classification: 'confirmed', affectedAssets: [c.name],
      attackScenario: `${c.name} is recorded as internet facing; attackers can attempt authentication attacks and exploit database vulnerabilities directly.`,
      preconditions: ['Database listener reachable from the internet'], existingControls: [], missingInformation: [],
      likelihood: 5, impact: impactFor(v, c, []),
      mitigation: 'Remove direct internet exposure; place the data store in a restricted zone reachable only from the application tier.',
      rationale: 'Structural fact: property internetFacing = yes on a data store.',
      basis: [{ elementId: c.id, elementKind: 'component', fact: 'internetFacing', value: 'yes' }],
      tags: ['network-segmentation', 'data-protection'], modelVersion: 0,
    });
  }
  return out;
}

function isEntry(v: ModelView, c: ArchComponent) {
  const t = v.trust(c);
  if (c.type === 'user' || c.type === 'third_party') return t === undefined ? true : t <= 1;
  return v.prop(c, 'internetFacing') === 'yes' || (t !== undefined && t <= 1);
}

function isCrownJewel(v: ModelView, c: ArchComponent) {
  if (c.type !== 'database' && c.type !== 'cloud_service') return false;
  const crit = v.prop(c, 'criticality');
  return v.classificationOf(c) >= 4 || crit === 'high' || crit === 'critical';
}

function shortestPath(v: ModelView, from: string, to: string): string[] | null {
  const prev = new Map<string, string | null>([[from, null]]);
  const q = [from];
  while (q.length) {
    const cur = q.shift()!;
    if (cur === to) break;
    for (const n of v.neighbours(cur)) if (!prev.has(n)) { prev.set(n, cur); q.push(n); }
  }
  if (!prev.has(to)) return null;
  const path: string[] = [];
  for (let c: string | null = to; c; c = prev.get(c) ?? null) path.unshift(c);
  return path;
}

function flowBetween(v: ModelView, a: string, b: string) {
  return v.flows.find((f) => (f.from === a && f.to === b) || (f.bidirectional && f.from === b && f.to === a));
}

function pasta(v: ModelView): ThreatDraft[] {
  const out: ThreatDraft[] = [];
  const candidates = v.comps.filter((c) => isEntry(v, c));
  const ids = new Set(candidates.map((c) => c.id));
  // An entry point fed directly by another entry point (e.g. an edge firewall behind the
  // internet user) is a hop on that actor's path, not a separate entry point.
  const entries = candidates.filter((c) => !v.inbound(c).some((f) => ids.has(f.to === c.id ? f.from : f.to)));
  const targets = v.comps.filter((c) => isCrownJewel(v, c));
  for (const e of entries) {
    for (const t of targets) {
      if (e.id === t.id) continue;
      const path = shortestPath(v, e.id, t.id);
      if (!path) continue;
      const nodes = path.map((id) => v.byId.get(id)!);
      const weak: string[] = [];
      const unknown: string[] = [];
      const present: string[] = [];
      const basis: FactRef[] = [];
      for (let i = 0; i < nodes.length - 1; i++) {
        const f = flowBetween(v, nodes[i].id, nodes[i + 1].id)!;
        const hop = `${nodes[i].name} → ${nodes[i + 1].name}`;
        basis.push({ elementId: f.id, elementKind: 'flow', fact: 'encrypted', value: f.encrypted });
        if (f.encrypted === 'no') weak.push(`Hop ${hop} is not encrypted`);
        else if (f.encrypted === 'unknown') unknown.push(`Encryption of hop ${hop} not recorded`);
        else present.push(`Hop ${hop} encrypted (recorded)`);
      }
      for (const n of nodes.slice(1)) {
        if (!v.hasProp(n, 'authentication')) continue;
        const a = v.prop(n, 'authentication');
        basis.push({ elementId: n.id, elementKind: 'component', fact: 'authentication', value: a });
        if (a === 'no') weak.push(`${n.name} does not enforce authentication`);
        else if (a === 'unknown') unknown.push(`Authentication at ${n.name} not recorded`);
        else present.push(`${n.name} enforces authentication (recorded)`);
      }
      const cls: ThreatClass = weak.length ? 'confirmed' : unknown.length ? 'missing_evidence' : 'hypothesis';
      const missingInfo = [...unknown];
      const impact = impactFor(v, t, missingInfo);
      const hops = nodes.length - 1;
      const likelihood = clamp(5 - Math.max(0, hops - 2) * 0.5 + (cls === 'confirmed' ? 0 : cls === 'hypothesis' ? -2 : -1));
      out.push({
        key: `PASTA-PATH:${e.id}>${t.id}`,
        methodology: 'PASTA', category: 'Stage 6 — Attack modelling (attack path)',
        title: `Attack path from ${e.name} to ${t.name}`,
        classification: cls,
        affectedAssets: [t.name, ...nodes.slice(1, -1).map((n) => n.name)],
        attackScenario: `An adversary entering at ${e.name} traverses ${nodes.map((n) => n.name).join(' → ')} (${hops} hop${hops > 1 ? 's' : ''}) to reach ${t.name}, which holds ${v.prop(t, 'dataClassification')} data.`,
        preconditions: [`Adversary controls or impersonates ${e.name}`, ...weak],
        existingControls: present,
        missingInformation: missingInfo,
        likelihood, impact,
        mitigation: 'Break the path with layered controls: authenticate each hop, encrypt every boundary-crossing flow, restrict lateral movement and monitor the target data store.',
        rationale: 'PASTA stages 3–6: entry points and target assets derived from confirmed zones/properties; path is the shortest route over confirmed data flows.',
        basis, tags: ['network-segmentation', 'access-control', 'monitoring'], modelVersion: 0,
      });
    }
  }
  return out;
}

const OCTAVE_OUTCOMES: { id: string; outcome: string; controls: string[]; tags: string[]; mitigation: string }[] = [
  { id: 'DISC', outcome: 'Disclosure', controls: ['encryptionAtRest', 'authorization'], tags: ['data-protection', 'encryption-rest'], mitigation: 'Restrict access by need-to-know, encrypt at rest, monitor bulk data access.' },
  { id: 'MOD', outcome: 'Modification', controls: ['leastPrivilegeAccounts', 'activityMonitoring', 'authorization'], tags: ['access-control', 'monitoring'], mitigation: 'Restrict write privileges, monitor and alert on anomalous changes, maintain integrity checks.' },
  { id: 'DEST', outcome: 'Destruction / loss', controls: ['backups'], tags: ['backup', 'resilience'], mitigation: 'Maintain immutable, tested backups held outside the primary trust domain.' },
  { id: 'INT', outcome: 'Interruption', controls: ['backups', 'logging'], tags: ['availability', 'resilience'], mitigation: 'Define RTO/RPO, implement redundancy and rehearse recovery.' },
];

function octave(v: ModelView): ThreatDraft[] {
  const out: ThreatDraft[] = [];
  for (const asset of v.comps.filter((c) => isCrownJewel(v, c))) {
    const containers = v.comps.filter((c) => c.id !== asset.id && (v.neighbours(c.id).includes(asset.id) || v.neighbours(asset.id).includes(c.id)));
    const reachableFromEntry = v.comps.filter((c) => isEntry(v, c)).some((e) => shortestPath(v, e.id, asset.id));
    for (const o of OCTAVE_OUTCOMES) {
      const keys = o.controls.filter((k) => v.hasProp(asset, k));
      if (!keys.length) continue;
      const defs = COMPONENTS[asset.type].props;
      const values = keys.map((k) => ({ key: k, label: defs.find((d) => d.key === k)!.label, value: v.prop(asset, k) }));
      const r = classify(values);
      const missingInfo = [...r.missing];
      const impact = impactFor(v, asset, missingInfo);
      const actors = [
        containers.length ? `insiders or compromised services via ${containers.map((c) => c.name).join(', ')}` : 'administrators with direct access',
        reachableFromEntry ? 'external actors reaching the asset over confirmed flows' : null,
      ].filter(Boolean).join('; ');
      out.push({
        key: `OCTAVE-${o.id}:${asset.id}`,
        methodology: 'OCTAVE', category: `Area of concern — ${o.outcome}`,
        title: `${o.outcome} of information asset ${asset.name}`,
        classification: r.cls,
        affectedAssets: [asset.name, ...containers.map((c) => c.name)],
        attackScenario: `Threat actors (${actors}) cause ${o.outcome.toLowerCase()} of the information held in ${asset.name}. Impact areas: reputation/customer confidence, financial, legal/regulatory${o.id === 'INT' ? ', productivity' : ''}.`,
        preconditions: [`Access to a technical container of ${asset.name}`, ...r.weak],
        existingControls: r.existing,
        missingInformation: missingInfo,
        likelihood: clamp((reachableFromEntry ? 3 : 2) + (r.cls === 'confirmed' ? 1 : r.cls === 'hypothesis' ? -1 : 0)),
        impact,
        mitigation: o.mitigation,
        rationale: `OCTAVE Allegro: critical information asset (classification ${v.prop(asset, 'dataClassification')}, criticality ${v.prop(asset, 'criticality')}); containers derived from confirmed flows.`,
        basis: values.map((x) => ({ elementId: asset.id, elementKind: 'component' as const, fact: x.key, value: x.value })),
        tags: o.tags, modelVersion: 0,
      });
    }
  }
  return out;
}

function structuralGaps(v: ModelView): ThreatDraft[] {
  const gaps: ThreatDraft[] = [];
  const unplaced = v.comps.filter((c) => !v.zoneOf(c));
  if (unplaced.length && v.zones.length) {
    gaps.push(gap('GAP-ZONE', 'Components not placed in a security zone', unplaced.map((c) => c.name),
      unplaced.map((c) => `${c.name}: zone placement not recorded`), unplaced.map((c) => ({ elementId: c.id, elementKind: 'component' as const, fact: 'zone', value: 'none' }))));
  }
  if (!v.zones.length && v.comps.length) {
    gaps.push(gap('GAP-NOZONES', 'No confirmed trust boundaries / security zones', ['Whole architecture'],
      ['No confirmed security zones exist; boundary-crossing analysis cannot be performed.'], []));
  }
  const isolated = v.comps.filter((c) => !v.flows.some((f) => f.from === c.id || f.to === c.id));
  if (isolated.length) {
    gaps.push(gap('GAP-ISOLATED', 'Components without any confirmed data flow', isolated.map((c) => c.name),
      isolated.map((c) => `${c.name}: no confirmed data flows recorded`), isolated.map((c) => ({ elementId: c.id, elementKind: 'component' as const, fact: 'flows', value: '0' }))));
  }
  const noProto = v.flows.filter((f) => !f.protocol.trim());
  if (noProto.length) {
    gaps.push(gap('GAP-PROTO', 'Data flows without a recorded protocol', noProto.map((f) => `${v.byId.get(f.from)!.name} → ${v.byId.get(f.to)!.name}`),
      noProto.map((f) => `Protocol of flow ${v.byId.get(f.from)!.name} → ${v.byId.get(f.to)!.name} not recorded`), noProto.map((f) => ({ elementId: f.id, elementKind: 'flow' as const, fact: 'protocol', value: '' }))));
  }
  return gaps;
}

function gap(id: string, title: string, assets: string[], missing: string[], basis: FactRef[]): ThreatDraft {
  return {
    key: `${id}:${assets.join('|').slice(0, 120)}`,
    methodology: 'STRIDE', category: 'Model completeness', title, classification: 'missing_evidence',
    affectedAssets: assets, attackScenario: 'Not a threat scenario: information required to complete the analysis is absent from the confirmed model.',
    preconditions: [], existingControls: [], missingInformation: missing, likelihood: 1, impact: 1,
    mitigation: 'Obtain the missing information from the solution owner and update the architecture model.',
    rationale: 'Model completeness check.', basis, tags: ['asset-management'], modelVersion: 0,
  };
}

export function analyzeModel(model: ArchitectureModel, methods: Methodology[], modelVersion: number): AnalysisResult {
  const v = new ModelView(model);
  const drafts: ThreatDraft[] = [];
  if (methods.includes('STRIDE')) drafts.push(...stride(v));
  if (methods.includes('PASTA')) drafts.push(...pasta(v));
  if (methods.includes('OCTAVE')) drafts.push(...octave(v));
  const gaps = structuralGaps(v);
  const all = [...drafts, ...gaps].map((d) => ({ ...d, modelVersion }));
  return { drafts: all, skippedUnconfirmed: v.skipped, structuralGaps: gaps };
}

/**
 * Merge a new engine run with existing threats. Analyst decisions, notes and evidence are kept
 * for threats whose deterministic key is regenerated. Engine threats that are no longer produced
 * are dropped unless they were accepted or are referenced by a risk, in which case they are kept
 * and tagged "not-in-latest-run".
 */
export function mergeRun(
  existing: Threat[],
  drafts: ThreatDraft[],
  ctx: { runId: string; at: string; by: string; newId: () => string; referenced: Set<string> },
): Threat[] {
  const byKey = new Map(existing.map((t) => [t.key, t]));
  const produced = new Set<string>();
  const result: Threat[] = [];
  for (const d of drafts) {
    produced.add(d.key);
    const prev = byKey.get(d.key);
    result.push({
      ...d,
      id: prev?.id ?? ctx.newId(),
      decision: prev?.decision ?? 'proposed',
      analystNotes: prev?.analystNotes ?? '',
      evidenceRefs: prev?.evidenceRefs ?? [],
      runId: ctx.runId,
      createdAt: prev?.createdAt ?? ctx.at,
      updatedAt: ctx.at,
      updatedBy: ctx.by,
    });
  }
  for (const t of existing) {
    if (produced.has(t.key)) continue;
    if (t.methodology === 'MANUAL') { result.push(t); continue; }
    if (t.decision === 'accepted' || ctx.referenced.has(t.id)) {
      result.push({ ...t, tags: Array.from(new Set([...t.tags, 'not-in-latest-run'])) });
    }
  }
  return result;
}
