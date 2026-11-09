// Shared domain model for the Security Architecture Review & Threat Modeling Workbench.
// The canonical architecture model is the single source of truth that every analysis
// (threat modelling, control review, reporting) is derived from.

export const MODEL_SCHEMA = 'sawb.architecture/1.0';

export type Tri = 'yes' | 'no' | 'unknown';

export type ComponentType =
  | 'user'
  | 'endpoint'
  | 'firewall'
  | 'load_balancer'
  | 'api_gateway'
  | 'web_server'
  | 'app_server'
  | 'database'
  | 'iam'
  | 'cloud_service'
  | 'third_party';

export type ElementStatus = 'confirmed' | 'unconfirmed';

export interface SourceRef {
  kind: 'manual' | 'drawio' | 'document';
  /** File name or evidence id the element was derived from. */
  ref?: string;
  /** Page / location note for document-derived elements. */
  location?: string;
  /** Why an importer classified the element the way it did. */
  note?: string;
}

export interface ArchComponent {
  id: string;
  type: ComponentType;
  name: string;
  x: number;
  y: number;
  status: ElementStatus;
  source: SourceRef;
  /** Property values keyed by the property schema for this component type. */
  properties: Record<string, string>;
}

export type DataClassification = 'unknown' | 'public' | 'internal' | 'confidential' | 'restricted';

export interface DataFlow {
  id: string;
  from: string;
  to: string;
  label: string;
  protocol: string;
  port: string;
  encrypted: Tri;
  authenticated: Tri;
  dataClassification: DataClassification;
  bidirectional: boolean;
  status: ElementStatus;
  source: SourceRef;
}

export type ZoneType = 'internet' | 'dmz' | 'internal' | 'restricted' | 'management' | 'cloud' | 'third_party' | 'user_zone';

export interface TrustZone {
  id: string;
  name: string;
  zoneType: ZoneType;
  /** 0 = untrusted ... 4 = highly trusted. */
  trustLevel: number;
  x: number;
  y: number;
  w: number;
  h: number;
  status: ElementStatus;
  source: SourceRef;
}

export interface ArchitectureModel {
  schema: typeof MODEL_SCHEMA;
  components: ArchComponent[];
  flows: DataFlow[];
  zones: TrustZone[];
  notes: string;
}

export interface ModelVersion {
  version: number;
  savedAt: string;
  savedBy: string;
  message: string;
  hash: string;
  model: ArchitectureModel;
}

// ---------------------------------------------------------------- users & projects

export type Role = 'admin' | 'lead_reviewer' | 'analyst' | 'viewer';
export type ProjectRole = 'owner' | 'editor' | 'viewer';

export interface PublicUser {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  disabled: boolean;
}

export type AssessmentStatus = 'draft' | 'in_review' | 'pending_approval' | 'final' | 'archived';

export type Methodology = 'STRIDE' | 'PASTA' | 'OCTAVE';

export interface RiskMatrixConfig {
  likelihoodLabels: [string, string, string, string, string];
  impactLabels: [string, string, string, string, string];
  /** Inclusive lower score bounds for each band, ascending. score = L x I (1..25). */
  bands: { name: string; min: number; color: string }[];
}

export interface ProjectMember {
  userId: string;
  role: ProjectRole;
}

export interface HistoryEntry {
  at: string;
  by: string;
  action: string;
  detail?: string;
}

export interface ReportNarrative {
  executiveSummary: string;
  limitations: string;
  recommendations: string;
}

export interface Project {
  id: string;
  name: string;
  clientAlias: string;
  scope: string;
  architectureVersion: string;
  reviewerId: string;
  status: AssessmentStatus;
  reviewDate: string;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  isDemo: boolean;
  members: ProjectMember[];
  methodologies: Methodology[];
  catalogIds: string[];
  riskMatrix: RiskMatrixConfig;
  narrative: ReportNarrative;
  history: HistoryEntry[];
}

// ---------------------------------------------------------------- threat model

export type ThreatClass = 'confirmed' | 'hypothesis' | 'missing_evidence';
export type ThreatDecision = 'proposed' | 'accepted' | 'rejected';

export interface FactRef {
  elementId: string;
  elementKind: 'component' | 'flow' | 'zone';
  /** Property name, or a structural fact such as "crosses-boundary". */
  fact: string;
  value: string;
}

export interface Threat {
  id: string;
  /** Deterministic key (rule + elements) so re-runs keep analyst decisions. */
  key: string;
  methodology: Methodology | 'MANUAL';
  category: string;
  title: string;
  classification: ThreatClass;
  affectedAssets: string[];
  attackScenario: string;
  preconditions: string[];
  existingControls: string[];
  missingInformation: string[];
  likelihood: number;
  impact: number;
  mitigation: string;
  rationale: string;
  basis: FactRef[];
  tags: string[];
  decision: ThreatDecision;
  analystNotes: string;
  evidenceRefs: string[];
  modelVersion: number;
  runId: string;
  createdAt: string;
  updatedAt: string;
  updatedBy: string;
}

export interface AnalysisRun {
  id: string;
  at: string;
  by: string;
  provider: string;
  providerVersion: string;
  modelVersion: number;
  methodologies: Methodology[];
  counts: Record<ThreatClass, number>;
  skippedUnconfirmed: number;
}

// ---------------------------------------------------------------- controls

export type Framework = 'NCA_ECC' | 'SAMA_CSF' | 'NIST_CSF' | 'ISO_27001';
export type CatalogStatus = 'draft' | 'approved' | 'retired';

export interface CatalogControl {
  id: string;
  domain: string;
  title: string;
  /** Topic tags used to map threats to controls. */
  tags: string[];
}

export interface ControlCatalog {
  id: string;
  framework: Framework;
  name: string;
  version: string;
  status: CatalogStatus;
  source: string;
  isDemo: boolean;
  importedBy: string;
  importedAt: string;
  approvedBy?: string;
  approvedAt?: string;
  contentHash: string;
  controls: CatalogControl[];
}

export type ControlReviewStatus =
  | 'not_assessed'
  | 'information_missing'
  | 'gap_identified'
  | 'evidence_satisfied'
  | 'not_applicable';

export interface ControlReview {
  id: string;
  catalogId: string;
  controlId: string;
  status: ControlReviewStatus;
  notes: string;
  evidenceRefs: string[];
  updatedAt: string;
  updatedBy: string;
}

// ---------------------------------------------------------------- risks

export type TreatmentStrategy = 'mitigate' | 'accept' | 'transfer' | 'avoid';
export type TreatmentStatus = 'open' | 'in_progress' | 'implemented' | 'closed';

export interface MitigationAction {
  id: string;
  description: string;
  owner: string;
  dueDate: string;
  done: boolean;
}

export interface Risk {
  id: string;
  ref: string;
  title: string;
  description: string;
  threatIds: string[];
  likelihood: number;
  impact: number;
  residualLikelihood: number;
  residualImpact: number;
  owner: string;
  strategy: TreatmentStrategy;
  status: TreatmentStatus;
  targetDate: string;
  actions: MitigationAction[];
  approval: { state: 'pending' | 'approved' | 'changes_requested'; by?: string; at?: string; comment?: string };
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

// ---------------------------------------------------------------- evidence

export interface EvidenceFile {
  id: string;
  fileName: string;
  mimeType: string;
  size: number;
  sha256: string;
  uploadedBy: string;
  uploadedAt: string;
  description: string;
  /** Explicit per-file approval to send to an AI provider. Default false. */
  aiProcessingApproved: boolean;
  confirmation: 'pending' | 'transcribed' | 'not_used';
}

export interface ProjectData {
  project: Project;
  model: ArchitectureModel;
  versions: Omit<ModelVersion, 'model'>[];
  threats: Threat[];
  runs: AnalysisRun[];
  controlReviews: ControlReview[];
  risks: Risk[];
  evidence: EvidenceFile[];
}

export interface AuditEntry {
  seq: number;
  at: string;
  userId: string;
  username: string;
  action: string;
  projectId?: string;
  target?: string;
  detail?: string;
  ip?: string;
  prevHash: string;
  hash: string;
}

export interface AiStatus {
  configured: boolean;
  provider: string | null;
  adapterImplemented: boolean;
  documentProcessingAllowed: boolean;
  environment: 'demonstration' | 'production';
  message: string;
}
