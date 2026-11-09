// AI provider interface. No provider adapter ships with this build: the interface, gating and
// approval controls exist so an approved adapter can be added, but nothing is ever sent to an
// external AI service unless ALL of the following are true:
//   1. the environment is production-approved (SAWB_ENV=production),
//   2. a provider is configured (SAWB_AI_PROVIDER / SAWB_AI_ENDPOINT),
//   3. an adapter for that provider is implemented and registered below,
//   4. document processing is enabled (SAWB_AI_ALLOW_DOCUMENTS=true) for document extraction,
//   5. a lead reviewer approved the specific document, and
//   6. the requesting user explicitly confirms the individual request.

import { config } from './config';
import type { AiStatus, ArchitectureModel, ThreatClass } from '../shared/types';

export interface ExtractionCandidate {
  kind: 'component' | 'flow' | 'zone';
  label: string;
  confidence: number;
  location: string;
}

export interface AiAdapter {
  name: string;
  /** Propose candidate model elements from a document. Output is always UNCONFIRMED. */
  extractArchitecture(input: { fileName: string; mimeType: string; content: Buffer }): Promise<ExtractionCandidate[]>;
  /** Propose additional threat hypotheses for a saved model version. */
  analyze(input: { model: ArchitectureModel; modelVersion: number }): Promise<{ title: string; classification: ThreatClass; rationale: string }[]>;
}

/** Register implemented adapters here. Intentionally empty in this build. */
export const AI_ADAPTERS: Record<string, AiAdapter> = {};

export function getAiStatus(): AiStatus {
  const provider = config.ai.provider;
  const adapterImplemented = !!(provider && AI_ADAPTERS[provider]);
  const configured = !!(provider && config.ai.endpoint && config.mode === 'production');
  let message: string;
  if (config.mode !== 'production') message = 'Demonstration environment: external AI services are disabled until a production-approved environment is configured.';
  else if (!provider || !config.ai.endpoint) message = 'No AI provider is configured (SAWB_AI_PROVIDER / SAWB_AI_ENDPOINT).';
  else if (!adapterImplemented) message = `Provider "${provider}" is configured but no adapter is implemented in this build.`;
  else if (!config.ai.allowDocuments) message = 'Provider adapter available; document processing is disabled (SAWB_AI_ALLOW_DOCUMENTS).';
  else message = 'AI provider available. Each request still requires document approval and user confirmation.';
  return {
    configured,
    provider,
    adapterImplemented,
    documentProcessingAllowed: configured && adapterImplemented && config.ai.allowDocuments,
    environment: config.mode,
    message,
  };
}
