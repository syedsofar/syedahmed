// Component catalog (2,549 items, 24 groups) imported from the ArchGuard prototype.
// The catalog is reference material. A catalog item becomes a model component only
// when an analyst adds it; its type is a default that the Inspector can change.
import type { ComponentType } from './types';

export interface CatalogItem {
  id: string;
  name: string;
  groupId: string;
  subgroup: string;
  description: string;
  icon: string;
  iconType: 'embedded-svg' | 'embedded-png' | 'external-asset' | 'fallback';
  level: string;
  sourceId: string;
}

export interface CatalogGroup {
  id: string;
  name: string;
  description: string;
  count: number;
}

export interface ComponentCatalog {
  meta: Record<string, unknown>;
  groups: CatalogGroup[];
  components: CatalogItem[];
}

/** Default model type for each catalog group. Approximate; analysts can change it. */
export const GROUP_DEFAULT_TYPE: Record<string, ComponentType> = {
  threatmodel: 'app_server',
  process: 'app_server',
  aws: 'cloud_service',
  azure: 'cloud_service',
  gcp: 'cloud_service',
  cloud: 'cloud_service',
  onprem: 'app_server',
  net: 'firewall',
  endpoints: 'endpoint',
  gateways: 'api_gateway',
  ai: 'app_server',
  mobile: 'endpoint',
  iot: 'endpoint',
  compute: 'app_server',
  apps: 'web_server',
  data: 'database',
  security: 'app_server',
  devops: 'app_server',
  iam: 'iam',
  grc: 'app_server',
  bizarch: 'app_server',
  project: 'app_server',
  people: 'user',
  external: 'third_party',
};

export function defaultTypeFor(item: Pick<CatalogItem, 'groupId'>): ComponentType {
  return GROUP_DEFAULT_TYPE[item.groupId] ?? 'app_server';
}
