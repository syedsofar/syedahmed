import { api } from './api';
import type { ComponentCatalog } from '@shared/catalog';

// The component library is loaded once per browser session.
let cached: Promise<ComponentCatalog> | null = null;
export function loadCatalog(): Promise<ComponentCatalog> {
  if (!cached) {
    cached = api.get<ComponentCatalog>('/catalog/components').catch((e) => {
      cached = null;
      throw e;
    });
  }
  return cached;
}
