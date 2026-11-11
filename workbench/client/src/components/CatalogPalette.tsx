import { useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api';
import { defaultTypeFor, type CatalogItem, type ComponentCatalog } from '@shared/catalog';

// The catalog is loaded once per browser session and shared by every editor view.
let cached: Promise<ComponentCatalog> | null = null;
function loadCatalog(): Promise<ComponentCatalog> {
  if (!cached) {
    cached = api.get<ComponentCatalog>('/catalog/components').catch((e) => {
      cached = null;
      throw e;
    });
  }
  return cached;
}

const MAX_RESULTS = 60;

export function CatalogPalette({ editable, onAdd }: { editable: boolean; onAdd: (item: CatalogItem) => void }) {
  const [catalog, setCatalog] = useState<ComponentCatalog | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [group, setGroup] = useState('');

  useEffect(() => {
    let alive = true;
    loadCatalog().then((c) => alive && setCatalog(c)).catch((e) => alive && setError(e instanceof Error ? e.message : 'Could not load the component library.'));
    return () => { alive = false; };
  }, []);

  const results = useMemo(() => {
    if (!catalog) return { items: [] as CatalogItem[], total: 0 };
    const q = query.trim().toLowerCase();
    const matches = catalog.components.filter((c) =>
      (!group || c.groupId === group) &&
      (!q || c.name.toLowerCase().includes(q) || c.subgroup.toLowerCase().includes(q) || c.description.toLowerCase().includes(q)));
    return { items: matches.slice(0, MAX_RESULTS), total: matches.length };
  }, [catalog, query, group]);

  if (error) return <div className="muted small">Component library unavailable: {error}</div>;
  if (!catalog) return <div className="muted small">Loading component library…</div>;

  return (
    <div style={{ marginTop: 10 }} aria-label="Component library">
      <div className="field-label" style={{ marginBottom: 6 }}>Component library <span className="muted small">— {catalog.components.length.toLocaleString()} items; click to add</span></div>
      <input type="search" placeholder="Search library" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search component library" style={{ width: '100%' }} />
      <select value={group} onChange={(e) => setGroup(e.target.value)} aria-label="Filter by group" style={{ width: '100%', marginTop: 6 }}>
        <option value="">All groups</option>
        {catalog.groups.map((g) => <option key={g.id} value={g.id}>{g.name} ({g.count})</option>)}
      </select>
      <div className="muted small" style={{ margin: '6px 0' }}>{results.total.toLocaleString()} match{results.total === 1 ? '' : 'es'}{results.total > MAX_RESULTS ? `; showing first ${MAX_RESULTS}` : ''}</div>
      <div style={{ maxHeight: 320, overflowY: 'auto', display: 'grid', gap: 4 }}>
        {results.items.map((item) => (
          <button key={item.id} type="button" className="palette-item" disabled={!editable} onClick={() => onAdd(item)} title={`${item.subgroup}: ${item.description}`}
            style={{ textAlign: 'left', width: '100%' }}>
            <span className="palette-swatch" style={{ background: '#e6ecef', overflow: 'hidden', padding: 0 }}>
              {item.icon && item.iconType !== 'fallback' && item.iconType !== 'external-asset'
                ? <img src={item.icon} alt="" width={28} height={28} style={{ display: 'block' }} />
                : <span style={{ fontSize: 10, color: '#1d3b4a' }}>{item.name.slice(0, 3).toUpperCase()}</span>}
            </span>
            <span>{item.name}<span className="muted small" style={{ display: 'block' }}>{item.subgroup} → {defaultTypeFor(item).replace(/_/g, ' ')}</span></span>
          </button>
        ))}
      </div>
    </div>
  );
}
