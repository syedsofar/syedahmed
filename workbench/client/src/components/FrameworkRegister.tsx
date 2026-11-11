import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { FRAMEWORKS, LICENCE_LABELS, ROLE_LABELS, type FrameworkEntry } from '@shared/frameworks';

// Shows every framework the workbench is set up to support, and whether control text is loaded.
// Entries here are metadata only. Control text needs a versioned, approved catalog import.
export function FrameworkRegister() {
  const [items, setItems] = useState<FrameworkEntry[]>(FRAMEWORKS);
  useEffect(() => {
    api.get<FrameworkEntry[]>('/frameworks').then(setItems).catch(() => undefined);
  }, []);

  return (
    <div className="card card-pad" style={{ marginBottom: 14 }} aria-label="Framework register">
      <h2 style={{ marginTop: 0 }}>Framework register</h2>
      <p className="muted small" style={{ marginTop: 0 }}>
        {items.length} sources. Control text is loaded only from an approved, versioned catalog import. Versions and sources must be confirmed against the publisher before import.
      </p>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Framework</th><th>Role</th><th>Version</th><th>Licence</th><th>Control text</th></tr></thead>
          <tbody>
            {items.map((f) => (
              <tr key={f.id}>
                <td><a href={f.source} target="_blank" rel="noreferrer">{f.name}</a><div className="muted small">{f.publisher}{f.stated_scope ? ` · ${f.stated_scope}` : ''}</div></td>
                <td>{ROLE_LABELS[f.role]}</td>
                <td>{f.version}</td>
                <td>{LICENCE_LABELS[f.licence]}</td>
                <td className="muted">Not loaded</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
