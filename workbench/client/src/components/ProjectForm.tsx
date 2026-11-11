import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Field } from './ui';
import { FRAMEWORK_LABELS } from '@shared/controls';
import type { ControlCatalog, Methodology } from '@shared/types';

export interface ProjectFormValue {
  name: string;
  clientAlias: string;
  scope: string;
  architectureVersion: string;
  reviewerId: string;
  reviewDate: string;
  methodologies: Methodology[];
  catalogIds: string[];
}

export const emptyProjectForm = (): ProjectFormValue => ({
  name: '', clientAlias: '', scope: '', architectureVersion: '', reviewerId: '', reviewDate: '', methodologies: ['PROTOTYPE'], catalogIds: [],
});

export function useCatalogs() {
  const [cats, setCats] = useState<ControlCatalog[]>([]);
  useEffect(() => { api.get<ControlCatalog[]>('/catalogs').then(setCats).catch(() => setCats([])); }, []);
  return cats;
}

export function ProjectForm({ value, onChange, disabled }: { value: ProjectFormValue; onChange: (v: ProjectFormValue) => void; disabled?: boolean }) {
  const { users } = useAuth();
  const cats = useCatalogs();
  const set = <K extends keyof ProjectFormValue>(k: K, v: ProjectFormValue[K]) => onChange({ ...value, [k]: v });
  const toggle = <T,>(list: T[], item: T) => (list.includes(item) ? list.filter((x) => x !== item) : [...list, item]);
  const reviewers = users.filter((u) => !u.disabled && u.role !== 'viewer');
  const selectable = cats.filter((c) => c.status === 'approved' || value.catalogIds.includes(c.id));

  return (
    <div className="form-grid">
      <Field label="Assessment name *"><input type="text" value={value.name} onChange={(e) => set('name', e.target.value)} disabled={disabled} maxLength={160} /></Field>
      <Field label="Client alias *" hint="Use an alias, never the client's legal name."><input type="text" value={value.clientAlias} onChange={(e) => set('clientAlias', e.target.value)} disabled={disabled} maxLength={120} /></Field>
      <Field label="Assessment scope" full><textarea value={value.scope} onChange={(e) => set('scope', e.target.value)} disabled={disabled} rows={3} maxLength={4000} /></Field>
      <Field label="Architecture version (client reference)" hint="e.g. HLD 2.3, LLD draft 0.9"><input type="text" value={value.architectureVersion} onChange={(e) => set('architectureVersion', e.target.value)} disabled={disabled} maxLength={60} /></Field>
      <Field label="Reviewer">
        <select value={value.reviewerId} onChange={(e) => set('reviewerId', e.target.value)} disabled={disabled}>
          <option value="">— Unassigned —</option>
          {reviewers.map((u) => <option key={u.id} value={u.id}>{u.displayName}</option>)}
        </select>
      </Field>
      <Field label="Review date"><input type="date" value={value.reviewDate} onChange={(e) => set('reviewDate', e.target.value)} disabled={disabled} /></Field>
      <Field label="Threat modelling methodologies">
        <div className="row gap wrap">
          {(['STRIDE', 'PASTA', 'OCTAVE', 'PROTOTYPE'] as Methodology[]).map((m) => (
            <label key={m} className="check"><input type="checkbox" checked={value.methodologies.includes(m)} onChange={() => set('methodologies', toggle(value.methodologies, m))} disabled={disabled} />{m}</label>
          ))}
        </div>
      </Field>
      <Field label="Control catalogs (approved versions only)" full>
        <div className="stack" style={{ gap: 4 }}>
          {selectable.length === 0 && <span className="muted small">No approved catalogs available. An administrator must import and a reviewer approve a catalog version.</span>}
          {selectable.map((c) => (
            <label key={c.id} className="check">
              <input type="checkbox" checked={value.catalogIds.includes(c.id)} onChange={() => set('catalogIds', toggle(value.catalogIds, c.id))} disabled={disabled || (c.status !== 'approved' && !value.catalogIds.includes(c.id))} />
              <span>{FRAMEWORK_LABELS[c.framework]} — {c.version} {c.isDemo && <span className="badge badge-demo">demo excerpt</span>} {c.status !== 'approved' && <span className="badge badge-danger">{c.status}</span>}</span>
            </label>
          ))}
        </div>
      </Field>
    </div>
  );
}
