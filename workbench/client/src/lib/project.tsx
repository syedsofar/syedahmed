import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { useParams } from 'react-router-dom';
import { api } from './api';
import { useAuth } from './auth';
import { useToast } from '../components/ui';
import type { ProjectData, ProjectRole } from '@shared/types';

export type LoadedProject = ProjectData & { myRole: ProjectRole | 'admin' | null };

interface ProjectCtx {
  data: LoadedProject;
  setData: (d: ProjectData) => void;
  reload: () => Promise<void>;
  /** True when the user's global role AND project membership allow the permission. */
  can: (perm: string) => boolean;
  readOnly: boolean;
  /** Run an API call that returns the updated ProjectData; toasts errors. Returns success. */
  mutate: (fn: () => Promise<ProjectData>, okMsg?: string) => Promise<boolean>;
}

const Ctx = createContext<ProjectCtx | null>(null);

const WRITE = ['project:edit', 'model:edit', 'threat:edit', 'control:edit', 'risk:edit', 'risk:approve', 'evidence:upload', 'evidence:approve_ai', 'report:export'];

export function ProjectProvider({ children }: { children: ReactNode }) {
  const { projectId } = useParams();
  const auth = useAuth();
  const toast = useToast();
  const [data, setRaw] = useState<LoadedProject | null>(null);
  const [error, setError] = useState('');

  const reload = useCallback(async () => {
    try {
      setRaw(await api.get<LoadedProject>(`/projects/${projectId}`));
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [projectId]);

  useEffect(() => {
    setRaw(null);
    reload();
  }, [reload]);

  if (error) return <div className="page"><div className="callout callout-danger">{error}</div></div>;
  if (!data) return <div className="page"><div className="loading">Loading assessment…</div></div>;

  const role = data.myRole;
  const archived = data.project.status === 'archived';
  const can = (perm: string) => {
    if (!auth.can(perm) || !role) return false;
    if (role === 'admin') return !(archived && perm !== 'project:edit' && perm !== 'report:export');
    if (perm === 'member:manage' || perm === 'project:delete') return role === 'owner';
    if (WRITE.includes(perm)) {
      if (archived && perm !== 'project:edit' && perm !== 'report:export') return false;
      return role === 'owner' || role === 'editor';
    }
    return true;
  };
  const setData = (d: ProjectData) => setRaw({ ...d, myRole: role });
  const mutate = async (fn: () => Promise<ProjectData>, okMsg?: string) => {
    try {
      setData(await fn());
      if (okMsg) toast.ok(okMsg);
      return true;
    } catch (e) {
      toast.error(e);
      return false;
    }
  };

  return <Ctx.Provider value={{ data, setData, reload, can, readOnly: !can('model:edit'), mutate }}>{children}</Ctx.Provider>;
}

export function useProject() {
  const c = useContext(Ctx);
  if (!c) throw new Error('ProjectProvider missing');
  return c;
}
