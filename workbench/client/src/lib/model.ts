import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';
import { useProject } from './project';
import type { ArchitectureModel } from '@shared/types';

export type SaveState = 'saved' | 'pending' | 'saving' | 'error' | 'readonly';

/** Local working copy of the project's canonical model with debounced autosave and undo. */
export function useWorkingModel() {
  const { data, setData, can } = useProject();
  const editable = can('model:edit');
  const [model, setModel] = useState<ArchitectureModel>(data.model);
  const [state, setState] = useState<SaveState>(editable ? 'saved' : 'readonly');
  const [error, setError] = useState('');
  const undo = useRef<ArchitectureModel[]>([]);
  const timer = useRef<number | null>(null);
  const latest = useRef(model);
  const dataRef = useRef(data);
  dataRef.current = data;

  const save = useCallback(async () => {
    timer.current = null;
    setState('saving');
    try {
      await api.put(`/projects/${dataRef.current.project.id}/model`, { model: latest.current });
      setData({ ...dataRef.current, model: latest.current });
      setState('saved');
      setError('');
    } catch (e) {
      setState('error');
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [setData]);

  const flush = useCallback(async () => {
    if (timer.current) { window.clearTimeout(timer.current); await save(); }
  }, [save]);

  useEffect(() => () => { if (timer.current) { window.clearTimeout(timer.current); void save(); } }, [save]);

  /** Apply a change. `transient` changes (e.g. during a drag) do not push undo history. */
  const update = useCallback((fn: (m: ArchitectureModel) => ArchitectureModel, opts: { transient?: boolean; snapshot?: ArchitectureModel } = {}) => {
    if (!editable) return;
    setModel((prev) => {
      const next = fn(prev);
      if (!opts.transient) {
        undo.current.push(opts.snapshot ?? prev);
        if (undo.current.length > 60) undo.current.shift();
      }
      latest.current = next;
      return next;
    });
    setState('pending');
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(save, 700);
  }, [editable, save]);

  const pushUndo = (m: ArchitectureModel) => { undo.current.push(m); };

  const doUndo = useCallback(() => {
    const prev = undo.current.pop();
    if (!prev) return;
    latest.current = prev;
    setModel(prev);
    setState('pending');
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(save, 400);
  }, [save]);

  /** Replace the local copy with the server's (after restore etc.). */
  const reset = useCallback((m: ArchitectureModel) => { undo.current = []; latest.current = m; setModel(m); setState(editable ? 'saved' : 'readonly'); }, [editable]);

  return { model, update, state, error, editable, undo: doUndo, canUndo: undo.current.length > 0, flush, reset, pushUndo };
}
