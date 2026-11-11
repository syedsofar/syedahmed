import { useEffect, useRef, useState } from 'react';
import { useProject } from '../lib/project';
import { useWorkingModel } from '../lib/model';
import { Callout } from '../components/ui';
import { loadCatalog } from '../components/CatalogPalette';
import { canonicalToDesigner, designerToCanonical, type DesignerModel } from '@shared/designer';
import type { CatalogItem } from '@shared/catalog';

// Hosts the ArchGuard designer editor (served from /designer/). The designer's changes
// are saved to this project's architecture model, so the threat analysis, versions and
// reports see the same diagram.
export function DesignerPage() {
  const { data } = useProject();
  const { model, update, editable } = useWorkingModel();
  const frameRef = useRef<HTMLIFrameElement>(null);
  const [catalog, setCatalog] = useState<CatalogItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const modelRef = useRef(model);
  modelRef.current = model;
  const editableRef = useRef(editable);
  editableRef.current = editable;
  const catalogRef = useRef<CatalogItem[] | null>(null);
  catalogRef.current = catalog;
  const readyRef = useRef(false);
  const projectName = data.project.name;

  const sendInit = () => {
    const frame = frameRef.current?.contentWindow;
    const cat = catalogRef.current;
    if (!frame || !cat || !readyRef.current) return;
    const designer: DesignerModel = canonicalToDesigner(modelRef.current, projectName, cat[0]?.id ?? '');
    frame.postMessage({ type: 'sawb:designer-init', model: designer }, window.location.origin);
  };

  useEffect(() => {
    loadCatalog()
      .then((c) => { setCatalog(c.components); })
      .catch((e) => setError(e instanceof Error ? e.message : 'Could not load the component library.'));
  }, []);

  useEffect(() => { sendInit(); }, [catalog]);

  useEffect(() => {
    const onMessage = (ev: MessageEvent) => {
      if (ev.source !== frameRef.current?.contentWindow || ev.origin !== window.location.origin) return;
      const msg = ev.data as { type?: string; model?: DesignerModel } | null;
      if (msg?.type === 'sawb:designer-ready') { readyRef.current = true; sendInit(); return; }
      if (msg?.type === 'sawb:designer-save' && msg.model) {
        const cat = catalogRef.current;
        if (!cat || !editableRef.current) return;
        const next = designerToCanonical(msg.model, cat, modelRef.current);
        if (JSON.stringify(next) === JSON.stringify(modelRef.current)) return;
        update(() => next);
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
    // sendInit reads refs only, so the listener is attached once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [update]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Designer</h1>
          <div className="sub">The ArchGuard designer editor. Changes save to this project's architecture model, which the threat analysis, versions and reports use.</div>
        </div>
      </div>
      {!editable && <Callout tone="warn">Read-only. Changes made in the designer are not saved.</Callout>}
      {error && <Callout tone="warn">{error}</Callout>}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <iframe ref={frameRef} src="/designer/index.html" title="Architecture designer" onLoad={() => sendInit()}
          style={{ display: 'block', width: '100%', height: '78vh', minHeight: 560, border: 0 }} />
      </div>
    </div>
  );
}
