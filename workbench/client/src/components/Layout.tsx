import { Boxes } from 'lucide-react';
import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useMatch, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, FolderKanban, Network, FileInput, ShieldAlert, ListChecks, Gauge, FileText, BookMarked, Users, ScrollText,
  Settings, LogOut, Menu, ShieldCheck, Info, KeyRound,
} from 'lucide-react';
import { useAuth } from '../lib/auth';
import { api } from '../lib/api';
import { ROLE_LABELS } from '@shared/schema';

interface ProjLite { id: string; name: string; isDemo: boolean }

export function Layout() {
  const { session, logout, can } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const match = useMatch('/projects/:projectId/*');
  const pid = match?.params.projectId;
  const [open, setOpen] = useState(false);
  const [proj, setProj] = useState<ProjLite | null>(null);

  useEffect(() => setOpen(false), [loc.pathname]);
  useEffect(() => {
    if (!pid) { setProj(null); return; }
    api.get<ProjLite>(`/projects/${pid}`).then((d: unknown) => {
      const p = (d as { project: ProjLite }).project;
      setProj({ id: p.id, name: p.name, isDemo: p.isDemo });
    }).catch(() => setProj(null));
  }, [pid]);

  const demo = session?.environment === 'demonstration';
  const item = (to: string, icon: JSX.Element, label: string, end = false) => (
    <NavLink to={to} end={end} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
      {icon}<span>{label}</span>
    </NavLink>
  );

  return (
    <div className={`shell ${open ? 'nav-open' : ''}`}>
      <aside className="sidebar" aria-label="Main navigation">
        <div className="brand">
          <ShieldCheck size={26} />
          <div>
            <div className="brand-name">Security Architecture</div>
            <div className="brand-sub">Review &amp; Threat Modeling Workbench</div>
          </div>
        </div>
        <nav>
          <div className="nav-group">Workspace</div>
          {item('/', <LayoutDashboard size={18} />, 'Dashboard', true)}
          {item('/projects', <FolderKanban size={18} />, 'Assessments', true)}
          {pid && (
            <>
              <div className="nav-group nav-project" title={proj?.name}>{proj ? proj.name : 'Assessment'}</div>
              {item(`/projects/${pid}`, <Info size={18} />, 'Overview', true)}
              {item(`/projects/${pid}/architecture`, <Network size={18} />, 'Architecture')}
              {item(`/projects/${pid}/designer`, <Boxes size={18} />, 'Designer')}
              {item(`/projects/${pid}/imports`, <FileInput size={18} />, 'Imports & evidence')}
              {item(`/projects/${pid}/threats`, <ShieldAlert size={18} />, 'Threat model')}
              {item(`/projects/${pid}/controls`, <ListChecks size={18} />, 'Control review')}
              {item(`/projects/${pid}/risks`, <Gauge size={18} />, 'Risk register')}
              {item(`/projects/${pid}/reports`, <FileText size={18} />, 'Reports')}
            </>
          )}
          <div className="nav-group">Governance</div>
          {item('/catalogs', <BookMarked size={18} />, 'Control catalogs')}
          {can('user:manage') && item('/users', <Users size={18} />, 'Users & roles')}
          {can('audit:read_all') && item('/audit', <ScrollText size={18} />, 'Audit trail')}
          {item('/settings', <Settings size={18} />, 'Environment & AI')}
        </nav>
        <div className="sidebar-foot">
          <div className="me">
            <div className="avatar">{session?.user.displayName.slice(0, 1)}</div>
            <div>
              <div className="me-name">{session?.user.displayName}</div>
              <div className="me-role">{ROLE_LABELS[session?.user.role ?? 'viewer']}</div>
            </div>
          </div>
          <div className="row gap-s">
            <button className="btn btn-ghost-light btn-sm" onClick={() => nav('/account')}><KeyRound size={14} /> Account</button>
            <button className="btn btn-ghost-light btn-sm" onClick={async () => { await logout(); nav('/'); }}><LogOut size={14} /> Sign out</button>
          </div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="icon-btn mobile-only" onClick={() => setOpen(!open)} aria-label="Toggle navigation"><Menu size={20} /></button>
          {demo ? (
            <div className="env-banner env-demo" role="note">
              <strong>Demonstration environment.</strong> Use synthetic or sanitised data only. External AI services are disabled.
            </div>
          ) : (
            <div className="env-banner env-prod">Production environment — client-confidential handling applies.</div>
          )}
        </header>
        <Outlet />
      </div>
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
    </div>
  );
}
