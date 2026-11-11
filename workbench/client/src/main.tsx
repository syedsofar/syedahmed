import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes, Outlet } from 'react-router-dom';
import './styles.css';
import { AuthProvider, useAuth } from './lib/auth';
import { ProjectProvider } from './lib/project';
import { ToastProvider } from './components/ui';
import { Layout } from './components/Layout';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { ProjectsPage } from './pages/ProjectsPage';
import { OverviewPage } from './pages/OverviewPage';
import { ArchitecturePage } from './pages/ArchitecturePage';
import { ImportsPage } from './pages/ImportsPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { ControlsPage } from './pages/ControlsPage';
import { DesignerPage } from './pages/DesignerPage';
import { RisksPage } from './pages/RisksPage';
import { ReportsPage } from './pages/ReportsPage';
import { CatalogsPage } from './pages/CatalogsPage';
import { UsersPage } from './pages/UsersPage';
import { AuditPage } from './pages/AuditPage';
import { SettingsPage } from './pages/SettingsPage';
import { AccountPage } from './pages/AccountPage';

function Gate() {
  const { session, loading } = useAuth();
  if (loading) return <div className="loading full">Loading…</div>;
  if (!session) return <LoginPage />;
  if (session.mustChangePassword) return <AccountPage forced />;
  return <Layout />;
}

function ProjectScope() {
  return (
    <ProjectProvider>
      <Outlet />
    </ProjectProvider>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ToastProvider>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<Gate />}>
              <Route index element={<DashboardPage />} />
              <Route path="projects" element={<ProjectsPage />} />
              <Route path="projects/:projectId" element={<ProjectScope />}>
                <Route index element={<OverviewPage />} />
                <Route path="architecture" element={<ArchitecturePage />} />
                <Route path="designer" element={<DesignerPage />} />
                <Route path="imports" element={<ImportsPage />} />
                <Route path="threats" element={<ThreatsPage />} />
                <Route path="controls" element={<ControlsPage />} />
                <Route path="risks" element={<RisksPage />} />
                <Route path="reports" element={<ReportsPage />} />
              </Route>
              <Route path="catalogs" element={<CatalogsPage />} />
              <Route path="users" element={<UsersPage />} />
              <Route path="audit" element={<AuditPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="account" element={<AccountPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ToastProvider>
  </StrictMode>,
);
