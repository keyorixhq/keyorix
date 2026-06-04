import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './features/auth';
import { SecretsListPage } from "./pages/secrets/SecretsListPage";
import { SecretExpiryPage, SecretsHealthPage, RotationPoliciesPage } from "./pages/secrets";
import { ProjectsListPage, ProjectDetailPage } from './pages/projects';
import { ProtectedRoute, PublicRoute, AdminRoute, Layout } from './components/layout';
import { SessionTimeoutWarning } from './components/ui';
import { LoginPage } from './pages/auth';
import { DashboardPage } from './pages/dashboard';
import { AuditLogPage } from './pages/audit/AuditLogPage';
import { AdminPage, RolesPoliciesPage, GroupsPage, ServiceAccountsPage, APITokensPage } from './pages/admin';
import { AppearancePage } from './pages/settings/AppearancePage';
import { CompliancePage } from './pages/compliance/CompliancePage';
import { KeyorixConnectPage } from './pages/integrations/KeyorixConnectPage';
import { RoadmapPage } from './pages/roadmap/RoadmapPage';
import { ProfilePage } from './pages/profile';
import { ROUTES } from './constants';

function App() {
  const { isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg-app)' }}>
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p style={{ color: 'var(--text-secondary)' }}>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <>
      <Routes>
        {/* Public Routes */}
        <Route
          path={ROUTES.LOGIN}
          element={
            <PublicRoute>
              <LoginPage />
            </PublicRoute>
          }
        />

        {/* Authenticated routes */}
        <Route
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path={ROUTES.DASHBOARD} element={<DashboardPage />} />
                  <Route path={ROUTES.SECRETS} element={<SecretsListPage />} />
                  <Route path="/secrets/dynamic" element={<div className="p-8" style={{ color: 'var(--text-muted)' }}>Dynamic Secrets — coming soon</div>} />
                  <Route path="/secrets/rotation" element={<RotationPoliciesPage />} />
                  <Route path="/secrets/expiry" element={<SecretExpiryPage />} />
                  <Route path="/secrets/health" element={<SecretsHealthPage />} />
                  {/* Projects hierarchy */}
                  <Route path={ROUTES.PROJECTS} element={<ProjectsListPage />} />
                  <Route path="/projects/:id/*" element={<ProjectDetailPage />} />
                  {/* Other */}
                  <Route path={ROUTES.AUDIT} element={<AuditLogPage />} />
                  <Route path={ROUTES.SHARING} element={<div className="p-8" style={{ color: 'var(--text-muted)' }}>Sharing — coming soon</div>} />
                  <Route path={ROUTES.PROFILE} element={<ProfilePage />} />
                  {/* Access Control (admin-only) */}
                  <Route path={ROUTES.ADMIN_USERS} element={<AdminRoute><AdminPage /></AdminRoute>} />
                  <Route path={ROUTES.ADMIN} element={<AdminRoute><AdminPage /></AdminRoute>} />
                  <Route path="/admin/roles" element={<AdminRoute><RolesPoliciesPage /></AdminRoute>} />
                  <Route path="/admin/groups" element={<AdminRoute><GroupsPage /></AdminRoute>} />
                  <Route path="/admin/service-accounts" element={<AdminRoute><ServiceAccountsPage /></AdminRoute>} />
                  <Route path="/admin/api-tokens" element={<AdminRoute><APITokensPage /></AdminRoute>} />
                  <Route path="/settings/appearance" element={<AppearancePage />} />
                  <Route path={ROUTES.COMPLIANCE} element={<CompliancePage />} />
                  <Route path={ROUTES.CONNECT} element={<KeyorixConnectPage />} />
                  <Route path={ROUTES.ROADMAP} element={<RoadmapPage />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
          path="/*"
        />

        {/* Default redirect */}
        <Route path={ROUTES.HOME} element={<Navigate to={ROUTES.DASHBOARD} replace />} />

        {/* Catch all */}
        <Route
          path="*"
          element={
            <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg-app)' }}>
              <div className="text-center">
                <h1 className="text-4xl font-bold mb-4" style={{ color: 'var(--text-primary)' }}>404</h1>
                <p className="mb-4" style={{ color: 'var(--text-secondary)' }}>Page not found</p>
                <a href={ROUTES.DASHBOARD} style={{ color: 'var(--accent)' }}>
                  Go to Dashboard
                </a>
              </div>
            </div>
          }
        />
      </Routes>

      <SessionTimeoutWarning />
    </>
  );
}

export default App;
