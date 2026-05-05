import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';
import { SecretsListPage } from "./pages/secrets/SecretsListPage";
import { ProtectedRoute, PublicRoute, Layout } from './components/layout';
import { SessionTimeoutWarning } from './components/ui';
import { LoginPage } from './pages/auth';
import { DashboardPage } from './pages/dashboard';
import { AuditLogPage } from './pages/audit/AuditLogPage';
import { AdminPage } from './pages/admin';
import { ROUTES } from './constants';

function App() {
  const { isLoading } = useAuth();

  // Show loading screen while checking authentication
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
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

        {/* Authenticated routes — all wrapped in Layout for sidebar + header */}
        <Route
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path={ROUTES.DASHBOARD} element={<DashboardPage />} />
                  <Route path={ROUTES.SECRETS} element={<SecretsListPage />} />
                  <Route path={ROUTES.AUDIT} element={<AuditLogPage />} />
                  <Route path={ROUTES.SHARING} element={<div className="p-8 text-gray-500">Sharing — coming soon</div>} />
                  <Route path={ROUTES.PROFILE} element={<div className="p-8 text-gray-500">Profile — coming soon</div>} />
                  <Route path={ROUTES.ADMIN_USERS} element={<AdminPage />} />
                  <Route path={ROUTES.ADMIN} element={<AdminPage />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
          path="/*"
        />

        {/* Default redirect */}
        <Route
          path={ROUTES.HOME}
          element={<Navigate to={ROUTES.DASHBOARD} replace />}
        />

        {/* Catch all route */}
        <Route
          path="*"
          element={
            <div className="min-h-screen bg-gray-50 flex items-center justify-center">
              <div className="text-center">
                <h1 className="text-4xl font-bold text-gray-900 mb-4">404</h1>
                <p className="text-gray-600 mb-4">Page not found</p>
                <a
                  href={ROUTES.DASHBOARD}
                  className="text-blue-600 hover:text-blue-500"
                >
                  Go to Dashboard
                </a>
              </div>
            </div>
          }
        />
      </Routes>

      {/* Session timeout warning */}
      <SessionTimeoutWarning />
    </>
  );
}

export default App;
