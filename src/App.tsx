import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';
import { SecretsListPage } from "./pages/secrets/SecretsListPage";
import { ProtectedRoute, PublicRoute, AdminRoute } from './components/layout';
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

        {/* Protected Routes */}
        <Route
          path={ROUTES.DASHBOARD}
          element={
            <ProtectedRoute>
              <DashboardPage />
            </ProtectedRoute>
          }
        />

        {/* Admin Routes */}
        <Route
          path={ROUTES.ADMIN}
          element={
            <AdminRoute>
              <AdminPage />
            </AdminRoute>
          }
        />

        <Route
          path={ROUTES.AUDIT}
          element={
            <ProtectedRoute>
              <AuditLogPage />
            </ProtectedRoute>
          }
        />

        {/* Placeholder routes for future implementation */}
        <Route
          path={ROUTES.SECRETS}
          element={
            <ProtectedRoute>
              <SecretsListPage />
            </ProtectedRoute>
          }
        />

        <Route
          path={ROUTES.SHARING}
          element={
            <ProtectedRoute>
              <div className="min-h-screen bg-gray-50 flex items-center justify-center">
                <div className="text-center">
                  <h1 className="text-2xl font-bold text-gray-900 mb-4">Sharing Management</h1>
                  <p className="text-gray-600">Sharing features will be implemented in subsequent tasks</p>
                </div>
              </div>
            </ProtectedRoute>
          }
        />

        <Route
          path={ROUTES.PROFILE}
          element={
            <ProtectedRoute>
              <div className="min-h-screen bg-gray-50 flex items-center justify-center">
                <div className="text-center">
                  <h1 className="text-2xl font-bold text-gray-900 mb-4">User Profile</h1>
                  <p className="text-gray-600">Profile features will be implemented in subsequent tasks</p>
                </div>
              </div>
            </ProtectedRoute>
          }
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
