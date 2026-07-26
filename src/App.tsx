import React, { Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './features/auth';
import { ProtectedRoute, PublicRoute, AdminRoute, Layout, RequirePasswordChange } from './components/layout';
import {
    SessionTimeoutWarning,
    AbsoluteSessionExpiryWarning,
    Spinner,
    ErrorBoundary,
    RouteErrorBoundary,
} from './components/ui';
import { ROUTES } from './constants';

// ── Page-level lazy bundles ───────────────────────────────────────────────────
// Each route gets its own chunk; the core shell (guards, layout, stores) stays
// in the initial bundle and is never re-fetched.

const LoginPage = React.lazy(() => import('./pages/auth/LoginPage').then((m) => ({ default: m.LoginPage })));
const SetupPage = React.lazy(() => import('./pages/auth/SetupPage').then((m) => ({ default: m.SetupPage })));
const SSOCompletePage = React.lazy(() =>
    import('./pages/auth/SSOCompletePage').then((m) => ({ default: m.SSOCompletePage }))
);

const DashboardPage = React.lazy(() =>
    import('./pages/dashboard/DashboardPage').then((m) => ({ default: m.DashboardPage }))
);

const SecretsListPage = React.lazy(() =>
    import('./pages/secrets/SecretsListPage').then((m) => ({ default: m.SecretsListPage }))
);
const DynamicSecretsPage = React.lazy(() => import('./pages/secrets/DynamicSecretsPage'));
const RotationPoliciesPage = React.lazy(() =>
    import('./pages/secrets/RotationPoliciesPage').then((m) => ({ default: m.RotationPoliciesPage }))
);
const SecretExpiryPage = React.lazy(() =>
    import('./pages/secrets/SecretExpiryPage').then((m) => ({ default: m.SecretExpiryPage }))
);
const SecretsHealthPage = React.lazy(() =>
    import('./pages/secrets/SecretsHealthPage').then((m) => ({ default: m.SecretsHealthPage }))
);
const UsageAnalyticsPage = React.lazy(() =>
    import('./pages/secrets/UsageAnalyticsPage').then((m) => ({ default: m.UsageAnalyticsPage }))
);

const ProjectsListPage = React.lazy(() =>
    import('./pages/projects/ProjectsListPage').then((m) => ({ default: m.ProjectsListPage }))
);
const ProjectDetailPage = React.lazy(() =>
    import('./pages/projects/ProjectDetailPage').then((m) => ({ default: m.ProjectDetailPage }))
);

const AuditLogPage = React.lazy(() => import('./pages/audit/AuditLogPage').then((m) => ({ default: m.AuditLogPage })));
const SharingManagementPage = React.lazy(() =>
    import('./pages/sharing').then((m) => ({ default: m.SharingManagementPage }))
);
const ProfilePage = React.lazy(() => import('./pages/profile').then((m) => ({ default: m.ProfilePage })));

const AdminPage = React.lazy(() => import('./pages/admin/AdminPage').then((m) => ({ default: m.AdminPage })));
const UserDetailPage = React.lazy(() =>
    import('./pages/admin/UserDetailPage').then((m) => ({ default: m.UserDetailPage }))
);
const RolesPoliciesPage = React.lazy(() =>
    import('./pages/admin/RolesPoliciesPage').then((m) => ({ default: m.RolesPoliciesPage }))
);
const GroupsPage = React.lazy(() => import('./pages/admin/GroupsPage').then((m) => ({ default: m.GroupsPage })));
const ServiceAccountsPage = React.lazy(() =>
    import('./pages/admin/ServiceAccountsPage').then((m) => ({ default: m.ServiceAccountsPage }))
);
const APITokensPage = React.lazy(() =>
    import('./pages/admin/APITokensPage').then((m) => ({ default: m.APITokensPage }))
);

const AppearancePage = React.lazy(() =>
    import('./pages/settings/AppearancePage').then((m) => ({ default: m.AppearancePage }))
);
const CompliancePage = React.lazy(() =>
    import('./pages/compliance/CompliancePage').then((m) => ({ default: m.CompliancePage }))
);
const KeyorixConnectPage = React.lazy(() =>
    import('./pages/integrations/KeyorixConnectPage').then((m) => ({ default: m.KeyorixConnectPage }))
);
const RoadmapPage = React.lazy(() => import('./pages/roadmap/RoadmapPage').then((m) => ({ default: m.RoadmapPage })));

// ── Route fallback ────────────────────────────────────────────────────────────

const PageSpinner = () => (
    <div className="min-h-screen flex items-center justify-center">
        <Spinner size="lg" />
    </div>
);

function App() {
    useAuth();

    return (
        <ErrorBoundary>
            <Suspense fallback={<PageSpinner />}>
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

                    <Route path="/auth/setup/:token" element={<SetupPage />} />
                    <Route path="/auth/sso/complete" element={<SSOCompletePage />} />

                    {/* Authenticated routes */}
                    <Route
                        element={
                            <ProtectedRoute>
                                <RequirePasswordChange>
                                    <Layout>
                                        <RouteErrorBoundary>
                                            <Routes>
                                                <Route path={ROUTES.DASHBOARD} element={<DashboardPage />} />
                                                <Route path={ROUTES.SECRETS} element={<SecretsListPage />} />
                                                <Route path="/secrets/dynamic" element={<DynamicSecretsPage />} />
                                                <Route path="/secrets/rotation" element={<RotationPoliciesPage />} />
                                                <Route path="/secrets/expiry" element={<SecretExpiryPage />} />
                                                <Route path="/secrets/health" element={<SecretsHealthPage />} />
                                                <Route path="/secrets/usage" element={<UsageAnalyticsPage />} />
                                                <Route path={ROUTES.PROJECTS} element={<ProjectsListPage />} />
                                                <Route path="/projects/:id/*" element={<ProjectDetailPage />} />
                                                <Route path={ROUTES.AUDIT} element={<AuditLogPage />} />
                                                <Route path={ROUTES.SHARING} element={<SharingManagementPage />} />
                                                <Route path={ROUTES.PROFILE} element={<ProfilePage />} />
                                                <Route
                                                    path={ROUTES.ADMIN_USERS}
                                                    element={
                                                        <AdminRoute>
                                                            <AdminPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/users/:id"
                                                    element={
                                                        <AdminRoute>
                                                            <UserDetailPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path={ROUTES.ADMIN}
                                                    element={
                                                        <AdminRoute>
                                                            <AdminPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/roles"
                                                    element={
                                                        <AdminRoute>
                                                            <RolesPoliciesPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/groups"
                                                    element={
                                                        <AdminRoute>
                                                            <GroupsPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/service-accounts"
                                                    element={
                                                        <AdminRoute>
                                                            <ServiceAccountsPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/api-tokens"
                                                    element={
                                                        <AdminRoute>
                                                            <APITokensPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route path="/settings/appearance" element={<AppearancePage />} />
                                                <Route path={ROUTES.COMPLIANCE} element={<CompliancePage />} />
                                                <Route path={ROUTES.CONNECT} element={<KeyorixConnectPage />} />
                                                <Route path={ROUTES.ROADMAP} element={<RoadmapPage />} />
                                            </Routes>
                                        </RouteErrorBoundary>
                                    </Layout>
                                </RequirePasswordChange>
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
                            <div className="min-h-screen flex items-center justify-center bg-app">
                                <div className="text-center">
                                    <h1 className="text-4xl font-bold mb-4 text-[var(--text-primary)]">404</h1>
                                    <p className="mb-4 text-[var(--text-secondary)]">Page not found</p>
                                    <a href={ROUTES.DASHBOARD} className="text-[var(--accent)]">
                                        Go to Dashboard
                                    </a>
                                </div>
                            </div>
                        }
                    />
                </Routes>
            </Suspense>

            <SessionTimeoutWarning />
            <AbsoluteSessionExpiryWarning />
        </ErrorBoundary>
    );
}

export default App;
