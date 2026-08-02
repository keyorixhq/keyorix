import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import App from '../App';
import { useAuth } from '../features/auth';

vi.mock('../features/auth', () => ({ useAuth: vi.fn() }));

// ── Page stubs ────────────────────────────────────────────────────────────────
// Each lazy page is replaced with a minimal stub so React.lazy resolves
// immediately and Suspense never blocks. The stubs' text labels are what
// the tests assert on.

vi.mock('../pages/auth/LoginPage', () => ({ LoginPage: () => <div>Login Page</div> }));
vi.mock('../pages/auth/SetupPage', () => ({ SetupPage: () => <div>Setup Page</div> }));
vi.mock('../pages/auth/SSOCompletePage', () => ({ SSOCompletePage: () => <div>SSO Complete</div> }));
vi.mock('../pages/dashboard/DashboardPage', () => ({ DashboardPage: () => <div>Dashboard Page</div> }));
vi.mock('../pages/secrets/SecretsListPage', () => ({ SecretsListPage: () => <div>Secrets Page</div> }));
vi.mock('../pages/secrets/DynamicSecretsPage', () => ({ default: () => <div>Dynamic Secrets</div> }));
vi.mock('../pages/secrets/RotationPoliciesPage', () => ({
    RotationPoliciesPage: () => <div>Rotation Policies</div>,
}));
vi.mock('../pages/secrets/SecretExpiryPage', () => ({ SecretExpiryPage: () => <div>Secret Expiry</div> }));
vi.mock('../pages/secrets/SecretsHealthPage', () => ({ SecretsHealthPage: () => <div>Secrets Health</div> }));
vi.mock('../pages/secrets/UsageAnalyticsPage', () => ({
    UsageAnalyticsPage: () => <div>Usage Analytics</div>,
}));
vi.mock('../pages/projects/ProjectsListPage', () => ({ ProjectsListPage: () => <div>Projects Page</div> }));
vi.mock('../pages/projects/ProjectDetailPage', () => ({ ProjectDetailPage: () => <div>Project Detail</div> }));
vi.mock('../pages/audit/AuditLogPage', () => ({ AuditLogPage: () => <div>Audit Log</div> }));
vi.mock('../pages/sharing', () => ({ SharingManagementPage: () => <div>Sharing Page</div> }));
vi.mock('../pages/profile', () => ({ ProfilePage: () => <div>Profile Page</div> }));
vi.mock('../pages/admin/AdminPage', () => ({ AdminPage: () => <div>Admin Page</div> }));
vi.mock('../pages/admin/UserDetailPage', () => ({ UserDetailPage: () => <div>User Detail</div> }));
vi.mock('../pages/admin/RolesPoliciesPage', () => ({ RolesPoliciesPage: () => <div>Roles Policies</div> }));
vi.mock('../pages/admin/GroupsPage', () => ({ GroupsPage: () => <div>Groups Page</div> }));
vi.mock('../pages/admin/ServiceAccountsPage', () => ({
    ServiceAccountsPage: () => <div>Service Accounts</div>,
}));
vi.mock('../pages/admin/APITokensPage', () => ({ APITokensPage: () => <div>API Tokens</div> }));
vi.mock('../pages/admin/NotificationChannelsPage', () => ({
    NotificationChannelsPage: () => <div>Notification Channels</div>,
}));
vi.mock('../pages/settings/AppearancePage', () => ({ AppearancePage: () => <div>Appearance</div> }));
vi.mock('../pages/settings/SystemHealthPage', () => ({ SystemHealthPage: () => <div>System Health</div> }));
vi.mock('../pages/compliance/CompliancePage', () => ({ CompliancePage: () => <div>Compliance</div> }));
vi.mock('../pages/integrations/KeyorixConnectPage', () => ({
    KeyorixConnectPage: () => <div>Keyorix Connect</div>,
}));
vi.mock('../pages/integrations/SdksPage', () => ({ SdksPage: () => <div>SDKs & CLI</div> }));
vi.mock('../pages/roadmap/RoadmapPage', () => ({ RoadmapPage: () => <div>Roadmap</div> }));

// ── Layout: real guards + stub Layout ────────────────────────────────────────
// The route guards (ProtectedRoute, PublicRoute, AdminRoute, RequirePasswordChange)
// are kept real so App tests verify that the right guard wraps each route.
// Layout is replaced to avoid rendering Header / Sidebar and their transitive deps.
vi.mock('../components/layout', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../components/layout')>();
    return {
        ...actual,
        Layout: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    };
});

// ── UI: stub shell components with side effects / complex deps ────────────────
vi.mock('../components/ui', () => ({
    SessionTimeoutWarning: () => null,
    AbsoluteSessionExpiryWarning: () => null,
    Spinner: () => <div />,
    ErrorBoundary: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    RouteErrorBoundary: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

// ── Auth helpers ──────────────────────────────────────────────────────────────

const mockUseAuth = vi.mocked(useAuth);

type AuthOverrides = {
    isAuthenticated?: boolean;
    isLoading?: boolean;
    hasCheckedAuth?: boolean;
    user?: { role?: string; passwordChangeRequired?: boolean; permissions?: string[] } | null;
};

function setAuth({
    isAuthenticated = false,
    isLoading = false,
    hasCheckedAuth = true,
    user = null,
}: AuthOverrides = {}) {
    mockUseAuth.mockReturnValue({
        user,
        isAuthenticated,
        isLoading,
        hasCheckedAuth,
        hasPermission: (p: string) => (user?.permissions ?? []).includes(p),
    } as unknown as ReturnType<typeof useAuth>);
}

const renderAt = (path: string) =>
    render(
        <MemoryRouter initialEntries={[path]}>
            <App />
        </MemoryRouter>
    );

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('App', () => {
    beforeEach(() => {
        mockUseAuth.mockReset();
    });

    describe('auth bootstrap', () => {
        it('shows the route-guard loading indicator while the auth check is in flight', () => {
            setAuth({ isLoading: true, hasCheckedAuth: false });
            renderAt('/dashboard');
            // ProtectedRoute renders its own spinner synchronously — no Suspense involved.
            expect(screen.getByText('Loading...')).toBeInTheDocument();
        });
    });

    describe('public routes', () => {
        it('renders the login page to an unauthenticated visitor', async () => {
            setAuth();
            renderAt('/login');
            expect(await screen.findByText('Login Page')).toBeInTheDocument();
        });

        it('redirects an already-authenticated visitor from /login to the dashboard', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/login');
            expect(await screen.findByText('Dashboard Page')).toBeInTheDocument();
        });

        it('renders the account-setup page without auth', async () => {
            setAuth();
            renderAt('/auth/setup/abc-token');
            expect(await screen.findByText('Setup Page')).toBeInTheDocument();
        });

        it('renders the SSO complete page without auth', async () => {
            setAuth();
            renderAt('/auth/sso/complete');
            expect(await screen.findByText('SSO Complete')).toBeInTheDocument();
        });
    });

    describe('protected routes', () => {
        it('redirects unauthenticated users to /login', async () => {
            setAuth();
            renderAt('/dashboard');
            expect(await screen.findByText('Login Page')).toBeInTheDocument();
        });

        it('renders /dashboard for an authenticated user', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/dashboard');
            expect(await screen.findByText('Dashboard Page')).toBeInTheDocument();
        });

        it('renders /secrets for an authenticated user', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/secrets');
            expect(await screen.findByText('Secrets Page')).toBeInTheDocument();
        });

        it('renders /profile for an authenticated user', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/profile');
            expect(await screen.findByText('Profile Page')).toBeInTheDocument();
        });

        it('renders /audit for an authenticated user', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/audit');
            expect(await screen.findByText('Audit Log')).toBeInTheDocument();
        });

        it('renders /integrations/sdks for an authenticated user', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/integrations/sdks');
            expect(await screen.findByText('SDKs & CLI')).toBeInTheDocument();
        });
    });

    describe('admin routes', () => {
        it('renders /admin for an admin user', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'admin' } });
            renderAt('/admin');
            expect(await screen.findByText('Admin Page')).toBeInTheDocument();
        });

        it('accepts system_admin as an admin role', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'system_admin' } });
            renderAt('/admin');
            expect(await screen.findByText('Admin Page')).toBeInTheDocument();
        });

        it('redirects a non-admin to the dashboard from /admin', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/admin');
            expect(await screen.findByText('Dashboard Page')).toBeInTheDocument();
        });

        it('renders /admin/users for an admin', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'admin' } });
            renderAt('/admin/users');
            expect(await screen.findByText('Admin Page')).toBeInTheDocument();
        });

        it('renders /admin/roles for an admin', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'admin' } });
            renderAt('/admin/roles');
            expect(await screen.findByText('Roles Policies')).toBeInTheDocument();
        });

        it('renders /admin/notification-channels for an admin', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'admin' } });
            renderAt('/admin/notification-channels');
            expect(await screen.findByText('Notification Channels')).toBeInTheDocument();
        });

        it('redirects a non-admin to the dashboard from /admin/notification-channels', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/admin/notification-channels');
            expect(await screen.findByText('Dashboard Page')).toBeInTheDocument();
        });

        it('renders /settings/health for an admin', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'admin' } });
            renderAt('/settings/health');
            expect(await screen.findByText('System Health')).toBeInTheDocument();
        });

        it('redirects a non-admin to the dashboard from /settings/health', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/settings/health');
            expect(await screen.findByText('Dashboard Page')).toBeInTheDocument();
        });
    });

    describe('RequirePasswordChange gate', () => {
        it('redirects a user with passwordChangeRequired to /profile', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user', passwordChangeRequired: true } });
            renderAt('/dashboard');
            expect(await screen.findByText('Profile Page')).toBeInTheDocument();
        });

        it('lets a user with passwordChangeRequired stay on /profile', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user', passwordChangeRequired: true } });
            renderAt('/profile');
            expect(await screen.findByText('Profile Page')).toBeInTheDocument();
        });

        it('does not redirect a user without the flag', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user', passwordChangeRequired: false } });
            renderAt('/dashboard');
            expect(await screen.findByText('Dashboard Page')).toBeInTheDocument();
        });
    });

    describe('root and catch-all', () => {
        it('redirects / to /dashboard for an authenticated user', async () => {
            setAuth({ isAuthenticated: true, user: { role: 'user' } });
            renderAt('/');
            expect(await screen.findByText('Dashboard Page')).toBeInTheDocument();
        });

        it('redirects / to /login for an unauthenticated user', async () => {
            setAuth();
            renderAt('/');
            expect(await screen.findByText('Login Page')).toBeInTheDocument();
        });
    });
});
