import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ProtectedRoute, PublicRoute, AdminRoute } from '../components/layout';
import { useAuth } from '../hooks/useAuth';
import { ROUTES } from '../constants';

// Mock the useAuth hook
vi.mock('../hooks/useAuth');

const mockUseAuth = vi.mocked(useAuth);

// Test components
const LoginPage = () => <div>Login Page</div>;
const DashboardPage = () => <div>Dashboard Page</div>;
const AdminPage = () => <div>Admin Page</div>;
const SecretsPage = () => <div>Secrets Page</div>;

// Test wrapper with all providers
const TestWrapper = ({ children }: { children: React.ReactNode }) => {
    const queryClient = new QueryClient({
        defaultOptions: {
            queries: { retry: false },
            mutations: { retry: false },
        },
    });

    return (
        <QueryClientProvider client={queryClient}>
            <BrowserRouter>{children}</BrowserRouter>
        </QueryClientProvider>
    );
};

// Test app with routes
const TestApp = () => (
    <Routes>
        <Route
            path={ROUTES.LOGIN}
            element={
                <PublicRoute>
                    <LoginPage />
                </PublicRoute>
            }
        />
        <Route
            path={ROUTES.DASHBOARD}
            element={
                <ProtectedRoute>
                    <DashboardPage />
                </ProtectedRoute>
            }
        />
        <Route
            path={ROUTES.SECRETS}
            element={
                <ProtectedRoute>
                    <SecretsPage />
                </ProtectedRoute>
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
        <Route path="/" element={<div>Home</div>} />
    </Routes>
);

describe('Authentication Integration', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Clear localStorage
        localStorage.clear();
    });

    it('shows loading state during authentication check', async () => {
        mockUseAuth.mockReturnValue({
            isAuthenticated: false,
            isLoading: true,
            user: null,
            token: null,
            error: null,
            login: vi.fn(),
            logout: vi.fn(),
            refreshToken: vi.fn(),
            checkAuth: vi.fn(),
            clearError: vi.fn(),
            isAdmin: false,
            permissions: [],
            hasPermission: vi.fn().mockReturnValue(false),
        });

        render(
            <TestWrapper>
                <TestApp />
            </TestWrapper>
        );

        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('redirects unauthenticated users to login', async () => {
        mockUseAuth.mockReturnValue({
            isAuthenticated: false,
            isLoading: false,
            user: null,
            token: null,
            error: null,
            login: vi.fn(),
            logout: vi.fn(),
            refreshToken: vi.fn(),
            checkAuth: vi.fn(),
            clearError: vi.fn(),
            isAdmin: false,
            permissions: [],
            hasPermission: vi.fn().mockReturnValue(false),
        });

        // Mock window.location for navigation testing
        delete (window as any).location;
        window.location = { pathname: ROUTES.DASHBOARD } as any;

        render(
            <TestWrapper>
                <TestApp />
            </TestWrapper>
        );

        // Should not show protected content
        expect(screen.queryByText('Dashboard Page')).not.toBeInTheDocument();
        expect(screen.queryByText('Secrets Page')).not.toBeInTheDocument();
        expect(screen.queryByText('Admin Page')).not.toBeInTheDocument();
    });

    it('allows authenticated users to access protected routes', async () => {
        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'testuser',
                email: 'test@example.com',
                role: 'user',
                permissions: ['secrets:read', 'secrets:write'],
                preferences: {
                    language: 'en',
                    timezone: 'UTC',
                    theme: 'light',
                    notifications: {
                        email: true,
                        browser: true,
                        sharing: true,
                        security: true,
                    },
                },
                lastLogin: '2024-01-01T00:00:00Z',
            },
            token: 'mock-token',
            error: null,
            login: vi.fn(),
            logout: vi.fn(),
            refreshToken: vi.fn(),
            checkAuth: vi.fn(),
            clearError: vi.fn(),
            isAdmin: false,
            permissions: ['secrets:read', 'secrets:write'],
            hasPermission: vi.fn().mockReturnValue(true),
        });

        // Mock window.location for navigation testing
        delete (window as any).location;
        window.location = { pathname: ROUTES.DASHBOARD } as any;

        render(
            <TestWrapper>
                <TestApp />
            </TestWrapper>
        );

        await waitFor(() => {
            expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
        });
    });

    it('restricts admin routes to admin users only', async () => {
        // Test with regular user
        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'testuser',
                email: 'test@example.com',
                role: 'user',
                permissions: ['secrets:read', 'secrets:write'],
                preferences: {
                    language: 'en',
                    timezone: 'UTC',
                    theme: 'light',
                    notifications: {
                        email: true,
                        browser: true,
                        sharing: true,
                        security: true,
                    },
                },
                lastLogin: '2024-01-01T00:00:00Z',
            },
            token: 'mock-token',
            error: null,
            login: vi.fn(),
            logout: vi.fn(),
            refreshToken: vi.fn(),
            checkAuth: vi.fn(),
            clearError: vi.fn(),
            isAdmin: false,
            permissions: ['secrets:read', 'secrets:write'],
            hasPermission: vi.fn().mockReturnValue(true),
        });

        // Mock window.location for navigation testing
        delete (window as any).location;
        window.location = { pathname: ROUTES.ADMIN } as any;

        render(
            <TestWrapper>
                <TestApp />
            </TestWrapper>
        );

        // Should not show admin content
        expect(screen.queryByText('Admin Page')).not.toBeInTheDocument();
    });

    it('allows admin users to access admin routes', async () => {
        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'admin',
                email: 'admin@example.com',
                role: 'admin',
                permissions: ['secrets:read', 'secrets:write', 'admin:write', 'system:admin'],
                preferences: {
                    language: 'en',
                    timezone: 'UTC',
                    theme: 'light',
                    notifications: {
                        email: true,
                        browser: true,
                        sharing: true,
                        security: true,
                    },
                },
                lastLogin: '2024-01-01T00:00:00Z',
            },
            token: 'mock-token',
            error: null,
            login: vi.fn(),
            logout: vi.fn(),
            refreshToken: vi.fn(),
            checkAuth: vi.fn(),
            clearError: vi.fn(),
            isAdmin: true,
            permissions: ['secrets:read', 'secrets:write', 'admin:write', 'system:admin'],
            hasPermission: vi.fn().mockReturnValue(true),
        });

        // Mock window.location for navigation testing
        delete (window as any).location;
        window.location = { pathname: ROUTES.ADMIN } as any;

        render(
            <TestWrapper>
                <TestApp />
            </TestWrapper>
        );

        await waitFor(() => {
            expect(screen.getByText('Admin Page')).toBeInTheDocument();
        });
    });

    it('redirects authenticated users away from public routes', async () => {
        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'testuser',
                email: 'test@example.com',
                role: 'user',
                permissions: ['secrets:read', 'secrets:write'],
                preferences: {
                    language: 'en',
                    timezone: 'UTC',
                    theme: 'light',
                    notifications: {
                        email: true,
                        browser: true,
                        sharing: true,
                        security: true,
                    },
                },
                lastLogin: '2024-01-01T00:00:00Z',
            },
            token: 'mock-token',
            error: null,
            login: vi.fn(),
            logout: vi.fn(),
            refreshToken: vi.fn(),
            checkAuth: vi.fn(),
            clearError: vi.fn(),
            isAdmin: false,
            permissions: ['secrets:read', 'secrets:write'],
            hasPermission: vi.fn().mockReturnValue(true),
        });

        // Mock window.location for navigation testing
        delete (window as any).location;
        window.location = { pathname: ROUTES.LOGIN } as any;

        render(
            <TestWrapper>
                <TestApp />
            </TestWrapper>
        );

        // Should not show login page for authenticated users
        expect(screen.queryByText('Login Page')).not.toBeInTheDocument();
    });
});