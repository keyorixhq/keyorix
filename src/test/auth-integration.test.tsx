import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ProtectedRoute } from '../components/layout/ProtectedRoute';
import { PublicRoute } from '../components/layout/PublicRoute';
import { AdminRoute } from '../components/layout/AdminRoute';
import { useAuth } from '../features/auth';

vi.mock('../features/auth', () => ({
    useAuth: vi.fn(),
}));

const mockUseAuth = vi.mocked(useAuth);

type AuthOverrides = {
    isAuthenticated?: boolean;
    isLoading?: boolean;
    hasCheckedAuth?: boolean;
    user?: { role?: string; permissions?: string[] } | null;
};

function setAuth(overrides: AuthOverrides = {}) {
    const permissions = overrides.user?.permissions ?? [];
    mockUseAuth.mockReturnValue({
        user: overrides.user ?? null,
        isAuthenticated: overrides.isAuthenticated ?? false,
        isLoading: overrides.isLoading ?? false,
        hasCheckedAuth: overrides.hasCheckedAuth ?? true,
        hasPermission: (permission: string) => permissions.includes(permission),
    } as unknown as ReturnType<typeof useAuth>);
}

// A small app wiring the three guards onto distinct routes, mirroring how the
// real router composes them.
function renderApp(initialPath: string) {
    return render(
        <MemoryRouter initialEntries={[initialPath]}>
            <Routes>
                <Route
                    path="/login"
                    element={
                        <PublicRoute>
                            <div>Login Page</div>
                        </PublicRoute>
                    }
                />
                <Route
                    path="/dashboard"
                    element={
                        <ProtectedRoute>
                            <div>Dashboard Page</div>
                        </ProtectedRoute>
                    }
                />
                <Route
                    path="/admin"
                    element={
                        <AdminRoute>
                            <div>Admin Page</div>
                        </AdminRoute>
                    }
                />
            </Routes>
        </MemoryRouter>
    );
}

describe('auth route-guard integration', () => {
    beforeEach(() => {
        mockUseAuth.mockReset();
    });

    it('sends an anonymous visitor from a protected route to login', () => {
        setAuth({ isAuthenticated: false });
        renderApp('/dashboard');
        expect(screen.getByText('Login Page')).toBeInTheDocument();
        expect(screen.queryByText('Dashboard Page')).not.toBeInTheDocument();
    });

    it('keeps an authenticated user away from the public login route', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user' } });
        renderApp('/login');
        expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
        expect(screen.queryByText('Login Page')).not.toBeInTheDocument();
    });

    it('lets an authenticated user reach a protected route', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user' } });
        renderApp('/dashboard');
        expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
    });

    it('blocks a non-admin from the admin route but admits an admin', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user' } });
        const { unmount } = renderApp('/admin');
        expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
        expect(screen.queryByText('Admin Page')).not.toBeInTheDocument();
        unmount();

        setAuth({ isAuthenticated: true, user: { role: 'admin' } });
        renderApp('/admin');
        expect(screen.getByText('Admin Page')).toBeInTheDocument();
    });
});
