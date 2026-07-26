import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AdminRoute } from '../AdminRoute';
import { useAuth } from '../../../features/auth';

vi.mock('../../../features/auth', () => ({
    useAuth: vi.fn(),
}));

const mockUseAuth = vi.mocked(useAuth);

type AuthOverrides = {
    isAuthenticated?: boolean;
    isLoading?: boolean;
    user?: { role?: string; permissions?: string[] } | null;
};

function setAuth(overrides: AuthOverrides = {}) {
    const permissions = overrides.user?.permissions ?? [];
    mockUseAuth.mockReturnValue({
        user: overrides.user ?? null,
        isAuthenticated: overrides.isAuthenticated ?? false,
        isLoading: overrides.isLoading ?? false,
        hasPermission: (permission: string) => permissions.includes(permission),
    } as unknown as ReturnType<typeof useAuth>);
}

function renderGuard(ui: React.ReactNode) {
    return render(
        <MemoryRouter initialEntries={['/admin']}>
            <Routes>
                <Route path="/admin" element={ui} />
                <Route path="/login" element={<div>Login Page</div>} />
                <Route path="/dashboard" element={<div>Dashboard Page</div>} />
            </Routes>
        </MemoryRouter>
    );
}

describe('AdminRoute', () => {
    beforeEach(() => {
        mockUseAuth.mockReset();
    });

    it('redirects unauthenticated users to the login page', () => {
        setAuth({ isAuthenticated: false });
        renderGuard(<AdminRoute>admin panel</AdminRoute>);
        expect(screen.getByText('Login Page')).toBeInTheDocument();
        expect(screen.queryByText('admin panel')).not.toBeInTheDocument();
    });

    it('redirects authenticated non-admin users to the dashboard', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user' } });
        renderGuard(<AdminRoute>admin panel</AdminRoute>);
        expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
        expect(screen.queryByText('admin panel')).not.toBeInTheDocument();
    });

    it('renders children for an authenticated admin', () => {
        setAuth({ isAuthenticated: true, user: { role: 'admin' } });
        renderGuard(<AdminRoute>admin panel</AdminRoute>);
        expect(screen.getByText('admin panel')).toBeInTheDocument();
    });

    it('still enforces extra permission requirements for an admin', () => {
        setAuth({ isAuthenticated: true, user: { role: 'admin', permissions: [] } });
        renderGuard(<AdminRoute requiredPermissions={['rbac:manage']}>admin panel</AdminRoute>);
        expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
        expect(screen.queryByText('admin panel')).not.toBeInTheDocument();
    });
});
