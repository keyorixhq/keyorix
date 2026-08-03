import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ProtectedRoute } from '../ProtectedRoute';
import { useAuth } from '../../../features/auth';

vi.mock('../../../features/auth', () => ({
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

function renderGuard(ui: React.ReactNode) {
    return render(
        <MemoryRouter initialEntries={['/protected']}>
            <Routes>
                <Route path="/protected" element={ui} />
                <Route path="/login" element={<div>Login Page</div>} />
                <Route path="/dashboard" element={<div>Dashboard Page</div>} />
            </Routes>
        </MemoryRouter>
    );
}

describe('ProtectedRoute', () => {
    beforeEach(() => {
        mockUseAuth.mockReset();
    });

    it('shows a loading state while auth is resolving', () => {
        setAuth({ isLoading: true, hasCheckedAuth: false });
        renderGuard(<ProtectedRoute>secret</ProtectedRoute>);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('redirects unauthenticated users to the login page', () => {
        setAuth({ isAuthenticated: false });
        renderGuard(<ProtectedRoute>secret</ProtectedRoute>);
        expect(screen.getByText('Login Page')).toBeInTheDocument();
        expect(screen.queryByText('secret')).not.toBeInTheDocument();
    });

    it('renders children for an authenticated user with no extra requirements', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user' } });
        renderGuard(<ProtectedRoute>secret</ProtectedRoute>);
        expect(screen.getByText('secret')).toBeInTheDocument();
    });

    it('redirects to the dashboard when the required role is missing', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user' } });
        renderGuard(<ProtectedRoute requiredRole="admin">secret</ProtectedRoute>);
        expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
        expect(screen.queryByText('secret')).not.toBeInTheDocument();
    });

    it('shows an Access Denied page on a role mismatch when redirectOnFailure is false', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user' } });
        renderGuard(
            <ProtectedRoute requiredRole="admin" redirectOnFailure={false}>
                secret
            </ProtectedRoute>
        );
        expect(screen.getByText('Access Denied')).toBeInTheDocument();
        expect(screen.getByText(/Required role: admin/)).toBeInTheDocument();
    });

    it('renders children when all required permissions are present', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user', permissions: ['secrets:read'] } });
        renderGuard(<ProtectedRoute requiredPermissions={['secrets:read']}>secret</ProtectedRoute>);
        expect(screen.getByText('secret')).toBeInTheDocument();
    });

    it('lists missing permissions on Access Denied when redirectOnFailure is false', () => {
        setAuth({ isAuthenticated: true, user: { role: 'user', permissions: ['secrets:read'] } });
        renderGuard(
            <ProtectedRoute requiredPermissions={['secrets:read', 'secrets:write']} redirectOnFailure={false}>
                secret
            </ProtectedRoute>
        );
        expect(screen.getByText('Access Denied')).toBeInTheDocument();
        expect(screen.getByText(/Missing permissions: secrets:write/)).toBeInTheDocument();
    });
});
