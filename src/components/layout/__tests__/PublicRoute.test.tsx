import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PublicRoute } from '../PublicRoute';
import { useAuth } from '../../../features/auth';

vi.mock('../../../features/auth', () => ({
    useAuth: vi.fn(),
}));

const mockUseAuth = vi.mocked(useAuth);

function setAuth(overrides: { isAuthenticated?: boolean; isLoading?: boolean } = {}) {
    mockUseAuth.mockReturnValue({
        isAuthenticated: overrides.isAuthenticated ?? false,
        isLoading: overrides.isLoading ?? false,
    } as unknown as ReturnType<typeof useAuth>);
}

function renderGuard(ui: React.ReactNode) {
    return render(
        <MemoryRouter initialEntries={['/login']}>
            <Routes>
                <Route path="/login" element={ui} />
                <Route path="/dashboard" element={<div>Dashboard Page</div>} />
            </Routes>
        </MemoryRouter>
    );
}

describe('PublicRoute', () => {
    beforeEach(() => {
        mockUseAuth.mockReset();
    });

    it('shows a loading state while auth is resolving', () => {
        setAuth({ isLoading: true });
        renderGuard(<PublicRoute>login form</PublicRoute>);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('renders children for unauthenticated users', () => {
        setAuth({ isAuthenticated: false });
        renderGuard(<PublicRoute>login form</PublicRoute>);
        expect(screen.getByText('login form')).toBeInTheDocument();
    });

    it('redirects authenticated users away to the dashboard', () => {
        setAuth({ isAuthenticated: true });
        renderGuard(<PublicRoute>login form</PublicRoute>);
        expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
        expect(screen.queryByText('login form')).not.toBeInTheDocument();
    });
});
