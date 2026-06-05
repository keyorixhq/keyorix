import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RequirePasswordChange } from '../RequirePasswordChange';
import type { User } from '../../../types';

// Mock useAuth so the guard reads a controllable user.
let mockUser: Partial<User> | null = null;
vi.mock('../../../features/auth', () => ({
    useAuth: () => ({ user: mockUser }),
}));

const renderAt = (path: string) =>
    render(
        <MemoryRouter initialEntries={[path]}>
            <Routes>
                <Route
                    path="/profile"
                    element={
                        <RequirePasswordChange>
                            <div>Profile Page</div>
                        </RequirePasswordChange>
                    }
                />
                <Route
                    path="/*"
                    element={
                        <RequirePasswordChange>
                            <div>App Content</div>
                        </RequirePasswordChange>
                    }
                />
            </Routes>
        </MemoryRouter>
    );

describe('RequirePasswordChange', () => {
    beforeEach(() => {
        mockUser = null;
    });

    it('renders children when no password change is required', () => {
        mockUser = { id: 1, passwordChangeRequired: false };
        renderAt('/dashboard');
        expect(screen.getByText('App Content')).toBeInTheDocument();
    });

    it('redirects a restricted user to the profile page', () => {
        mockUser = { id: 1, passwordChangeRequired: true };
        renderAt('/dashboard');
        expect(screen.getByText('Profile Page')).toBeInTheDocument();
        expect(screen.queryByText('App Content')).not.toBeInTheDocument();
    });

    it('lets a restricted user stay on the profile page', () => {
        mockUser = { id: 1, passwordChangeRequired: true };
        renderAt('/profile');
        // On /profile the guard renders its children (the profile route content).
        expect(screen.getByText('Profile Page')).toBeInTheDocument();
    });

    it('renders children when there is no user', () => {
        mockUser = null;
        renderAt('/dashboard');
        expect(screen.getByText('App Content')).toBeInTheDocument();
    });
});
