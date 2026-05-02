import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { AdminRoute } from '../AdminRoute';
import { useAuth } from '../../../hooks/useAuth';

// Mock the useAuth hook
vi.mock('../../../hooks/useAuth');

const mockUseAuth = vi.mocked(useAuth);

// Test component
const TestComponent = () => <div>Admin Content</div>;

// Wrapper component
const TestWrapper = ({ children }: { children: React.ReactNode }) => (
    <BrowserRouter>{children}</BrowserRouter>
);

describe('AdminRoute', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('shows loading screen when authentication is loading', () => {
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
                <AdminRoute>
                    <TestComponent />
                </AdminRoute>
            </TestWrapper>
        );

        expect(screen.getByText('Loading...')).toBeInTheDocument();
        expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
    });

    it('redirects to login when user is not authenticated', () => {
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

        render(
            <TestWrapper>
                <AdminRoute>
                    <TestComponent />
                </AdminRoute>
            </TestWrapper>
        );

        // Should redirect to login, so admin content should not be visible
        expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
    });

    it('redirects to dashboard when user is not admin', () => {
        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'testuser',
                email: 'test@example.com',
                role: 'user',
                permissions: ['read', 'write'],
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
            permissions: ['read', 'write'],
            hasPermission: vi.fn().mockReturnValue(true),
        });

        render(
            <TestWrapper>
                <AdminRoute>
                    <TestComponent />
                </AdminRoute>
            </TestWrapper>
        );

        // Should redirect to dashboard, so admin content should not be visible
        expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
    });

    it('renders children when user is admin', () => {
        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'admin',
                email: 'admin@example.com',
                role: 'admin',
                permissions: ['read', 'write', 'admin:write'],
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
            permissions: ['read', 'write', 'admin:write'],
            hasPermission: vi.fn().mockReturnValue(true),
        });

        render(
            <TestWrapper>
                <AdminRoute>
                    <TestComponent />
                </AdminRoute>
            </TestWrapper>
        );

        expect(screen.getByText('Admin Content')).toBeInTheDocument();
    });

    it('checks required permissions for admin users', () => {
        const mockHasPermission = vi.fn()
            .mockImplementation((permission: string) => permission !== 'system:admin');

        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'admin',
                email: 'admin@example.com',
                role: 'admin',
                permissions: ['read', 'write', 'admin:write'],
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
            permissions: ['read', 'write', 'admin:write'],
            hasPermission: mockHasPermission,
        });

        render(
            <TestWrapper>
                <AdminRoute requiredPermissions={['system:admin']}>
                    <TestComponent />
                </AdminRoute>
            </TestWrapper>
        );

        // Should redirect to dashboard due to missing permission
        expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
        expect(mockHasPermission).toHaveBeenCalledWith('system:admin');
    });

    it('renders children when admin user has required permissions', () => {
        const mockHasPermission = vi.fn().mockReturnValue(true);

        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'admin',
                email: 'admin@example.com',
                role: 'admin',
                permissions: ['read', 'write', 'admin:write', 'system:admin'],
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
            permissions: ['read', 'write', 'admin:write', 'system:admin'],
            hasPermission: mockHasPermission,
        });

        render(
            <TestWrapper>
                <AdminRoute requiredPermissions={['system:admin']}>
                    <TestComponent />
                </AdminRoute>
            </TestWrapper>
        );

        expect(screen.getByText('Admin Content')).toBeInTheDocument();
        expect(mockHasPermission).toHaveBeenCalledWith('system:admin');
    });
});