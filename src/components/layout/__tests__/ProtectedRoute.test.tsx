import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { ProtectedRoute } from '../ProtectedRoute';
import { useAuth } from '../../../hooks/useAuth';

// Mock the useAuth hook
vi.mock('../../../hooks/useAuth');

const mockUseAuth = vi.mocked(useAuth);

// Test component
const TestComponent = () => <div>Protected Content</div>;

// Wrapper component
const TestWrapper = ({ children }: { children: React.ReactNode }) => (
    <BrowserRouter>{children}</BrowserRouter>
);

describe('ProtectedRoute', () => {
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
                <ProtectedRoute>
                    <TestComponent />
                </ProtectedRoute>
            </TestWrapper>
        );

        expect(screen.getByText('Loading...')).toBeInTheDocument();
        expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
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
                <ProtectedRoute>
                    <TestComponent />
                </ProtectedRoute>
            </TestWrapper>
        );

        // Should redirect to login, so protected content should not be visible
        expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    });

    it('renders children when user is authenticated', () => {
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
                <ProtectedRoute>
                    <TestComponent />
                </ProtectedRoute>
            </TestWrapper>
        );

        expect(screen.getByText('Protected Content')).toBeInTheDocument();
    });

    it('redirects to dashboard when user lacks required role', () => {
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
                <ProtectedRoute requiredRole="admin">
                    <TestComponent />
                </ProtectedRoute>
            </TestWrapper>
        );

        // Should redirect to dashboard, so protected content should not be visible
        expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    });

    it('redirects to dashboard when user lacks required permissions', () => {
        const mockHasPermission = vi.fn()
            .mockImplementation((permission: string) => permission !== 'admin:write');

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
            hasPermission: mockHasPermission,
        });

        render(
            <TestWrapper>
                <ProtectedRoute requiredPermissions={['admin:write']}>
                    <TestComponent />
                </ProtectedRoute>
            </TestWrapper>
        );

        // Should redirect to dashboard, so protected content should not be visible
        expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
        expect(mockHasPermission).toHaveBeenCalledWith('admin:write');
    });

    it('renders children when user has required permissions', () => {
        const mockHasPermission = vi.fn().mockReturnValue(true);

        mockUseAuth.mockReturnValue({
            isAuthenticated: true,
            isLoading: false,
            user: {
                id: 1,
                username: 'testuser',
                email: 'test@example.com',
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
                <ProtectedRoute requiredPermissions={['admin:write']}>
                    <TestComponent />
                </ProtectedRoute>
            </TestWrapper>
        );

        expect(screen.getByText('Protected Content')).toBeInTheDocument();
        expect(mockHasPermission).toHaveBeenCalledWith('admin:write');
    });

    it('uses custom fallback path when provided', () => {
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
                <ProtectedRoute fallbackPath="/custom-login">
                    <TestComponent />
                </ProtectedRoute>
            </TestWrapper>
        );

        // Should redirect to custom path, so protected content should not be visible
        expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    });
});