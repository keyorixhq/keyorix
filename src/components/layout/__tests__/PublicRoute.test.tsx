import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { PublicRoute } from '../PublicRoute';
import { useAuth } from '../../../hooks/useAuth';

// Mock the useAuth hook
vi.mock('../../../hooks/useAuth');

const mockUseAuth = vi.mocked(useAuth);

// Test component
const TestComponent = () => <div>Public Content</div>;

// Wrapper component
const TestWrapper = ({ children }: { children: React.ReactNode }) => (
    <BrowserRouter>{children}</BrowserRouter>
);

describe('PublicRoute', () => {
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
                <PublicRoute>
                    <TestComponent />
                </PublicRoute>
            </TestWrapper>
        );

        expect(screen.getByText('Loading...')).toBeInTheDocument();
        expect(screen.queryByText('Public Content')).not.toBeInTheDocument();
    });

    it('renders children when user is not authenticated', () => {
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
                <PublicRoute>
                    <TestComponent />
                </PublicRoute>
            </TestWrapper>
        );

        expect(screen.getByText('Public Content')).toBeInTheDocument();
    });

    it('redirects to dashboard when user is authenticated', () => {
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
                <PublicRoute>
                    <TestComponent />
                </PublicRoute>
            </TestWrapper>
        );

        // Should redirect to dashboard, so public content should not be visible
        expect(screen.queryByText('Public Content')).not.toBeInTheDocument();
    });

    it('uses custom redirect path when provided', () => {
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
                <PublicRoute redirectTo="/custom-dashboard">
                    <TestComponent />
                </PublicRoute>
            </TestWrapper>
        );

        // Should redirect to custom path, so public content should not be visible
        expect(screen.queryByText('Public Content')).not.toBeInTheDocument();
    });
});