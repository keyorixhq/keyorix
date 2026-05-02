import { renderHook, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useAuth } from '../useAuth';
import { authService } from '../../services/auth';
import { mockAuthUser, mockApiResponse, mockApiError } from '../../test/test-utils';

// Mock the auth service
vi.mock('../../services/auth');
const mockAuthService = authService as any;

const createWrapper = () => {
    const queryClient = new QueryClient({
        defaultOptions: {
            queries: { retry: false },
            mutations: { retry: false },
        },
    });

    return ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client= { queryClient } > { children } </QueryClientProvider>
  );
};

describe('useAuth', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        localStorage.clear();
    });

    it('returns initial unauthenticated state', () => {
        mockAuthService.getCurrentUser.mockResolvedValue(null);

        const { result } = renderHook(() => useAuth(), {
            wrapper: createWrapper(),
        });

        expect(result.current.user).toBeNull();
        expect(result.current.isAuthenticated).toBe(false);
        expect(result.current.isLoading).toBe(true);
    });

    it('loads authenticated user on mount', async () => {
        mockAuthService.getCurrentUser.mockResolvedValue(mockAuthUser);

        const { result, waitForNextUpdate } = renderHook(() => useAuth(), {
            wrapper: createWrapper(),
        });

        await waitForNextUpdate();

        expect(result.current.user).toEqual(mockAuthUser);
        expect(result.current.isAuthenticated).toBe(true);
        expect(result.current.isLoading).toBe(false);
    });

    it('handles login successfully', async () => {
        mockAuthService.getCurrentUser.mockResolvedValue(null);
        mockAuthService.login.mockResolvedValue(mockAuthUser);

        const { result, waitForNextUpdate } = renderHook(() => useAuth(), {
            wrapper: createWrapper(),
        });

        await waitForNextUpdate();

        await act(async () => {
            await result.current.login('test@example.com', 'password');
        });

        expect(mockAuthService.login).toHaveBeenCalledWith('test@example.com', 'password');
        expect(result.current.user).toEqual(mockAuthUser);
        expect(result.current.isAuthenticated).toBe(true);
    });

    it('handles login failure', async () => {
        mockAuthService.getCurrentUser.mockResolvedValue(null);
        mockAuthService.login.mockRejectedValue(mockApiError('Invalid credentials', 401));

        const { result, waitForNextUpdate } = renderHook(() => useAuth(), {
            wrapper: createWrapper(),
        });

        await waitForNextUpdate();

        await expect(
            act(async () => {
                await result.current.login('test@example.com', 'wrong-password');
            })
        ).rejects.toThrow('Invalid credentials');

        expect(result.current.user).toBeNull();
        expect(result.current.isAuthenticated).toBe(false);
    });

    it('handles logout successfully', async () => {
        mockAuthService.getCurrentUser.mockResolvedValue(mockAuthUser);
        mockAuthService.logout.mockResolvedValue(undefined);

        const { result, waitForNextUpdate } = renderHook(() => useAuth(), {
            wrapper: createWrapper(),
        });

        await waitForNextUpdate();

        await act(async () => {
            await result.current.logout();
        });

        expect(mockAuthService.logout).toHaveBeenCalled();
        expect(result.current.user).toBeNull();
        expect(result.current.isAuthenticated).toBe(false);
    });

    it('checks user permissions correctly', async () => {
        mockAuthService.getCurrentUser.mockResolvedValue(mockAuthUser);

        const { result, waitForNextUpdate } = renderHook(() => useAuth(), {
            wrapper: createWrapper(),
        });

        await waitForNextUpdate();

        expect(result.current.hasPermission('read:secrets')).toBe(true);
        expect(result.current.hasPermission('admin:users')).toBe(false);
    });

    it('checks user roles correctly', async () => {
        mockAuthService.getCurrentUser.mockResolvedValue(mockAuthUser);

        const { result, waitForNextUpdate } = renderHook(() => useAuth(), {
            wrapper: createWrapper(),
        });

        await waitForNextUpdate();

        expect(result.current.hasRole('user')).toBe(true);
        expect(result.current.hasRole('admin')).toBe(false);
    });

    it('handles token refresh', async () => {
        mockAuthService.getCurrentUser.mockResolvedValue(mockAuthUser);
        mockAuthService.refreshToken.mockResolvedValue(mockAuthUser);

        const { result, waitForNextUpdate } = renderHook(() => useAuth(), {
            wrapper: createWrapper(),
        });

        await waitForNextUpdate();

        await act(async () => {
            await result.current.refreshToken();
        });

        expect(mockAuthService.refreshToken).toHaveBeenCalled();
    });
});