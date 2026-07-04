import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useAuthStore } from '../authStore';
import { useUIStore } from '../uiStore';
import { useProjectMruStore } from '../projectMruStore';
import { authService } from '../../services/auth';
import { mockUser } from '../../test/mocks';
import type { User, LoginResponse } from '../../types';

// Mock the network + persistence side-effects so store logic is tested in isolation.
vi.mock('../../services/auth', () => ({
    authService: {
        login: vi.fn(),
        logout: vi.fn(),
        refreshToken: vi.fn(),
        getProfile: vi.fn(),
    },
}));

vi.mock('../../utils/auth', () => ({
    persistAuthData: vi.fn(),
    clearPersistedAuthData: vi.fn(),
    updateTokenExpiry: vi.fn(),
    isTokenValid: vi.fn(() => true),
    getTimeUntilExpiry: vi.fn(() => 0),
}));

const mockedLogin = vi.mocked(authService.login);

const asUser = (u: typeof mockUser): User => u as unknown as User;

describe('authStore', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Reset to a clean logged-out state between tests (zustand store is a singleton).
        useAuthStore.setState({
            user: null,
            token: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
        });
    });

    it('starts logged out', () => {
        const state = useAuthStore.getState();
        expect(state.isAuthenticated).toBe(false);
        expect(state.user).toBeNull();
    });

    it('setUser sets the user and derives isAuthenticated', () => {
        useAuthStore.getState().setUser(asUser(mockUser));
        expect(useAuthStore.getState().user?.username).toBe('testuser');
        expect(useAuthStore.getState().isAuthenticated).toBe(true);

        useAuthStore.getState().setUser(null);
        expect(useAuthStore.getState().isAuthenticated).toBe(false);
    });

    it('setError and clearError manage the error field', () => {
        useAuthStore.getState().setError('boom');
        expect(useAuthStore.getState().error).toBe('boom');

        useAuthStore.getState().clearError();
        expect(useAuthStore.getState().error).toBeNull();
    });

    it('setLoading toggles the loading flag', () => {
        useAuthStore.getState().setLoading(true);
        expect(useAuthStore.getState().isLoading).toBe(true);
        useAuthStore.getState().setLoading(false);
        expect(useAuthStore.getState().isLoading).toBe(false);
    });

    it('login success authenticates the user (session lives in an httpOnly cookie, not client state)', async () => {
        const response: LoginResponse = {
            token: 'tok-123',
            expires_at: '2030-01-01T00:00:00Z',
            user_id: 1,
            username: 'testuser',
            email: 'test@example.com',
            display_name: 'Test User',
        };
        mockedLogin.mockResolvedValueOnce(response);

        await useAuthStore.getState().login({ username: 'testuser', password: 'pw' } as never);

        const state = useAuthStore.getState();
        expect(state.isAuthenticated).toBe(true);
        expect(state.user?.username).toBe('testuser');
        expect(state.isLoading).toBe(false);
        expect(state.error).toBeNull();
    });

    it('login failure records the error and rethrows', async () => {
        mockedLogin.mockRejectedValueOnce(new Error('Invalid credentials'));

        await expect(
            useAuthStore.getState().login({ username: 'x', password: 'y' } as never)
        ).rejects.toThrow('Invalid credentials');

        const state = useAuthStore.getState();
        expect(state.isAuthenticated).toBe(false);
        expect(state.user).toBeNull();
        expect(state.error).toBe('Invalid credentials');
        expect(state.isLoading).toBe(false);
    });
});

describe('uiStore', () => {
    beforeEach(() => {
        useUIStore.setState({
            sidebarOpen: true,
            activeModal: null,
            modalData: null,
            theme: 'dark',
            sidebarExpanded: { secrets: true, access: true, integrations: false, settings: false },
        });
    });

    it('toggleSidebar flips sidebarOpen', () => {
        expect(useUIStore.getState().sidebarOpen).toBe(true);
        useUIStore.getState().toggleSidebar();
        expect(useUIStore.getState().sidebarOpen).toBe(false);
    });

    it('setSidebarOpen sets an explicit value', () => {
        useUIStore.getState().setSidebarOpen(false);
        expect(useUIStore.getState().sidebarOpen).toBe(false);
    });

    it('openModal / closeModal manage modal state', () => {
        useUIStore.getState().openModal('confirm-delete', { id: 7 });
        expect(useUIStore.getState().activeModal).toBe('confirm-delete');
        expect(useUIStore.getState().modalData).toEqual({ id: 7 });

        useUIStore.getState().closeModal();
        expect(useUIStore.getState().activeModal).toBeNull();
        expect(useUIStore.getState().modalData).toBeNull();
    });

    it('setTheme updates the theme and reflects it on the document element', () => {
        useUIStore.getState().setTheme('light');
        expect(useUIStore.getState().theme).toBe('light');
        expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    });

    it('toggleTheme switches between dark and light', () => {
        expect(useUIStore.getState().theme).toBe('dark');
        useUIStore.getState().toggleTheme();
        expect(useUIStore.getState().theme).toBe('light');
        useUIStore.getState().toggleTheme();
        expect(useUIStore.getState().theme).toBe('dark');
    });

    it('toggleSidebarGroup flips a single group', () => {
        expect(useUIStore.getState().sidebarExpanded.secrets).toBe(true);
        useUIStore.getState().toggleSidebarGroup('secrets');
        expect(useUIStore.getState().sidebarExpanded.secrets).toBe(false);
        // other groups untouched
        expect(useUIStore.getState().sidebarExpanded.access).toBe(true);
    });
});

describe('projectMruStore', () => {
    beforeEach(() => {
        useProjectMruStore.setState({ recentIds: [] });
    });

    it('starts empty', () => {
        expect(useProjectMruStore.getState().recentIds).toEqual([]);
    });

    it('recordAccess prepends the most-recent project', () => {
        const { recordAccess } = useProjectMruStore.getState();
        recordAccess(1);
        recordAccess(2);
        expect(useProjectMruStore.getState().recentIds).toEqual([2, 1]);
    });

    it('re-accessing an existing project moves it to the front without duplicating', () => {
        const { recordAccess } = useProjectMruStore.getState();
        recordAccess(1);
        recordAccess(2);
        recordAccess(3);
        recordAccess(1);
        expect(useProjectMruStore.getState().recentIds).toEqual([1, 3, 2]);
    });

    it('caps the list at 10 entries, dropping the oldest', () => {
        const { recordAccess } = useProjectMruStore.getState();
        for (let i = 1; i <= 12; i++) recordAccess(i);
        const ids = useProjectMruStore.getState().recentIds;
        expect(ids).toHaveLength(10);
        expect(ids[0]).toBe(12);
        // the two oldest (1, 2) fell off
        expect(ids).not.toContain(1);
        expect(ids).not.toContain(2);
    });

    it('ignores non-finite ids', () => {
        const { recordAccess } = useProjectMruStore.getState();
        recordAccess(NaN);
        expect(useProjectMruStore.getState().recentIds).toEqual([]);
    });
});
