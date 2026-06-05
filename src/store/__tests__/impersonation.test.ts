import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useAuthStore } from '../authStore';
import { authService } from '../../services/auth';
import type { User } from '../../types';

vi.mock('../../services/auth', () => ({
    authService: {
        endImpersonation: vi.fn(),
    },
}));

vi.mock('../../utils/auth', () => ({
    persistAuthData: vi.fn(),
    clearPersistedAuthData: vi.fn(),
    updateTokenExpiry: vi.fn(),
    isTokenValid: vi.fn(() => true),
    getTimeUntilExpiry: vi.fn(() => 0),
}));

const makeUser = (id: number, username: string): User =>
    ({
        id,
        username,
        email: `${username}@example.com`,
        role: 'user',
        roles: [],
        permissions: [],
        preferences: {
            language: 'en',
            timezone: 'UTC',
            theme: 'system',
            notifications: { email: true, browser: true, sharing: true, security: true },
        },
        lastLogin: '2026-06-05T00:00:00Z',
    }) as User;

describe('authStore impersonation', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        useAuthStore.setState({
            user: makeUser(1, 'admin'),
            token: 'admin-token',
            isAuthenticated: true,
            adminToken: null,
            adminUser: null,
            isImpersonating: false,
            isLoading: false,
            error: null,
        });
    });

    it('stashes the admin session and swaps to the target on start', () => {
        const target = makeUser(2, 'alice');
        useAuthStore.getState().startImpersonation('alice-token', target);

        const s = useAuthStore.getState();
        expect(s.isImpersonating).toBe(true);
        expect(s.token).toBe('alice-token');
        expect(s.user?.username).toBe('alice');
        expect(s.adminToken).toBe('admin-token');
        expect(s.adminUser?.username).toBe('admin');
    });

    it('does not nest impersonation (keeps the original admin session stashed)', () => {
        useAuthStore.getState().startImpersonation('alice-token', makeUser(2, 'alice'));
        useAuthStore.getState().startImpersonation('bob-token', makeUser(3, 'bob'));

        const s = useAuthStore.getState();
        // Second call is a no-op: still impersonating alice, admin still stashed.
        expect(s.token).toBe('alice-token');
        expect(s.adminToken).toBe('admin-token');
    });

    it('restores the admin session on end and notifies the server', async () => {
        const ended = vi.mocked(authService.endImpersonation);
        ended.mockResolvedValueOnce(undefined);

        useAuthStore.getState().startImpersonation('alice-token', makeUser(2, 'alice'));
        await useAuthStore.getState().endImpersonation();

        const s = useAuthStore.getState();
        expect(ended).toHaveBeenCalledOnce();
        expect(s.isImpersonating).toBe(false);
        expect(s.token).toBe('admin-token');
        expect(s.user?.username).toBe('admin');
        expect(s.adminToken).toBeNull();
        expect(s.adminUser).toBeNull();
    });

    it('end is a no-op when not impersonating', async () => {
        await useAuthStore.getState().endImpersonation();
        expect(vi.mocked(authService.endImpersonation)).not.toHaveBeenCalled();
        expect(useAuthStore.getState().token).toBe('admin-token');
    });
});
