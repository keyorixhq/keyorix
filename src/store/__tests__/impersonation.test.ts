import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useAuthStore } from '../authStore';
import { authService } from '../../services/auth';
import type { User } from '../../types';

vi.mock('../../services/auth', () => ({
    authService: {
        endImpersonation: vi.fn(),
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

// Profile-shaped fixture matching what authService.getProfile() resolves to
// (User fields plus the optional, server-validated `impersonation` block).
const profileFixture = (user: User, impersonation?: { admin_id: number; admin_username: string; admin_display_name?: string }) => ({
    ...user,
    impersonation,
});

describe('authStore impersonation', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        useAuthStore.setState({
            user: makeUser(2, 'alice'),
            isAuthenticated: true,
            impersonatedBy: { adminId: 1, adminUsername: 'admin' },
            isLoading: false,
            error: null,
        });
    });

    it('checkAuth derives impersonatedBy from the profile response while impersonating', async () => {
        vi.mocked(authService.getProfile).mockResolvedValueOnce(
            profileFixture(makeUser(2, 'alice'), { admin_id: 1, admin_username: 'admin', admin_display_name: 'Admin User' })
        );

        await useAuthStore.getState().checkAuth();

        const s = useAuthStore.getState();
        expect(s.user?.username).toBe('alice');
        expect(s.impersonatedBy).toEqual({ adminId: 1, adminUsername: 'admin', adminDisplayName: 'Admin User' });
    });

    it('checkAuth clears impersonatedBy once the profile no longer reports it', async () => {
        vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser(1, 'admin')));

        await useAuthStore.getState().checkAuth();

        const s = useAuthStore.getState();
        expect(s.user?.username).toBe('admin');
        expect(s.impersonatedBy).toBeNull();
    });

    it('endImpersonation calls the server then re-syncs via checkAuth (server-side restore, no client-held admin credential)', async () => {
        const ended = vi.mocked(authService.endImpersonation);
        ended.mockResolvedValueOnce(undefined);
        // The server restored the admin's original session cookie — the next
        // profile fetch reflects the admin, with no impersonation field.
        vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser(1, 'admin')));

        await useAuthStore.getState().endImpersonation();

        const s = useAuthStore.getState();
        expect(ended).toHaveBeenCalledOnce();
        expect(authService.getProfile).toHaveBeenCalledOnce();
        expect(s.user?.username).toBe('admin');
        expect(s.impersonatedBy).toBeNull();
        expect(s.isAuthenticated).toBe(true);
    });

    it('endImpersonation logs the client out when the original admin session is gone (server clears the cookie, checkAuth 401s)', async () => {
        const ended = vi.mocked(authService.endImpersonation);
        ended.mockResolvedValueOnce(undefined);
        // Original session expired mid-impersonation — server cleared the
        // cookie entirely, so the next profile fetch 401s.
        vi.mocked(authService.getProfile).mockRejectedValueOnce(new Error('unauthorized'));

        await useAuthStore.getState().endImpersonation();

        const s = useAuthStore.getState();
        expect(s.isAuthenticated).toBe(false);
        expect(s.user).toBeNull();
        expect(s.impersonatedBy).toBeNull();
    });

    it('rejects and leaves state untouched when the server does not confirm the revoke (network blip)', async () => {
        const ended = vi.mocked(authService.endImpersonation);
        ended.mockRejectedValueOnce(new Error('network blip'));

        await expect(useAuthStore.getState().endImpersonation()).rejects.toThrow('network blip');

        // checkAuth() must not have run — no false "back to normal" or "logged
        // out" state despite the server never confirming the session ended.
        expect(authService.getProfile).not.toHaveBeenCalled();
        const s = useAuthStore.getState();
        expect(s.impersonatedBy).toEqual({ adminId: 1, adminUsername: 'admin' });
        expect(s.isAuthenticated).toBe(true);
    });

    it('does not persist impersonatedBy (only user/isAuthenticated survive a reload)', () => {
        const partialize = (useAuthStore.persist.getOptions() as { partialize?: (s: unknown) => object }).partialize;
        expect(partialize).toBeDefined();

        const persisted = partialize!(useAuthStore.getState()) as Record<string, unknown>;

        expect(persisted).not.toHaveProperty('impersonatedBy');
        expect(persisted).toHaveProperty('user');
        expect(persisted).toHaveProperty('isAuthenticated');
    });
});
