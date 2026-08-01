import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { useAuthStore, shouldRefreshToken, isTokenExpired } from '../authStore';
import { authService } from '../../services/auth';
import * as authUtils from '../../utils/auth';
import type { User, LoginResponse, RefreshTokenResponse } from '../../types';

// Phase 4 coverage sweep: authStore.ts's own action/reducer logic is exercised
// today only indirectly (via mocked-store page tests and the existing
// stores.test.ts / impersonation.test.ts / multiTabSync.test.ts files in this
// directory). This file is deliberately SEPARATE from stores.test.ts rather
// than an addition to it — editing a shared file risks merge conflicts with
// unrelated in-flight work in this multi-phase effort, and a second focused
// file matches the sweep's established "one file, one PR" pattern. It targets
// the actions/branches those three existing files don't reach: completeSetup,
// completeSSOLogin, logout, refreshToken (including its absolute-expiry and
// single-flight paths), checkAuth's re-entrancy guard and redirect branches,
// clearPasswordChangeRequired, and the shouldRefreshToken/isTokenExpired
// helpers — plus a couple of login/completeSetup response-shaping branches
// (account_state, password_change_required, role/roles/permissions defaults)
// that the existing happy-path login tests don't cover.

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
    updateAbsoluteTokenExpiry: vi.fn(),
    isAbsoluteExpiryPassed: vi.fn(() => false),
    isTokenValid: vi.fn(() => true),
    getTimeUntilExpiry: vi.fn(() => 0),
}));

const makeUser = (overrides: Partial<User> = {}): User =>
    ({
        id: 1,
        username: 'alice',
        email: 'alice@example.com',
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
        ...overrides,
    }) as User;

// Profile-shaped fixture matching what authService.getProfile() resolves to.
const profileFixture = (user: User) => ({ ...user, impersonation: undefined });

// Replaces window.location with a plain, mutable object so logout()/checkAuth()
// assigning `window.location.href` and reading `window.location.pathname`
// don't trigger jsdom's "Not implemented: navigation" error. Restored after
// every test. Mirrors the pattern already used in
// src/components/ui/__tests__/ErrorBoundary.test.tsx.
const originalLocation = window.location;
let locationMock: { href: string; pathname: string };

function stubLocation(pathname = '/dashboard') {
    locationMock = { href: '', pathname };
    Object.defineProperty(window, 'location', {
        configurable: true,
        value: locationMock,
    });
}

describe('authStore', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        stubLocation();
        useAuthStore.setState({
            user: null,
            isAuthenticated: false,
            impersonatedBy: null,
            isLoading: false,
            hasCheckedAuth: false,
            error: null,
        });
    });

    afterEach(() => {
        Object.defineProperty(window, 'location', {
            configurable: true,
            value: originalLocation,
        });
    });

    describe('login response shaping', () => {
        const baseResponse: LoginResponse = {
            expires_at: '2030-01-01T00:00:00Z',
            user_id: 5,
            username: 'bob',
            email: 'bob@example.com',
        };

        it('defaults role/roles/permissions and carries account_state through when present', async () => {
            vi.mocked(authService.login).mockResolvedValueOnce({
                ...baseResponse,
                account_state: 'pending_review',
                password_change_required: true,
            });

            await useAuthStore.getState().login({ username: 'bob', password: 'pw' } as never);

            const user = useAuthStore.getState().user;
            expect(user?.role).toBe('user');
            expect(user?.roles).toEqual([]);
            expect(user?.permissions).toEqual([]);
            expect(user?.accountState).toBe('pending_review');
            expect(user?.passwordChangeRequired).toBe(true);
        });

        it('omits accountState entirely when the response has no account_state', async () => {
            vi.mocked(authService.login).mockResolvedValueOnce(baseResponse);

            await useAuthStore.getState().login({ username: 'bob', password: 'pw' } as never);

            const user = useAuthStore.getState().user;
            expect(user).not.toHaveProperty('accountState');
            expect(user?.passwordChangeRequired).toBe(false);
        });
    });

    describe('completeSetup (ADR-028: land a setup-link consume response without re-authenticating)', () => {
        it('authenticates the user synchronously and persists bookkeeping, forcing isLoading false', () => {
            // Start from a deliberately "mid-request" isLoading:true to prove
            // completeSetup unconditionally settles it to false.
            useAuthStore.setState({ isLoading: true });

            const response: LoginResponse = {
                expires_at: '2030-01-01T00:00:00Z',
                absolute_expires_at: '2030-06-01T00:00:00Z',
                user_id: 9,
                username: 'carol',
                email: 'carol@example.com',
                display_name: 'Carol Setup',
            };

            useAuthStore.getState().completeSetup(response);

            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(true);
            expect(state.isLoading).toBe(false);
            expect(state.error).toBeNull();
            expect(state.user?.username).toBe('carol');
            expect(state.user?.displayName).toBe('Carol Setup');
            expect(authUtils.persistAuthData).toHaveBeenCalledWith(
                expect.objectContaining({
                    expiresAt: '2030-01-01T00:00:00Z',
                    absoluteExpiresAt: '2030-06-01T00:00:00Z',
                })
            );
        });
    });

    describe('completeSSOLogin (backend already set the session cookie on its redirect; this just loads the profile)', () => {
        it('populates the user via checkAuth and persists the passed-in expiry bookkeeping', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser({ username: 'dora' })));

            await useAuthStore.getState().completeSSOLogin('2031-01-01T00:00:00Z', '2031-06-01T00:00:00Z');

            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(true);
            expect(state.isLoading).toBe(false);
            expect(state.user?.username).toBe('dora');
            expect(authUtils.persistAuthData).toHaveBeenCalledWith({
                user: expect.objectContaining({ username: 'dora' }),
                expiresAt: '2031-01-01T00:00:00Z',
                absoluteExpiresAt: '2031-06-01T00:00:00Z',
            });
        });

        it('defaults expiresAt to an empty string when the SSO callback fragment omits it', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser({ username: 'dora' })));

            await useAuthStore.getState().completeSSOLogin();

            expect(authUtils.persistAuthData).toHaveBeenCalledWith(
                expect.objectContaining({ expiresAt: '', absoluteExpiresAt: undefined })
            );
        });

        it('does not persist anything when the profile fetch fails (checkAuth clears the user)', async () => {
            vi.mocked(authService.getProfile).mockRejectedValueOnce(new Error('unauthorized'));

            await useAuthStore.getState().completeSSOLogin('2031-01-01T00:00:00Z');

            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(authUtils.persistAuthData).not.toHaveBeenCalled();
        });
    });

    describe('logout', () => {
        it('clears local state, wipes persisted data, and redirects to /login on success', async () => {
            useAuthStore.setState({
                user: makeUser(),
                isAuthenticated: true,
                impersonatedBy: { adminId: 1, adminUsername: 'admin' },
                error: 'stale error',
            });
            vi.mocked(authService.logout).mockResolvedValueOnce(undefined);

            await useAuthStore.getState().logout();

            expect(authService.logout).toHaveBeenCalledOnce();
            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(state.impersonatedBy).toBeNull();
            expect(state.isLoading).toBe(false);
            expect(state.error).toBeNull();
            expect(authUtils.clearPersistedAuthData).toHaveBeenCalledOnce();
            expect(window.location.href).toBe('/login');
        });

        it('still clears local state and redirects even when the server logout call fails', async () => {
            useAuthStore.setState({ user: makeUser(), isAuthenticated: true });
            vi.mocked(authService.logout).mockRejectedValueOnce(new Error('network blip'));
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

            await useAuthStore.getState().logout();

            expect(warnSpy).toHaveBeenCalledWith('Logout request failed:', expect.any(Error));
            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(authUtils.clearPersistedAuthData).toHaveBeenCalledOnce();
            expect(window.location.href).toBe('/login');

            warnSpy.mockRestore();
        });
    });

    describe('refreshToken', () => {
        it('advances the token expiry bookkeeping and clears any stale error on success', async () => {
            useAuthStore.setState({ error: 'stale error' });
            const response: RefreshTokenResponse = {
                expires_at: '2027-01-01T00:00:00Z',
                absolute_expires_at: '2027-06-01T00:00:00Z',
            };
            vi.mocked(authService.refreshToken).mockResolvedValueOnce(response);

            await useAuthStore.getState().refreshToken();

            expect(useAuthStore.getState().error).toBeNull();
            expect(authUtils.updateTokenExpiry).toHaveBeenCalledWith('2027-01-01T00:00:00Z');
            expect(authUtils.updateAbsoluteTokenExpiry).toHaveBeenCalledWith('2027-06-01T00:00:00Z');
        });

        it('logs the user out and rethrows the original error when the refresh request itself fails', async () => {
            vi.mocked(authService.logout).mockResolvedValueOnce(undefined);
            vi.mocked(authService.refreshToken).mockRejectedValueOnce(new Error('refresh rejected'));

            await expect(useAuthStore.getState().refreshToken()).rejects.toThrow('refresh rejected');

            expect(authService.logout).toHaveBeenCalledOnce();
            expect(window.location.href).toBe('/login');
        });

        it('skips the network round-trip and logs out once the absolute session ceiling has passed', async () => {
            // BUG (documented, not fixed — see PR description): the
            // isAbsoluteExpiryPassed() branch (authStore.ts lines 211-214) calls
            // get().logout() and then throws *inside the same try block* that its
            // own catch (lines 225-228) also wraps. The thrown
            // "Session lifetime exceeded" error is therefore caught by that outer
            // catch too, which calls get().logout() a SECOND time before
            // rethrowing. Net effect: authService.logout() fires twice (and
            // window.location.href is (re-)assigned twice) for a single
            // refreshToken() call whenever the absolute ceiling has passed. This
            // test asserts the actual (buggy) double-call behavior rather than
            // the presumably-intended single call, so a fix will show up here as
            // a legitimate, deliberate test change rather than a silent
            // regression.
            vi.mocked(authUtils.isAbsoluteExpiryPassed).mockReturnValueOnce(true);
            vi.mocked(authService.logout).mockResolvedValue(undefined);

            await expect(useAuthStore.getState().refreshToken()).rejects.toThrow('Session lifetime exceeded');

            expect(authService.refreshToken).not.toHaveBeenCalled();
            expect(authService.logout).toHaveBeenCalledTimes(2);
        });

        it('coalesces concurrent callers onto a single in-flight POST /auth/refresh', async () => {
            let resolveRefresh!: (value: RefreshTokenResponse) => void;
            const pending = new Promise<RefreshTokenResponse>((resolve) => {
                resolveRefresh = resolve;
            });
            vi.mocked(authService.refreshToken).mockReturnValueOnce(pending);

            const first = useAuthStore.getState().refreshToken();
            const second = useAuthStore.getState().refreshToken();

            resolveRefresh({ expires_at: '2027-01-01T00:00:00Z' });
            await expect(Promise.all([first, second])).resolves.toBeDefined();

            expect(authService.refreshToken).toHaveBeenCalledTimes(1);
        });
    });

    describe('checkAuth', () => {
        it('populates the user, marks hasCheckedAuth true, and reports no impersonation on a plain profile', async () => {
            vi.mocked(authService.getProfile).mockResolvedValueOnce(profileFixture(makeUser({ username: 'erin' })));

            await useAuthStore.getState().checkAuth();

            const state = useAuthStore.getState();
            expect(state.isAuthenticated).toBe(true);
            expect(state.isLoading).toBe(false);
            expect(state.hasCheckedAuth).toBe(true);
            expect(state.user?.username).toBe('erin');
            expect(state.impersonatedBy).toBeNull();
        });

        it('redirects to /login when the profile fetch fails and the user is elsewhere', async () => {
            stubLocation('/secrets');
            vi.mocked(authService.getProfile).mockRejectedValueOnce(new Error('unauthorized'));

            await useAuthStore.getState().checkAuth();

            const state = useAuthStore.getState();
            expect(state.user).toBeNull();
            expect(state.isAuthenticated).toBe(false);
            expect(state.hasCheckedAuth).toBe(true);
            expect(authUtils.clearPersistedAuthData).toHaveBeenCalledOnce();
            expect(window.location.href).toBe('/login');
        });

        it('does not re-navigate when the profile fetch fails while already on /login', async () => {
            stubLocation('/login');
            vi.mocked(authService.getProfile).mockRejectedValueOnce(new Error('unauthorized'));

            await useAuthStore.getState().checkAuth();

            expect(window.location.href).toBe('');
            expect(useAuthStore.getState().hasCheckedAuth).toBe(true);
        });

        it('re-entrancy guard: a checkAuth() call in flight makes a concurrent call a no-op', async () => {
            let resolveProfile!: (value: ReturnType<typeof profileFixture>) => void;
            const pending = new Promise<ReturnType<typeof profileFixture>>((resolve) => {
                resolveProfile = resolve;
            });
            vi.mocked(authService.getProfile).mockReturnValueOnce(pending);

            const first = useAuthStore.getState().checkAuth();
            const second = useAuthStore.getState().checkAuth();

            resolveProfile(profileFixture(makeUser({ username: 'frank' })));
            await Promise.all([first, second]);

            expect(authService.getProfile).toHaveBeenCalledTimes(1);
            expect(useAuthStore.getState().user?.username).toBe('frank');
        });
    });

    describe('clearPasswordChangeRequired (ADR-025: lift the password-change gate once changed)', () => {
        it('flips the flag to false on the current user, preserving other fields', () => {
            useAuthStore.setState({ user: makeUser({ username: 'gina', passwordChangeRequired: true }) });

            useAuthStore.getState().clearPasswordChangeRequired();

            const user = useAuthStore.getState().user;
            expect(user?.passwordChangeRequired).toBe(false);
            expect(user?.username).toBe('gina');
        });

        it('is a no-op when there is no current user', () => {
            useAuthStore.setState({ user: null });

            expect(() => useAuthStore.getState().clearPasswordChangeRequired()).not.toThrow();
            expect(useAuthStore.getState().user).toBeNull();
        });
    });

    describe('shouldRefreshToken helper (wraps utils/auth getTimeUntilExpiry)', () => {
        it('is true when the token expires within the next 5 minutes', () => {
            vi.mocked(authUtils.getTimeUntilExpiry).mockReturnValueOnce(60_000);
            expect(shouldRefreshToken()).toBe(true);
        });

        it('is false when the token has already expired (0 remaining)', () => {
            vi.mocked(authUtils.getTimeUntilExpiry).mockReturnValueOnce(0);
            expect(shouldRefreshToken()).toBe(false);
        });

        it('is false when the token has more than 5 minutes left', () => {
            vi.mocked(authUtils.getTimeUntilExpiry).mockReturnValueOnce(10 * 60 * 1000);
            expect(shouldRefreshToken()).toBe(false);
        });
    });

    describe('isTokenExpired helper (wraps utils/auth isTokenValid)', () => {
        it('is true when isTokenValid() reports false', () => {
            vi.mocked(authUtils.isTokenValid).mockReturnValueOnce(false);
            expect(isTokenExpired()).toBe(true);
        });

        it('is false when isTokenValid() reports true', () => {
            vi.mocked(authUtils.isTokenValid).mockReturnValueOnce(true);
            expect(isTokenExpired()).toBe(false);
        });
    });
});
