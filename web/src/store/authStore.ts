import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { AuthState, User, LoginFormData, LoginResponse, ImpersonatedBy } from '../types';
import { authService } from '../services/auth';
import {
    persistAuthData,
    clearPersistedAuthData,
    updateTokenExpiry,
    updateAbsoluteTokenExpiry,
    isAbsoluteExpiryPassed,
    isTokenValid,
    getTimeUntilExpiry,
} from '../utils/auth';

interface AuthStore extends AuthState {
    // Impersonation state is now derived entirely from the server (GET
    // /auth/profile's `impersonation` field, populated from the session — see
    // checkAuth) rather than tracked client-side. Under cookie auth there is no
    // client-readable token to stash/swap, so "return to admin" is resolved
    // server-side by the backend's OriginalSessionID linkage; the client's job
    // is just to call the endpoints and re-sync via checkAuth().
    impersonatedBy: ImpersonatedBy | null;

    // Actions
    login: (credentials: LoginFormData) => Promise<void>;
    // ADR-028: land the user logged in from a setup-link consume response (which is
    // login-shaped) without re-authenticating with a password.
    completeSetup: (response: LoginResponse) => void;
    // Land the user logged in from an SSO callback: the backend has already set
    // the session cookie on its redirect response, so this just loads the
    // profile and persists the expiry bookkeeping.
    completeSSOLogin: (expiresAt?: string, absoluteExpiresAt?: string) => Promise<void>;
    logout: () => Promise<void>;
    refreshToken: () => Promise<void>;
    checkAuth: () => Promise<void>;
    clearError: () => void;
    setUser: (user: User | null) => void;
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
    // ADR-025: lift the password-change gate once the user has changed it.
    clearPasswordChangeRequired: () => void;
    // End impersonation: tell the server (which restores the admin's original
    // session cookie, or clears it if that session is gone), then re-sync.
    endImpersonation: () => Promise<void>;
}

// Shared in-flight refresh promise so concurrent callers coalesce onto a single
// POST /auth/refresh (see refreshToken). Module-scoped: there is one auth store.
let inFlightRefresh: Promise<void> | null = null;

// Re-entrancy guard for checkAuth, separate from isLoading — isLoading starts
// true by design (to hold route guards in the spinner state until the first
// check resolves), so gating checkAuth on isLoading would make its own very
// first call a no-op.
let checkAuthInFlight = false;

export const useAuthStore = create<AuthStore>()(
    persist(
        (set, get) => ({
            // Initial state — isLoading: true holds every route guard in the
            // spinner state until rehydrate() + checkAuth() have both resolved.
            // skipHydration (below) prevents the persist middleware from loading
            // stale localStorage values synchronously before the server validates
            // the session, which would let a manipulated auth-storage entry pass
            // ProtectedRoute before checkAuth fires.
            user: null,
            isAuthenticated: false,
            impersonatedBy: null,
            isLoading: true,
            hasCheckedAuth: false,
            error: null,

            // Actions
            login: async (credentials: LoginFormData) => {
                set({ isLoading: true, error: null });

                try {
                    const response = await authService.login(credentials);

                    const user: User = {
                        id: response.user_id,
                        username: response.username,
                        displayName: response.display_name || response.username,
                        email: response.email,
                        role: response.role || 'user',
                        roles: response.roles || [],
                        permissions: response.permissions || [],
                        preferences: {
                            language: 'en',
                            timezone: 'UTC',
                            theme: 'system',
                            notifications: { email: true, browser: true, sharing: true, security: true },
                        },
                        lastLogin: new Date().toISOString(),
                        passwordChangeRequired: response.password_change_required || false,
                        ...(response.account_state ? { accountState: response.account_state } : {}),
                    };

                    set({
                        user,
                        isAuthenticated: true,
                        isLoading: false,
                        error: null,
                    });

                    // Persist non-credential bookkeeping (the session itself is now an
                    // httpOnly cookie — there is no token for the client to hold).
                    persistAuthData({
                        user,
                        expiresAt: response.expires_at,
                        absoluteExpiresAt: response.absolute_expires_at,
                    });
                } catch (error) {
                    const errorMessage = error instanceof Error ? error.message : 'Login failed';
                    set({
                        user: null,
                        isAuthenticated: false,
                        isLoading: false,
                        error: errorMessage,
                    });
                    throw error;
                }
            },

            completeSetup: (response: LoginResponse) => {
                const user: User = {
                    id: response.user_id,
                    username: response.username,
                    displayName: response.display_name || response.username,
                    email: response.email,
                    role: response.role || 'user',
                    roles: response.roles || [],
                    permissions: response.permissions || [],
                    preferences: {
                        language: 'en',
                        timezone: 'UTC',
                        theme: 'system',
                        notifications: { email: true, browser: true, sharing: true, security: true },
                    },
                    lastLogin: new Date().toISOString(),
                    passwordChangeRequired: response.password_change_required || false,
                    ...(response.account_state ? { accountState: response.account_state } : {}),
                };

                set({
                    user,
                    isAuthenticated: true,
                    isLoading: false,
                    error: null,
                });

                persistAuthData({
                    user,
                    expiresAt: response.expires_at,
                    absoluteExpiresAt: response.absolute_expires_at,
                });
            },

            completeSSOLogin: async (expiresAt?: string, absoluteExpiresAt?: string) => {
                // The backend already set the session cookie on its redirect response
                // (see sso.go/saml.go) — nothing to stash here, just load the profile.
                set({ isLoading: true, error: null });
                await get().checkAuth(); // populates user, or clears + redirects on failure
                const user = get().user;
                if (user) {
                    persistAuthData({
                        user,
                        expiresAt: expiresAt ?? '',
                        absoluteExpiresAt,
                    });
                }
            },

            logout: async () => {
                set({ isLoading: true });

                try {
                    await authService.logout();
                } catch (error) {
                    console.warn('Logout request failed:', error);
                } finally {
                    // Always clear local state regardless of server response
                    set({
                        user: null,
                        isAuthenticated: false,
                        impersonatedBy: null,
                        isLoading: false,
                        error: null,
                    });

                    // Clear stored data
                    clearPersistedAuthData();
                    // Redirect to login
                    window.location.href = '/login';
                }
            },

            refreshToken: async () => {
                // Single-flight: several in-flight requests can hit expiry at once.
                // Without dedup each would POST /auth/refresh and rotate the session
                // cookie out from under the others (every rotation deletes the prior
                // session → cascading 401s). Share one refresh across concurrent
                // callers instead.
                if (inFlightRefresh) {
                    return inFlightRefresh;
                }
                inFlightRefresh = (async () => {
                    try {
                        // Past the absolute ceiling there is nothing to refresh into —
                        // re-authentication is required. Skip the round-trip and log out.
                        if (isAbsoluteExpiryPassed()) {
                            await get().logout();
                            throw new Error('Session lifetime exceeded');
                        }

                        try {
                            const response = await authService.refreshToken();
                            set({ error: null });

                            // Advance the access window and carry the (possibly absent)
                            // ceiling. Note: the field is expires_at to match the backend
                            // payload — reading the old camelCase expiresAt silently stored
                            // undefined and logged the user out on the next request.
                            updateTokenExpiry(response.expires_at);
                            updateAbsoluteTokenExpiry(response.absolute_expires_at);
                        } catch (error) {
                            // If refresh fails, logout user
                            await get().logout();
                            throw error;
                        }
                    } finally {
                        inFlightRefresh = null;
                    }
                })();
                return inFlightRefresh;
            },

            checkAuth: async () => {
                // Always attempt the profile fetch — under cookie auth there is no
                // client-visible token to gate on; a 401 from the request itself is
                // the only way to know the session is gone.
                if (checkAuthInFlight) return;
                checkAuthInFlight = true;
                set({ isLoading: true });
                try {
                    const profile = await authService.getProfile();
                    const user: User = {
                        id: profile.id,
                        username: profile.username,
                        email: profile.email,
                        role: profile.role || 'user',
                        roles: profile.roles || [],
                        permissions: profile.permissions || [],
                        preferences: profile.preferences || {
                            language: 'en',
                            timezone: 'UTC',
                            theme: 'system',
                            notifications: { email: true, browser: true, sharing: true, security: true },
                        },
                        lastLogin: profile.lastLogin || new Date().toISOString(),
                        // Carry the server's flag forward on every reload so
                        // RequirePasswordChange stays effective past the first session.
                        passwordChangeRequired: profile.passwordChangeRequired ?? false,
                    };
                    // impersonation is present only while the session is actively
                    // impersonating — server-validated, not a client claim (see
                    // services/auth.ts's getProfile doc comment).
                    const impersonatedBy = profile.impersonation
                        ? {
                              adminId: profile.impersonation.admin_id,
                              adminUsername: profile.impersonation.admin_username,
                              adminDisplayName: profile.impersonation.admin_display_name,
                          }
                        : null;
                    set({ user, isAuthenticated: true, isLoading: false, error: null, impersonatedBy });
                } catch {
                    set({ user: null, isAuthenticated: false, isLoading: false, impersonatedBy: null });
                    clearPersistedAuthData();
                    if (window.location.pathname !== '/login') {
                        window.location.href = '/login';
                    }
                } finally {
                    checkAuthInFlight = false;
                    set({ hasCheckedAuth: true });
                }
            },

            clearError: () => {
                set({ error: null });
            },

            setUser: (user: User | null) => {
                set({ user, isAuthenticated: !!user });
            },

            setLoading: (loading: boolean) => {
                set({ isLoading: loading });
            },

            setError: (error: string | null) => {
                set({ error });
            },

            clearPasswordChangeRequired: () => {
                const { user } = get();
                if (user) {
                    set({ user: { ...user, passwordChangeRequired: false } });
                }
            },

            endImpersonation: async () => {
                // The server restores the admin's original session cookie (or clears
                // it if that session is gone) as part of this call — see
                // internal/core/impersonation.go's EndImpersonation and the
                // OriginalSessionID linkage. The client never holds a second
                // credential to swap back to; checkAuth() re-syncs to whichever
                // session is now active. If the request itself fails (network blip,
                // backend hiccup), this rejects without touching local state, so the
                // caller (ImpersonationBanner) can offer a retry instead of a false
                // "you're back to normal" UI.
                await authService.endImpersonation();
                await get().checkAuth();
            },
        }),
        {
            name: 'auth-storage',
            partialize: (state) => ({
                user: state.user,
                isAuthenticated: state.isAuthenticated,
            }),
            // Prevent synchronous localStorage hydration on store creation.
            // Without this, persist rehydrates before checkAuth runs, so a
            // manipulated auth-storage entry (isAuthenticated: true, role:
            // 'admin') would pass ProtectedRoute/AdminRoute for the first
            // render cycle. useAuth's init() calls rehydrate() + checkAuth()
            // in sequence under isLoading: true, which keeps the guards in the
            // spinner state until the server validates the session.
            skipHydration: true,
        }
    )
);

// Multi-tab session sync: zustand's persist writes every state change to the
// 'auth-storage' localStorage key, but only OTHER tabs get a native `storage`
// event for it (the tab that made the change doesn't). Without this, a logout
// or token refresh in one tab left every other open tab holding a stale,
// possibly-revoked token in memory until it happened to make its own request
// and get a 401. Re-hydrating here on every cross-tab change (including a
// storage.clear(), signaled by event.key === null) keeps all tabs in sync with
// whichever tab last wrote the session state.
if (typeof window !== 'undefined') {
    window.addEventListener('storage', (event) => {
        if (event.key === 'auth-storage' || event.key === null) {
            // Re-validate with the server after accepting cross-tab state.
            // Rehydrate alone is insufficient: a tampered auth-storage written
            // by another same-origin context would set isAuthenticated: true
            // without the session cookie that actually lets API calls through.
            Promise.resolve(useAuthStore.persist.rehydrate()).then(() => {
                const { isAuthenticated } = useAuthStore.getState();
                if (isAuthenticated) {
                    useAuthStore.getState().checkAuth();
                }
            });
        }
    });
}

// Helper function to check if token needs refresh
export const shouldRefreshToken = (): boolean => {
    const timeUntilExpiry = getTimeUntilExpiry();
    const fiveMinutes = 5 * 60 * 1000;

    return timeUntilExpiry > 0 && timeUntilExpiry < fiveMinutes;
};

// Helper function to check if token is expired
export const isTokenExpired = (): boolean => {
    return !isTokenValid();
};
