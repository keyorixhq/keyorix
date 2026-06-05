import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { AuthState, User, LoginFormData, LoginResponse } from '../types';
import { authService } from '../services/auth';
import {
    persistAuthData,
    clearPersistedAuthData,
    updateTokenExpiry,
    isTokenValid,
    getTimeUntilExpiry
} from '../utils/auth';

interface AuthStore extends AuthState {
    // Impersonation (ADR audit-design): while impersonating, `token`/`user` are
    // the target's and the admin's own session is stashed here so the client can
    // swap back without re-authenticating.
    adminToken: string | null;
    adminUser: User | null;
    isImpersonating: boolean;

    // Actions
    login: (credentials: LoginFormData) => Promise<void>;
    // ADR-028: land the user logged in from a setup-link consume response (which is
    // login-shaped) without re-authenticating with a password.
    completeSetup: (response: LoginResponse) => void;
    logout: () => Promise<void>;
    refreshToken: () => Promise<void>;
    checkAuth: () => Promise<void>;
    clearError: () => void;
    setUser: (user: User | null) => void;
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
    // ADR-025: lift the password-change gate once the user has changed it.
    clearPasswordChangeRequired: () => void;
    // Swap the active session to an impersonation token, stashing the admin's.
    startImpersonation: (token: string, impersonatedUser: User) => void;
    // End impersonation: tell the server, then restore the admin's session.
    endImpersonation: () => Promise<void>;
}

export const useAuthStore = create<AuthStore>()(
    persist(
        (set, get) => ({
            // Initial state
            user: null,
            token: null,
            isAuthenticated: false,
            adminToken: null,
            adminUser: null,
            isImpersonating: false,
            isLoading: false,
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
                        token: response.token,
                        isAuthenticated: true,
                        isLoading: false,
                        error: null,
                    });

                    // Persist authentication data
                    persistAuthData({
                        user,
                        token: response.token,
                        expiresAt: response.expires_at,
                        rememberMe: credentials.rememberMe,
                    });
                } catch (error) {
                    const errorMessage = error instanceof Error ? error.message : 'Login failed';
                    set({
                        user: null,
                        token: null,
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
                    token: response.token,
                    isAuthenticated: true,
                    isLoading: false,
                    error: null,
                });

                persistAuthData({
                    user,
                    token: response.token,
                    expiresAt: response.expires_at,
                    rememberMe: false,
                });
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
                        token: null,
                        isAuthenticated: false,
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
                try {
                    const response = await authService.refreshToken();

                    set({
                        token: response.token,
                        error: null,
                    });

                    // Update token expiration
                    updateTokenExpiry(response.expiresAt);
                } catch (error) {
                    // If refresh fails, logout user
                    await get().logout();
                    throw error;
                }
            },

            checkAuth: async () => {
                const state = get();
                if (!state.token) {
                    set({ isLoading: false, isAuthenticated: false, user: null });
                    return;
                }
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
                    };
                    set({ user, isAuthenticated: true, isLoading: false, error: null });
                } catch {
                    set({ user: null, token: null, isAuthenticated: false, isLoading: false });
                    clearPersistedAuthData();
                    window.location.href = '/login';
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

            startImpersonation: (token: string, impersonatedUser: User) => {
                const { token: currentToken, user: currentUser, isImpersonating } = get();
                // Refuse to nest impersonation — stash only the real admin session.
                if (isImpersonating) {
                    return;
                }
                set({
                    adminToken: currentToken,
                    adminUser: currentUser,
                    isImpersonating: true,
                    token,
                    user: impersonatedUser,
                    isAuthenticated: true,
                    error: null,
                });
            },

            endImpersonation: async () => {
                const { adminToken, adminUser, isImpersonating } = get();
                if (!isImpersonating) {
                    return;
                }
                // Best-effort server notify (logs the end event + drops the session).
                try {
                    await authService.endImpersonation();
                } catch (error) {
                    console.warn('End-impersonation request failed:', error);
                }
                set({
                    token: adminToken,
                    user: adminUser,
                    isAuthenticated: !!adminToken,
                    adminToken: null,
                    adminUser: null,
                    isImpersonating: false,
                    error: null,
                });
            },
        }),
        {
            name: 'auth-storage',
            partialize: (state) => ({
                user: state.user,
                token: state.token,
                isAuthenticated: state.isAuthenticated,
                adminToken: state.adminToken,
                adminUser: state.adminUser,
                isImpersonating: state.isImpersonating,
            }),
        }
    )
);

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