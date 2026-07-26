import { storage } from './index';

// Authentication persistence utilities

export interface AuthPersistenceData {
    user: any;
    expiresAt: string;
    // Hard ceiling on total session lifetime (backend absolute_expires_at). When
    // set, refresh is refused past it and the user must re-authenticate. Omitted
    // when the install runs with no absolute ceiling (refreshable indefinitely).
    // Explicit `| undefined` so callers may pass the (often-absent) backend field
    // directly under exactOptionalPropertyTypes.
    absoluteExpiresAt?: string | undefined;
}

const AUTH_STORAGE_KEY = 'auth-storage';
const TOKEN_EXPIRY_KEY = 'tokenExpiresAt';
const ABSOLUTE_EXPIRY_KEY = 'absoluteExpiresAt';

// CSRF double-submit cookie (Phase 1 auth-cookie migration): the backend sets a
// JS-readable csrf_token cookie alongside the HttpOnly session cookie; both
// axios instances (services/client.ts, services/auth.ts) echo it back as
// X-CSRF-Token on state-changing requests. Shared here rather than duplicated
// in each — this has no dependency on authStore, so no circular-import
// constraint applies (unlike the token-read logic those two files used to
// duplicate for that reason).
const CSRF_COOKIE_NAME = 'csrf_token';
export const CSRF_HEADER_NAME = 'X-CSRF-Token';
export const CSRF_PROTECTED_METHODS = new Set(['post', 'put', 'patch', 'delete']);

export function getCsrfToken(): string | undefined {
    const match = document.cookie.match(new RegExp(`(?:^|; )${CSRF_COOKIE_NAME}=([^;]*)`));
    return match?.[1] ? decodeURIComponent(match[1]) : undefined;
}

/**
 * Persists authentication data to storage
 */
export const persistAuthData = (data: AuthPersistenceData): void => {
    try {
        // IMPORTANT: the `auth-storage` key is owned exclusively by the Zustand
        // `persist` middleware, which serialises a `{state, version}` wrapper.
        // Writing a flat `{user, isAuthenticated}` object here clobbers that
        // wrapper, so on the next reload Zustand can't rehydrate — the session is
        // lost and a deep route (e.g. /admin/users) bounces to /login. Zustand
        // already persists user/isAuthenticated via its `partialize`, so we only
        // own the token-expiry key here (the session credential itself is an
        // httpOnly cookie — this repo never sees or stores its value).
        storage.set(TOKEN_EXPIRY_KEY, data.expiresAt);

        // Absolute ceiling (optional). Remove a stale value when this login has
        // no ceiling, so an earlier capped session can't leave a ceiling behind.
        if (data.absoluteExpiresAt) {
            storage.set(ABSOLUTE_EXPIRY_KEY, data.absoluteExpiresAt);
        } else {
            storage.remove(ABSOLUTE_EXPIRY_KEY);
        }
    } catch (error) {
        console.error('Failed to persist auth data:', error);
    }
};

/**
 * Clears all persisted authentication data
 */
export const clearPersistedAuthData = (): void => {
    try {
        storage.remove(AUTH_STORAGE_KEY);
        storage.remove(TOKEN_EXPIRY_KEY);
        storage.remove(ABSOLUTE_EXPIRY_KEY);
    } catch (error) {
        console.error('Failed to clear persisted auth data:', error);
    }
};

/**
 * Updates the token expiration time
 */
export const updateTokenExpiry = (expiresAt: string): void => {
    storage.set(TOKEN_EXPIRY_KEY, expiresAt);
};

/**
 * Updates (or clears) the absolute session-lifetime ceiling. A refresh that
 * returns no ceiling clears any prior value.
 */
export const updateAbsoluteTokenExpiry = (absoluteExpiresAt?: string): void => {
    if (absoluteExpiresAt) {
        storage.set(ABSOLUTE_EXPIRY_KEY, absoluteExpiresAt);
    } else {
        storage.remove(ABSOLUTE_EXPIRY_KEY);
    }
};

/**
 * True once the absolute session-lifetime ceiling has passed: refresh is no
 * longer possible and the user must re-authenticate. Always false when no
 * ceiling is configured (the session is refreshable indefinitely).
 */
export const isAbsoluteExpiryPassed = (): boolean => {
    const absolute = storage.get<string>(ABSOLUTE_EXPIRY_KEY);
    if (!absolute) {
        return false;
    }
    return new Date(absolute).getTime() <= Date.now();
};

/**
 * Milliseconds until the absolute session-lifetime ceiling, or null when no
 * ceiling is configured (the session is refreshable indefinitely, so there is
 * nothing to warn about). Clamped at 0 once the ceiling has passed.
 */
export const getTimeUntilAbsoluteExpiry = (): number | null => {
    const absolute = storage.get<string>(ABSOLUTE_EXPIRY_KEY);
    if (!absolute) {
        return null;
    }
    return Math.max(0, new Date(absolute).getTime() - Date.now());
};

/**
 * Validates if a token is still valid based on expiration time
 */
export const isTokenValid = (): boolean => {
    const expiresAt = storage.get<string>(TOKEN_EXPIRY_KEY);

    if (!expiresAt) {
        return false;
    }

    return new Date(expiresAt).getTime() > Date.now();
};

/**
 * Gets time until token expires in milliseconds
 */
export const getTimeUntilExpiry = (): number => {
    const expiresAt = storage.get<string>(TOKEN_EXPIRY_KEY);

    if (!expiresAt) {
        return 0;
    }

    return Math.max(0, new Date(expiresAt).getTime() - Date.now());
};

/**
 * Checks if token needs refresh (expires within 5 minutes)
 */
export const shouldRefreshToken = (): boolean => {
    const timeUntilExpiry = getTimeUntilExpiry();
    const fiveMinutes = 5 * 60 * 1000;

    return timeUntilExpiry > 0 && timeUntilExpiry < fiveMinutes;
};

/**
 * Milliseconds the proactive background timer should wait before refreshing the
 * access token: a short lead before expiry so the new token is in hand before the
 * old one lapses. The lead scales down for short windows so it never exceeds half
 * the remaining time (which would refresh-storm on a very short TTL). Returns 0
 * when the token is already expired/unset, so the timer refreshes immediately.
 */
export const getProactiveRefreshDelay = (): number => {
    const timeUntilExpiry = getTimeUntilExpiry();
    if (timeUntilExpiry <= 0) {
        return 0;
    }
    const oneMinute = 60 * 1000;
    const lead = Math.min(oneMinute, timeUntilExpiry / 2);
    return Math.max(0, timeUntilExpiry - lead);
};
