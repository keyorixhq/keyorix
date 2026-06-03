import { storage } from './index';

// Authentication persistence utilities

export interface AuthPersistenceData {
    user: any;
    token: string;
    expiresAt: string;
    rememberMe: boolean;
}

const AUTH_STORAGE_KEY = 'auth-storage';
const TOKEN_EXPIRY_KEY = 'tokenExpiresAt';
const REMEMBER_ME_KEY = 'rememberMe';

/**
 * Persists authentication data to storage
 */
export const persistAuthData = (data: AuthPersistenceData): void => {
    try {
        // Always store basic auth data
        storage.set(AUTH_STORAGE_KEY, {
            user: data.user,
            token: data.token,
            isAuthenticated: true,
        });

        storage.set(TOKEN_EXPIRY_KEY, data.expiresAt);

        // Store remember me preference
        if (data.rememberMe) {
            storage.set(REMEMBER_ME_KEY, true);
        } else {
            storage.remove(REMEMBER_ME_KEY);
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
        storage.remove(REMEMBER_ME_KEY);
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