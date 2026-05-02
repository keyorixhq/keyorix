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
 * Retrieves persisted authentication data
 */
export const getPersistedAuthData = (): Partial<AuthPersistenceData> | null => {
    try {
        const authData = storage.get(AUTH_STORAGE_KEY);
        const expiresAt = storage.get<string>(TOKEN_EXPIRY_KEY);
        const rememberMe = storage.get<boolean>(REMEMBER_ME_KEY) || false;

        if (!authData || !expiresAt) {
            return null;
        }

        // Check if token is expired
        if (new Date(expiresAt).getTime() <= Date.now()) {
            clearPersistedAuthData();
            return null;
        }

        return {
            user: (authData as any).user,
            token: (authData as any).token,
            expiresAt,
            rememberMe,
        };
    } catch (error) {
        console.error('Failed to retrieve persisted auth data:', error);
        return null;
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
 * Checks if the user has "remember me" enabled
 */
export const hasRememberMe = (): boolean => {
    return storage.get<boolean>(REMEMBER_ME_KEY) || false;
};

/**
 * Updates the token expiration time
 */
export const updateTokenExpiry = (expiresAt: string): void => {
    storage.set(TOKEN_EXPIRY_KEY, expiresAt);
};

/**
 * Checks if the current session should be restored
 * This considers both token expiry and remember me preference
 */
export const shouldRestoreSession = (): boolean => {
    const persistedData = getPersistedAuthData();

    if (!persistedData) {
        return false;
    }

    // If user didn't check "remember me", only restore if session is recent
    if (!persistedData.rememberMe) {
        const sessionAge = Date.now() - new Date(persistedData.expiresAt!).getTime();
        const maxSessionAge = 24 * 60 * 60 * 1000; // 24 hours

        return sessionAge < maxSessionAge;
    }

    // If "remember me" is enabled, restore as long as token is valid
    return true;
};

/**
 * Gets the current authentication state from storage
 */
export const getCurrentAuthState = () => {
    const persistedData = getPersistedAuthData();

    return {
        isAuthenticated: !!persistedData,
        user: persistedData?.user || null,
        token: persistedData?.token || null,
        rememberMe: persistedData?.rememberMe || false,
    };
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