import { describe, it, expect, beforeEach, vi } from 'vitest';

// Back the storage layer with a simple in-memory map so we test auth logic in
// isolation (not localStorage/JSON serialization).
const { memStore } = vi.hoisted(() => {
    const map = new Map<string, unknown>();
    return {
        memStore: {
            map,
            get: <T>(key: string, def?: T): T | null =>
                map.has(key) ? (map.get(key) as T) : (def ?? null),
            set: (key: string, value: unknown): void => {
                map.set(key, value);
            },
            remove: (key: string): void => {
                map.delete(key);
            },
        },
    };
});

vi.mock('../index', () => ({ storage: memStore }));

import {
    persistAuthData,
    getPersistedAuthData,
    clearPersistedAuthData,
    hasRememberMe,
    updateTokenExpiry,
    isTokenValid,
    getTimeUntilExpiry,
    shouldRefreshToken,
    shouldRestoreSession,
    getCurrentAuthState,
} from '../auth';

const future = (ms: number) => new Date(Date.now() + ms).toISOString();
const past = (ms: number) => new Date(Date.now() - ms).toISOString();

beforeEach(() => {
    memStore.map.clear();
});

describe('isTokenValid', () => {
    it('is false with no expiry stored', () => {
        expect(isTokenValid()).toBe(false);
    });
    it('is true for a future expiry and false for a past one', () => {
        updateTokenExpiry(future(60_000));
        expect(isTokenValid()).toBe(true);
        updateTokenExpiry(past(1_000));
        expect(isTokenValid()).toBe(false);
    });
});

describe('getTimeUntilExpiry', () => {
    it('returns 0 when unset or already expired', () => {
        expect(getTimeUntilExpiry()).toBe(0);
        updateTokenExpiry(past(5_000));
        expect(getTimeUntilExpiry()).toBe(0);
    });
    it('returns a positive remaining window for a future expiry', () => {
        updateTokenExpiry(future(120_000));
        const remaining = getTimeUntilExpiry();
        expect(remaining).toBeGreaterThan(0);
        expect(remaining).toBeLessThanOrEqual(120_000);
    });
});

describe('shouldRefreshToken', () => {
    it('is true only inside the 5-minute pre-expiry window', () => {
        updateTokenExpiry(future(2 * 60_000)); // 2 min out
        expect(shouldRefreshToken()).toBe(true);

        updateTokenExpiry(future(10 * 60_000)); // 10 min out
        expect(shouldRefreshToken()).toBe(false);

        memStore.map.clear(); // no expiry
        expect(shouldRefreshToken()).toBe(false);
    });
});

describe('persist / retrieve / clear', () => {
    it('round-trips valid auth data', () => {
        persistAuthData({
            user: { id: 1, username: 'testuser' },
            token: 'tok-1',
            expiresAt: future(60_000),
            rememberMe: true,
        });

        const data = getPersistedAuthData();
        expect(data?.token).toBe('tok-1');
        expect((data?.user as { username: string }).username).toBe('testuser');
        expect(data?.rememberMe).toBe(true);
        expect(hasRememberMe()).toBe(true);
    });

    it('drops "remember me" when not requested', () => {
        persistAuthData({
            user: { id: 1 },
            token: 'tok-2',
            expiresAt: future(60_000),
            rememberMe: false,
        });
        expect(hasRememberMe()).toBe(false);
    });

    it('returns null and self-clears once the token has expired', () => {
        persistAuthData({
            user: { id: 1 },
            token: 'tok-3',
            expiresAt: past(1_000),
            rememberMe: true,
        });
        expect(getPersistedAuthData()).toBeNull();
    });

    it('clear removes all persisted auth data', () => {
        persistAuthData({
            user: { id: 1 },
            token: 'tok-4',
            expiresAt: future(60_000),
            rememberMe: true,
        });
        clearPersistedAuthData();
        expect(getPersistedAuthData()).toBeNull();
        expect(hasRememberMe()).toBe(false);
    });
});

describe('getCurrentAuthState', () => {
    it('reflects the logged-out state by default', () => {
        expect(getCurrentAuthState()).toEqual({
            isAuthenticated: false,
            user: null,
            token: null,
            rememberMe: false,
        });
    });

    it('reflects a persisted, valid session', () => {
        persistAuthData({
            user: { id: 9, username: 'admin' },
            token: 'tok-9',
            expiresAt: future(60_000),
            rememberMe: true,
        });
        const state = getCurrentAuthState();
        expect(state.isAuthenticated).toBe(true);
        expect(state.token).toBe('tok-9');
        expect(state.rememberMe).toBe(true);
    });
});

describe('shouldRestoreSession', () => {
    it('is false with nothing persisted', () => {
        expect(shouldRestoreSession()).toBe(false);
    });
    it('is true for a valid remember-me session', () => {
        persistAuthData({
            user: { id: 1 },
            token: 'tok',
            expiresAt: future(60_000),
            rememberMe: true,
        });
        expect(shouldRestoreSession()).toBe(true);
    });
});
