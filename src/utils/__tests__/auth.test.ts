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
    clearPersistedAuthData,
    updateTokenExpiry,
    isTokenValid,
    getTimeUntilExpiry,
    shouldRefreshToken,
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

describe('persist / clear', () => {
    it('writes expiry and remember-me, and does NOT clobber the Zustand auth-storage key', () => {
        persistAuthData({
            user: { id: 1, username: 'testuser' },
            token: 'tok-1',
            expiresAt: future(60_000),
            rememberMe: true,
        });
        // Regression guard: the `auth-storage` key is owned by Zustand's persist
        // middleware ({state,version}). persistAuthData must never write it — a
        // flat write broke rehydration on reload (deep routes bounced to /login).
        expect(memStore.map.has('auth-storage')).toBe(false);
        expect(memStore.map.get('rememberMe')).toBe(true);
        // the expiry write is observable through the public token API
        expect(isTokenValid()).toBe(true);
    });

    it('omits the remember-me flag when not requested', () => {
        persistAuthData({
            user: { id: 1 },
            token: 'tok-2',
            expiresAt: future(60_000),
            rememberMe: false,
        });
        expect(memStore.map.has('rememberMe')).toBe(false);
    });

    it('clear removes all persisted auth data', () => {
        persistAuthData({
            user: { id: 1 },
            token: 'tok-4',
            expiresAt: future(60_000),
            rememberMe: true,
        });
        clearPersistedAuthData();
        expect(memStore.map.has('auth-storage')).toBe(false);
        expect(memStore.map.has('tokenExpiresAt')).toBe(false);
        expect(memStore.map.has('rememberMe')).toBe(false);
        expect(isTokenValid()).toBe(false);
    });
});
