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
    updateAbsoluteTokenExpiry,
    getTimeUntilAbsoluteExpiry,
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
    it('writes expiry, and does NOT clobber the Zustand auth-storage key', () => {
        persistAuthData({
            user: { id: 1, username: 'testuser' },
            token: 'tok-1',
            expiresAt: future(60_000),
        });
        // Regression guard: the `auth-storage` key is owned by Zustand's persist
        // middleware ({state,version}). persistAuthData must never write it — a
        // flat write broke rehydration on reload (deep routes bounced to /login).
        expect(memStore.map.has('auth-storage')).toBe(false);
        // the expiry write is observable through the public token API
        expect(isTokenValid()).toBe(true);
    });

    it('clear removes all persisted auth data', () => {
        persistAuthData({
            user: { id: 1 },
            token: 'tok-4',
            expiresAt: future(60_000),
        });
        clearPersistedAuthData();
        expect(memStore.map.has('auth-storage')).toBe(false);
        expect(memStore.map.has('tokenExpiresAt')).toBe(false);
        expect(isTokenValid()).toBe(false);
    });
});

describe('getTimeUntilAbsoluteExpiry', () => {
    it('returns null when no ceiling is configured', () => {
        expect(getTimeUntilAbsoluteExpiry()).toBeNull();
    });

    it('returns remaining ms when the ceiling is in the future', () => {
        updateAbsoluteTokenExpiry(future(10 * 60_000));
        const ms = getTimeUntilAbsoluteExpiry();
        expect(ms).not.toBeNull();
        expect(ms!).toBeGreaterThan(9 * 60_000);
        expect(ms!).toBeLessThanOrEqual(10 * 60_000);
    });

    it('clamps to 0 once the ceiling has passed', () => {
        updateAbsoluteTokenExpiry(past(60_000));
        expect(getTimeUntilAbsoluteExpiry()).toBe(0);
    });

    it('returns null again after the ceiling is cleared', () => {
        updateAbsoluteTokenExpiry(future(60_000));
        expect(getTimeUntilAbsoluteExpiry()).not.toBeNull();
        updateAbsoluteTokenExpiry(undefined);
        expect(getTimeUntilAbsoluteExpiry()).toBeNull();
    });
});
