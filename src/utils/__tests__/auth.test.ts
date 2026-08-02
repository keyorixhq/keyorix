import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Back the storage layer with a simple in-memory map so we test auth logic in
// isolation (not localStorage/JSON serialization).
const { memStore } = vi.hoisted(() => {
    const map = new Map<string, unknown>();
    return {
        memStore: {
            map,
            get: <T>(key: string, def?: T): T | null => (map.has(key) ? (map.get(key) as T) : (def ?? null)),
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
    getCsrfToken,
    isAbsoluteExpiryPassed,
    getProactiveRefreshDelay,
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

describe('getCsrfToken', () => {
    afterEach(() => {
        document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
    });

    it('returns undefined when no csrf_token cookie is present', () => {
        expect(getCsrfToken()).toBeUndefined();
    });

    it('reads and URL-decodes the csrf_token cookie value', () => {
        document.cookie = 'csrf_token=abc%2F123';
        expect(getCsrfToken()).toBe('abc/123');
    });

    it('finds the cookie among several, regardless of position', () => {
        document.cookie = 'other=1';
        document.cookie = 'csrf_token=tok-456';
        expect(getCsrfToken()).toBe('tok-456');
    });
});

describe('persistAuthData error handling and absolute-expiry ceiling', () => {
    it('writes the absolute ceiling when one is provided', () => {
        persistAuthData({
            user: { id: 1 },
            expiresAt: future(60_000),
            absoluteExpiresAt: future(10 * 60_000),
        });
        expect(memStore.map.has('absoluteExpiresAt')).toBe(true);
    });

    it('logs (without throwing) when the underlying storage write fails', () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const setSpy = vi.spyOn(memStore, 'set').mockImplementationOnce(() => {
            throw new Error('quota exceeded');
        });

        expect(() => persistAuthData({ user: { id: 1 }, expiresAt: future(60_000) })).not.toThrow();
        expect(errorSpy).toHaveBeenCalledWith('Failed to persist auth data:', expect.any(Error));

        setSpy.mockRestore();
        errorSpy.mockRestore();
    });
});

describe('clearPersistedAuthData error handling', () => {
    it('logs (without throwing) when the underlying storage remove fails', () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const removeSpy = vi.spyOn(memStore, 'remove').mockImplementationOnce(() => {
            throw new Error('boom');
        });

        expect(() => clearPersistedAuthData()).not.toThrow();
        expect(errorSpy).toHaveBeenCalledWith('Failed to clear persisted auth data:', expect.any(Error));

        removeSpy.mockRestore();
        errorSpy.mockRestore();
    });
});

describe('isAbsoluteExpiryPassed', () => {
    it('is false when no ceiling is configured', () => {
        expect(isAbsoluteExpiryPassed()).toBe(false);
    });

    it('is false while the ceiling is still in the future', () => {
        updateAbsoluteTokenExpiry(future(10 * 60_000));
        expect(isAbsoluteExpiryPassed()).toBe(false);
    });

    it('is true once the ceiling has passed', () => {
        updateAbsoluteTokenExpiry(past(1_000));
        expect(isAbsoluteExpiryPassed()).toBe(true);
    });
});

describe('getProactiveRefreshDelay', () => {
    it('returns 0 when the token is already expired or unset', () => {
        expect(getProactiveRefreshDelay()).toBe(0);
        updateTokenExpiry(past(1_000));
        expect(getProactiveRefreshDelay()).toBe(0);
    });

    it('returns a delay a short lead before expiry for a comfortably long window', () => {
        updateTokenExpiry(future(10 * 60_000)); // 10 min out
        const delay = getProactiveRefreshDelay();
        // one-minute lead: roughly 9 minutes remain until the delay elapses
        expect(delay).toBeGreaterThan(8 * 60_000);
        expect(delay).toBeLessThanOrEqual(9 * 60_000);
    });

    it('scales the lead down to half the remaining time for a short window', () => {
        updateTokenExpiry(future(20_000)); // 20s out — half is less than the 1-minute lead
        const delay = getProactiveRefreshDelay();
        // lead = min(60_000, 10_000) = 10_000, so delay ~= 10s
        expect(delay).toBeGreaterThan(5_000);
        expect(delay).toBeLessThanOrEqual(10_000);
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
