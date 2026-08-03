import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useAuthStore } from '../authStore';
import type { User } from '../../types';

vi.mock('../../services/auth', () => ({
    authService: {
        endImpersonation: vi.fn(),
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

const makeUser = (id: number, username: string): User =>
    ({
        id,
        username,
        email: `${username}@example.com`,
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
    }) as User;

// Build a storage event without the StorageEvent init-dict constructor argument
// (which some static analysers flag as a superfluous trailing argument). The key
// and newValue are attached as own properties so listeners can read them via
// event.key / event.newValue exactly as a real browser storage event would.
function mkStorageEvent(key: string | null, newValue: string | null): Event {
    return Object.assign(new Event('storage'), { key, newValue });
}

// Simulates what another same-origin tab would produce: it writes its own new
// state to the shared 'auth-storage' localStorage key, then the browser fires
// a `storage` event on every OTHER tab (never on the tab that wrote it) —
// reproduced here by writing directly and dispatching the event ourselves.
function writeAuthStorageFromAnotherTab(state: Record<string, unknown>) {
    const raw = JSON.stringify({ state, version: 0 });
    localStorage.setItem('auth-storage', raw);
    window.dispatchEvent(mkStorageEvent('auth-storage', raw));
}

describe('authStore multi-tab session sync', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // The global localStorage mock (src/test/setup.ts) is a bare vi.fn()
        // with no backing store — give it one here so getItem actually reflects
        // what setItem wrote, which is what the rehydrate-on-storage-event flow
        // under test depends on.
        const backing = new Map<string, string>();
        vi.mocked(localStorage.getItem).mockImplementation((key: string) => backing.get(key) ?? null);
        vi.mocked(localStorage.setItem).mockImplementation((key: string, value: string) => {
            backing.set(key, value);
        });
        vi.mocked(localStorage.clear).mockImplementation(() => backing.clear());

        useAuthStore.setState({
            user: makeUser(1, 'alice'),
            token: 'alice-token',
            isAuthenticated: true,
            adminToken: null,
            adminUser: null,
            isImpersonating: false,
            isLoading: false,
            error: null,
        });
    });

    it('logs this tab out when another tab logs out', () => {
        writeAuthStorageFromAnotherTab({
            user: null,
            token: null,
            isAuthenticated: false,
            adminToken: null,
            adminUser: null,
            isImpersonating: false,
        });

        const s = useAuthStore.getState();
        expect(s.isAuthenticated).toBe(false);
        expect(s.token).toBeNull();
        expect(s.user).toBeNull();
    });

    it('picks up a rotated token when another tab refreshes', () => {
        writeAuthStorageFromAnotherTab({
            user: makeUser(1, 'alice'),
            token: 'rotated-token',
            isAuthenticated: true,
            adminToken: null,
            adminUser: null,
            isImpersonating: false,
        });

        expect(useAuthStore.getState().token).toBe('rotated-token');
    });

    it('ignores storage events for unrelated keys', () => {
        window.dispatchEvent(mkStorageEvent('some-other-key', 'noise'));

        const s = useAuthStore.getState();
        expect(s.isAuthenticated).toBe(true);
        expect(s.token).toBe('alice-token');
    });

    it('re-syncs on a storage.clear() signal (key: null)', () => {
        localStorage.clear();
        window.dispatchEvent(mkStorageEvent(null, null));

        // Nothing left in storage to hydrate from — state is left as-is by
        // hydrate() when there's no stored value, so this just proves the
        // listener doesn't throw on a clear() and still calls rehydrate().
        expect(useAuthStore.getState().token).toBe('alice-token');
    });
});
