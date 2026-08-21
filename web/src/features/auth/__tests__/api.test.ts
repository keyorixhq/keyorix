import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';

// useAuth wraps the real zustand authStore; mock it wholesale so we control
// exactly what state/actions it exposes without touching persistence or
// network. useAuthStore.persist.rehydrate() is called as a static method on
// the hook itself (not via its return value), so the mock needs that too.
// vi.hoisted() runs before the vi.mock() factory so these stubs are in scope there.
const { login, logout, refreshToken, checkAuth, clearError, setError, rehydrate } = vi.hoisted(() => ({
    login: vi.fn(),
    logout: vi.fn(),
    refreshToken: vi.fn(),
    checkAuth: vi.fn().mockResolvedValue(undefined),
    clearError: vi.fn(),
    setError: vi.fn(),
    rehydrate: vi.fn().mockResolvedValue(undefined),
}));

let storeState: {
    user: any;
    isAuthenticated: boolean;
    isLoading: boolean;
    hasCheckedAuth: boolean;
    error: string | null;
};

vi.mock('../../../store/authStore', () => {
    const useAuthStore: any = () => storeState;
    useAuthStore.persist = { rehydrate };
    return { useAuthStore };
});

import { useAuth } from '../api';

function wrapper({ children }: { children: React.ReactNode }) {
    return React.createElement(React.Fragment, null, children);
}

beforeEach(() => {
    vi.clearAllMocks();
    rehydrate.mockResolvedValue(undefined);
    checkAuth.mockResolvedValue(undefined);
    storeState = {
        user: null,
        isAuthenticated: false,
        isLoading: false,
        hasCheckedAuth: false,
        error: null,
    };
    // useAuthStore() destructures login/logout/etc from its own return value,
    // so those actions must live on storeState too.
    Object.assign(storeState, { login, logout, refreshToken, checkAuth, clearError, setError });
});

// ── mount-once bootstrap ─────────────────────────────────────────────────────
// Regression coverage for the documented "must run exactly once per page
// load" contract: a module-level `didInit` flag guards this effect so that
// every component calling useAuth() doesn't re-trigger rehydrate/checkAuth
// (which previously caused an infinite loading loop — see project history).
// Because that flag is module-level, these two tests are order-dependent and
// must run in this sequence within the file.

describe('useAuth bootstrap', () => {
    it('rehydrates and checks auth exactly once on the first mount', async () => {
        renderHook(() => useAuth(), { wrapper });
        await waitFor(() => expect(checkAuth).toHaveBeenCalledTimes(1));
        expect(rehydrate).toHaveBeenCalledTimes(1);
    });

    it('does not re-run the bootstrap for a second mounted consumer', async () => {
        renderHook(() => useAuth(), { wrapper });
        // Give any effect a tick to (not) fire.
        await act(async () => {});
        expect(rehydrate).toHaveBeenCalledTimes(0);
        expect(checkAuth).toHaveBeenCalledTimes(0);
    });
});

// ── computed values ──────────────────────────────────────────────────────────

describe('useAuth computed values', () => {
    it('defaults roles/permissions to [] and isAdmin to false with no user', () => {
        const { result } = renderHook(() => useAuth(), { wrapper });
        expect(result.current.isAdmin).toBe(false);
        expect(result.current.roles).toEqual([]);
        expect(result.current.permissions).toEqual([]);
        expect(result.current.hasPermission('secrets.read')).toBe(false);
    });

    it('derives isAdmin from an admin role and exposes roles/permissions', () => {
        storeState.user = { role: 'system_admin', roles: ['system_admin'], permissions: ['secrets.read'] };
        const { result } = renderHook(() => useAuth(), { wrapper });
        expect(result.current.isAdmin).toBe(true);
        expect(result.current.roles).toEqual(['system_admin']);
        expect(result.current.hasPermission('secrets.read')).toBe(true);
        expect(result.current.hasPermission('secrets.write')).toBe(false);
    });

    it('isAdmin is false for a non-admin role', () => {
        storeState.user = { role: 'viewer', roles: ['viewer'] };
        const { result } = renderHook(() => useAuth(), { wrapper });
        expect(result.current.isAdmin).toBe(false);
    });
});

// ── session timeout ───────────────────────────────────────────────────────────

describe('useAuth session timeout', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('keeps sessionTimeLeftMs null outside the warning window', () => {
        storeState.isAuthenticated = true;
        const { result } = renderHook(() => useAuth(), { wrapper });
        expect(result.current.sessionTimeLeftMs).toBeNull();
    });

    it('enters the warning window and eventually logs out on inactivity', async () => {
        vi.useFakeTimers();
        storeState.isAuthenticated = true;
        const { result } = renderHook(() => useAuth(), { wrapper });

        // SESSION_TIMEOUT defaults to 3_600_000ms; the warning window opens
        // 5 minutes (300_000ms) before it, at the 3_300_000ms mark.
        act(() => {
            vi.advanceTimersByTime(3_300_000);
        });
        expect(result.current.sessionTimeLeftMs).not.toBeNull();

        act(() => {
            vi.advanceTimersByTime(300_000);
        });
        expect(logout).toHaveBeenCalledTimes(1);
        expect(setError).toHaveBeenCalledWith('Your session has expired due to inactivity. Please log in again.');
    });

    it('clears sessionTimeLeftMs when no longer authenticated', () => {
        storeState.isAuthenticated = false;
        const { result } = renderHook(() => useAuth(), { wrapper });
        expect(result.current.sessionTimeLeftMs).toBeNull();
    });

    it('resets the deadline and re-arms the timer on user activity', () => {
        vi.useFakeTimers();
        storeState.isAuthenticated = true;
        const { result } = renderHook(() => useAuth(), { wrapper });

        // Enter the warning window.
        act(() => {
            vi.advanceTimersByTime(3_300_000);
        });
        expect(result.current.sessionTimeLeftMs).not.toBeNull();

        // Activity should reset the deadline (resetDeadline -> schedule), so we
        // leave the warning window again instead of continuing to count down.
        act(() => {
            document.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
        });
        expect(result.current.sessionTimeLeftMs).toBeNull();

        // Not enough time has passed since the reset for a new warning/logout.
        act(() => {
            vi.advanceTimersByTime(3_300_000);
        });
        expect(logout).not.toHaveBeenCalled();
        expect(result.current.sessionTimeLeftMs).not.toBeNull();

        // Push past the reset deadline to confirm it actually took effect.
        act(() => {
            vi.advanceTimersByTime(300_000);
        });
        expect(logout).toHaveBeenCalledTimes(1);
    });

    it('clears the pending timeout and removes activity listeners on unmount', () => {
        vi.useFakeTimers();
        storeState.isAuthenticated = true;
        const { unmount } = renderHook(() => useAuth(), { wrapper });

        unmount();

        // If the cleanup didn't clear the scheduled timeout/listeners, advancing
        // past the full session timeout would still fire the inactivity logout.
        act(() => {
            vi.advanceTimersByTime(3_600_000);
        });
        expect(logout).not.toHaveBeenCalled();
    });
});
