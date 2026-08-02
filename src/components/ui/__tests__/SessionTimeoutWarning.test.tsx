import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SessionTimeoutWarning } from '../SessionTimeoutWarning';
import { useAuth } from '../../../features/auth';

// The countdown itself is owned by useAuth() (sessionTimeLeftMs) - this
// component is purely presentational and does not run its own
// setInterval/setTimeout, so fake timers are not needed here. "Ticking" is
// exercised by re-rendering with a different sessionTimeLeftMs, simulating
// what useAuth would push down on its own 1s schedule.
vi.mock('../../../features/auth', () => ({
    useAuth: vi.fn(),
}));

const mockUseAuth = vi.mocked(useAuth);

type AuthOverrides = {
    isAuthenticated?: boolean;
    sessionTimeLeftMs?: number | null;
    logout?: ReturnType<typeof vi.fn>;
    refreshToken?: ReturnType<typeof vi.fn>;
};

function setAuth(overrides: AuthOverrides = {}) {
    // Note: sessionTimeLeftMs is explicitly nullable (null is a real,
    // meaningful value distinct from "not overridden"), so an `??` default
    // would wrongly coerce an explicit `null` override back to 60000. Use an
    // `in` check instead to tell "unset" apart from "set to null".
    mockUseAuth.mockReturnValue({
        isAuthenticated: overrides.isAuthenticated ?? true,
        sessionTimeLeftMs: 'sessionTimeLeftMs' in overrides ? overrides.sessionTimeLeftMs : 60000,
        logout: overrides.logout ?? vi.fn().mockResolvedValue(undefined),
        refreshToken: overrides.refreshToken ?? vi.fn().mockResolvedValue(undefined),
    } as unknown as ReturnType<typeof useAuth>);
}

describe('SessionTimeoutWarning', () => {
    beforeEach(() => {
        mockUseAuth.mockReset();
    });

    it('renders nothing when the user is not authenticated', () => {
        setAuth({ isAuthenticated: false, sessionTimeLeftMs: 60000 });
        render(<SessionTimeoutWarning />);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('renders nothing when sessionTimeLeftMs is null (outside the warning window)', () => {
        setAuth({ isAuthenticated: true, sessionTimeLeftMs: null });
        render(<SessionTimeoutWarning />);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('renders the warning dialog when authenticated and inside the warning window', () => {
        setAuth({ isAuthenticated: true, sessionTimeLeftMs: 60000 });
        render(<SessionTimeoutWarning />);
        expect(screen.getByRole('dialog')).toBeInTheDocument();
        expect(screen.getByText('Session Expiring')).toBeInTheDocument();
    });

    it.each([
        [125000, '2:05'],
        [65000, '1:05'],
        [9000, '0:09'],
        [300000, '5:00'],
    ])('formats %ims remaining as %s', (ms, expected) => {
        setAuth({ sessionTimeLeftMs: ms });
        render(<SessionTimeoutWarning />);
        expect(screen.getByText(expected)).toBeInTheDocument();
    });

    it('updates the displayed countdown when sessionTimeLeftMs ticks down on rerender', () => {
        setAuth({ sessionTimeLeftMs: 65000 });
        const { rerender } = render(<SessionTimeoutWarning />);
        expect(screen.getByText('1:05')).toBeInTheDocument();

        setAuth({ sessionTimeLeftMs: 64000 });
        rerender(<SessionTimeoutWarning />);
        expect(screen.getByText('1:04')).toBeInTheDocument();
        expect(screen.queryByText('1:05')).not.toBeInTheDocument();
    });

    it('calls refreshToken and onExtendSession when "Extend Session" succeeds', async () => {
        let resolveRefresh!: () => void;
        const refreshToken = vi.fn(
            () =>
                new Promise<void>((resolve) => {
                    resolveRefresh = resolve;
                })
        );
        const onExtendSession = vi.fn();
        setAuth({ refreshToken });
        render(<SessionTimeoutWarning onExtendSession={onExtendSession} />);

        fireEvent.click(screen.getByRole('button', { name: 'Extend Session' }));

        // While the refreshToken promise is pending, the button should reflect
        // the in-flight extend attempt.
        expect(await screen.findByText('Loading...')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Loading/ })).toBeDisabled();

        await act(async () => {
            resolveRefresh();
            await Promise.resolve();
        });

        expect(refreshToken).toHaveBeenCalledTimes(1);
        expect(onExtendSession).toHaveBeenCalledTimes(1);
        expect(screen.getByRole('button', { name: 'Extend Session' })).toBeInTheDocument();
    });

    it('falls back to logout when refreshToken rejects', async () => {
        const refreshToken = vi.fn().mockRejectedValue(new Error('refresh failed'));
        const logout = vi.fn().mockResolvedValue(undefined);
        const onLogout = vi.fn();
        const onExtendSession = vi.fn();
        setAuth({ refreshToken, logout });
        render(<SessionTimeoutWarning onExtendSession={onExtendSession} onLogout={onLogout} />);

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Extend Session' }));
            await Promise.resolve();
            await Promise.resolve();
        });

        expect(refreshToken).toHaveBeenCalledTimes(1);
        expect(logout).toHaveBeenCalledTimes(1);
        expect(onLogout).toHaveBeenCalledTimes(1);
        expect(onExtendSession).not.toHaveBeenCalled();
    });

    it('calls logout and onLogout when "Logout" is clicked', async () => {
        const logout = vi.fn().mockResolvedValue(undefined);
        const onLogout = vi.fn();
        setAuth({ logout });
        render(<SessionTimeoutWarning onLogout={onLogout} />);

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Logout' }));
            await Promise.resolve();
        });

        expect(logout).toHaveBeenCalledTimes(1);
        expect(onLogout).toHaveBeenCalledTimes(1);
    });

    it('does not throw when onExtendSession/onLogout are not provided', async () => {
        const logout = vi.fn().mockResolvedValue(undefined);
        setAuth({ logout });
        render(<SessionTimeoutWarning />);

        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Logout' }));
            await Promise.resolve();
        });

        expect(logout).toHaveBeenCalledTimes(1);
    });

    it('dismisses the dialog when the close button is clicked', () => {
        setAuth({ sessionTimeLeftMs: 60000 });
        render(<SessionTimeoutWarning />);
        expect(screen.getByRole('dialog')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('re-arms after dismissal once sessionTimeLeftMs leaves and re-enters the warning window', () => {
        setAuth({ sessionTimeLeftMs: 60000 });
        const { rerender } = render(<SessionTimeoutWarning />);
        expect(screen.getByRole('dialog')).toBeInTheDocument();

        // Dismiss while still inside the warning window - dialog hides even
        // though sessionTimeLeftMs is unchanged.
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

        // Rerendering with the same sessionTimeLeftMs keeps it dismissed.
        setAuth({ sessionTimeLeftMs: 59000 });
        rerender(<SessionTimeoutWarning />);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

        // Activity resets the deadline - sessionTimeLeftMs goes back to null,
        // which re-arms the dismissal flag internally (still no dialog, since
        // there's no active warning to show).
        setAuth({ sessionTimeLeftMs: null });
        rerender(<SessionTimeoutWarning />);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

        // A fresh inactivity cycle enters the warning window again - the
        // warning should reappear since dismissal was re-armed.
        setAuth({ sessionTimeLeftMs: 60000 });
        rerender(<SessionTimeoutWarning />);
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it('updates and restores the close button color on hover', () => {
        setAuth({ sessionTimeLeftMs: 60000 });
        render(<SessionTimeoutWarning />);
        const closeButton = screen.getByRole('button', { name: 'Close' });

        fireEvent.mouseEnter(closeButton);
        expect(closeButton.style.color).toBe('var(--text-primary)');

        fireEvent.mouseLeave(closeButton);
        expect(closeButton.style.color).toBe('var(--text-muted)');
    });

    it('updates the Extend Session button background on hover while idle, and ignores hover mid-extend', async () => {
        let resolveRefresh!: () => void;
        const refreshToken = vi.fn(
            () =>
                new Promise<void>((resolve) => {
                    resolveRefresh = resolve;
                })
        );
        setAuth({ refreshToken });
        render(<SessionTimeoutWarning />);
        const extendButton = screen.getByRole('button', { name: 'Extend Session' });

        fireEvent.mouseEnter(extendButton);
        expect(extendButton.style.backgroundColor).toBe('var(--accent-hover)');

        fireEvent.mouseLeave(extendButton);
        expect(extendButton.style.backgroundColor).toBe('var(--accent)');

        fireEvent.click(extendButton);
        await screen.findByText('Loading...');
        const pendingButton = screen.getByRole('button', { name: /Loading/ });
        expect(pendingButton.style.backgroundColor).toBe('var(--bg-muted)');

        // While extending, the `if (!isExtending)` guard makes hover a no-op.
        fireEvent.mouseEnter(pendingButton);
        expect(pendingButton.style.backgroundColor).toBe('var(--bg-muted)');
        fireEvent.mouseLeave(pendingButton);
        expect(pendingButton.style.backgroundColor).toBe('var(--bg-muted)');

        await act(async () => {
            resolveRefresh();
            await Promise.resolve();
        });
    });

    it('updates and restores the Logout button background on hover', () => {
        setAuth();
        render(<SessionTimeoutWarning />);
        const logoutButton = screen.getByRole('button', { name: 'Logout' });

        fireEvent.mouseEnter(logoutButton);
        expect(logoutButton.style.backgroundColor).toBe('var(--bg-subtle)');

        fireEvent.mouseLeave(logoutButton);
        expect(logoutButton.style.backgroundColor).toBe('var(--bg-surface)');
    });
});
