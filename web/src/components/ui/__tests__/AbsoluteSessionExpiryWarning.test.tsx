import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { AbsoluteSessionExpiryWarning } from '../AbsoluteSessionExpiryWarning';
import { useAuth } from '../../../features/auth';
import { getTimeUntilAbsoluteExpiry } from '../../../utils/auth';

vi.mock('../../../features/auth', () => ({
    useAuth: vi.fn(),
}));

vi.mock('../../../utils/auth', () => ({
    getTimeUntilAbsoluteExpiry: vi.fn(),
}));

const mockUseAuth = vi.mocked(useAuth);
const mockGetTimeUntilAbsoluteExpiry = vi.mocked(getTimeUntilAbsoluteExpiry);

function setAuth(isAuthenticated: boolean, logout: ReturnType<typeof vi.fn> = vi.fn()) {
    mockUseAuth.mockReturnValue({
        isAuthenticated,
        logout,
    } as unknown as ReturnType<typeof useAuth>);
    return logout;
}

describe('AbsoluteSessionExpiryWarning', () => {
    beforeEach(() => {
        mockUseAuth.mockReset();
        mockGetTimeUntilAbsoluteExpiry.mockReset();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('renders nothing when the user is not authenticated', () => {
        setAuth(false);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(60 * 1000);
        render(<AbsoluteSessionExpiryWarning />);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        // The effect bails out before consulting the ceiling at all.
        expect(mockGetTimeUntilAbsoluteExpiry).not.toHaveBeenCalled();
    });

    it('renders nothing when authenticated but no absolute ceiling is configured', () => {
        setAuth(true);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(null);
        render(<AbsoluteSessionExpiryWarning />);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('renders nothing when remaining time is outside the warning window', () => {
        setAuth(true);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(10 * 60 * 1000); // 10 min > default 5 min warning
        render(<AbsoluteSessionExpiryWarning />);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('renders the warning with a formatted countdown once inside the default warning window', () => {
        setAuth(true);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(4 * 60 * 1000 + 5 * 1000); // 4:05
        render(<AbsoluteSessionExpiryWarning />);
        expect(screen.getByRole('alert')).toBeInTheDocument();
        expect(screen.getByText('4:05')).toBeInTheDocument();
        expect(screen.getByText(/Your session ends in/)).toBeInTheDocument();
        expect(screen.getByText(/can.t be extended/)).toBeInTheDocument();
    });

    it('renders exactly at the warning threshold boundary (remaining === warningTimeMs)', () => {
        setAuth(true);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(5 * 60 * 1000); // exactly the default threshold
        render(<AbsoluteSessionExpiryWarning />);
        expect(screen.getByRole('alert')).toBeInTheDocument();
        expect(screen.getByText('5:00')).toBeInTheDocument();
    });

    it('pads single-digit seconds with a leading zero, including a 0-minute countdown', () => {
        setAuth(true);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(9 * 1000); // 0:09
        render(<AbsoluteSessionExpiryWarning />);
        expect(screen.getByText('0:09')).toBeInTheDocument();
    });

    it('respects a custom warningTimeMs prop for the visibility window', () => {
        setAuth(true);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(90 * 1000); // 1:30

        const { rerender } = render(<AbsoluteSessionExpiryWarning warningTimeMs={60 * 1000} />);
        // 90s remaining is outside a 60s custom window.
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();

        rerender(<AbsoluteSessionExpiryWarning warningTimeMs={2 * 60 * 1000} />);
        // 90s remaining is inside a 2-minute custom window.
        expect(screen.getByRole('alert')).toBeInTheDocument();
        expect(screen.getByText('1:30')).toBeInTheDocument();
    });

    it('hides the banner when dismissed, without signing the user out', () => {
        const logout = vi.fn();
        setAuth(true, logout);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(2 * 60 * 1000);
        render(<AbsoluteSessionExpiryWarning />);

        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));

        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(logout).not.toHaveBeenCalled();
    });

    it('calls logout when "Sign in again" is clicked', () => {
        const logout = vi.fn();
        setAuth(true, logout);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(2 * 60 * 1000);
        render(<AbsoluteSessionExpiryWarning />);

        fireEvent.click(screen.getByRole('button', { name: /sign in again/i }));

        expect(logout).toHaveBeenCalledOnce();
    });

    it('hides the banner and stops tracking once the user becomes unauthenticated', () => {
        const logout = vi.fn();
        setAuth(true, logout);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(2 * 60 * 1000);
        const { rerender } = render(<AbsoluteSessionExpiryWarning />);
        expect(screen.getByRole('alert')).toBeInTheDocument();

        setAuth(false, logout);
        rerender(<AbsoluteSessionExpiryWarning />);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('counts down every second via the 1s interval tick', async () => {
        vi.useFakeTimers();
        const start = new Date('2026-08-01T12:00:00.000Z');
        vi.setSystemTime(start);

        const expiryTime = start.getTime() + 130 * 1000; // 2:10 remaining at mount
        mockGetTimeUntilAbsoluteExpiry.mockImplementation(() => Math.max(0, expiryTime - Date.now()));
        setAuth(true);

        render(<AbsoluteSessionExpiryWarning />);
        expect(screen.getByText('2:10')).toBeInTheDocument();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(1000);
        });
        expect(screen.getByText('2:09')).toBeInTheDocument();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        expect(screen.getByText('2:04')).toBeInTheDocument();
    });

    it('signs the user out and hides the banner once the absolute ceiling is reached', async () => {
        vi.useFakeTimers();
        const start = new Date('2026-08-01T12:00:00.000Z');
        vi.setSystemTime(start);

        const logout = vi.fn().mockResolvedValue(undefined);
        const expiryTime = start.getTime() + 2000; // 2s remaining, inside the default warning window
        mockGetTimeUntilAbsoluteExpiry.mockImplementation(() => Math.max(0, expiryTime - Date.now()));
        setAuth(true, logout);

        render(<AbsoluteSessionExpiryWarning />);
        expect(screen.getByRole('alert')).toBeInTheDocument();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });

        expect(logout).toHaveBeenCalledOnce();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('clears the polling interval on unmount', async () => {
        vi.useFakeTimers();
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(2 * 60 * 1000);
        setAuth(true);

        const { unmount } = render(<AbsoluteSessionExpiryWarning />);
        const callsBeforeUnmount = mockGetTimeUntilAbsoluteExpiry.mock.calls.length;

        unmount();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });

        // No further polling should happen once unmounted.
        expect(mockGetTimeUntilAbsoluteExpiry.mock.calls.length).toBe(callsBeforeUnmount);
    });

    it('updates and restores the "Sign in again" button background on hover', () => {
        setAuth(true);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(2 * 60 * 1000);
        render(<AbsoluteSessionExpiryWarning />);
        const signInButton = screen.getByRole('button', { name: /sign in again/i });

        fireEvent.mouseEnter(signInButton);
        expect(signInButton.style.backgroundColor).toBe('var(--accent-hover)');

        fireEvent.mouseLeave(signInButton);
        expect(signInButton.style.backgroundColor).toBe('var(--accent)');
    });

    it('updates and restores the dismiss button color on hover', () => {
        setAuth(true);
        mockGetTimeUntilAbsoluteExpiry.mockReturnValue(2 * 60 * 1000);
        render(<AbsoluteSessionExpiryWarning />);
        const dismissButton = screen.getByRole('button', { name: /dismiss/i });

        fireEvent.mouseEnter(dismissButton);
        expect(dismissButton.style.color).toBe('var(--text-primary)');

        fireEvent.mouseLeave(dismissButton);
        expect(dismissButton.style.color).toBe('var(--text-muted)');
    });
});
