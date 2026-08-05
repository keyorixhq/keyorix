import { describe, it, expect, vi, beforeEach } from 'vitest';
import { waitFor } from '@testing-library/react';
import { render } from '../../../test/test-utils';
import { SSOCompletePage } from '../SSOCompletePage';

const mockNavigate = vi.fn();
const navState: { navigate: typeof mockNavigate } = { navigate: mockNavigate };
vi.mock('react-router', async (orig) => ({
    ...(await orig<typeof import('react-router')>()),
    useNavigate: () => navState.navigate,
}));

const mockComplete = vi.fn().mockResolvedValue(undefined);
vi.mock('../../../store/authStore', () => ({
    useAuthStore: (sel: any) => sel({ completeSSOLogin: mockComplete }),
}));

describe('SSOCompletePage', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        window.location.hash = '';
        navState.navigate = mockNavigate;
        mockComplete.mockReset().mockResolvedValue(undefined);
    });

    it('completes login and navigates to return_to (the session cookie is already set by the backend redirect)', async () => {
        window.location.hash = '#expires_at=2026-12-31T00:00:00Z&return_to=/secrets';
        render(<SSOCompletePage />);
        await waitFor(() => expect(mockComplete).toHaveBeenCalledWith('2026-12-31T00:00:00Z', undefined));
        await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/secrets', { replace: true }));
    });

    it('redirects to /login on an error fragment without attempting login', async () => {
        window.location.hash = '#error=access_denied';
        render(<SSOCompletePage />);
        await waitFor(() =>
            expect(mockNavigate).toHaveBeenCalledWith(expect.stringContaining('/login?sso_error='), { replace: true })
        );
        expect(mockComplete).not.toHaveBeenCalled();
    });

    it('falls back to / for a protocol-relative return_to (open-redirect guard, shared with utils/routing.ts)', async () => {
        window.location.hash = '#expires_at=2026-12-31T00:00:00Z&return_to=' + encodeURIComponent('//evil.example/x');
        render(<SSOCompletePage />);
        await waitFor(() => expect(mockComplete).toHaveBeenCalledWith('2026-12-31T00:00:00Z', undefined));
        await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/', { replace: true }));
    });

    it('defaults to / when the fragment has no return_to', async () => {
        window.location.hash = '#expires_at=2026-12-31T00:00:00Z';
        render(<SSOCompletePage />);
        await waitFor(() => expect(mockComplete).toHaveBeenCalledWith('2026-12-31T00:00:00Z', undefined));
        await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/', { replace: true }));
    });

    it('passes through absolute_expires_at when present in the fragment', async () => {
        window.location.hash = '#expires_at=2026-12-31T00:00:00Z&absolute_expires_at=2027-01-01T00:00:00Z';
        render(<SSOCompletePage />);
        await waitFor(() => expect(mockComplete).toHaveBeenCalledWith('2026-12-31T00:00:00Z', '2027-01-01T00:00:00Z'));
    });

    it('redirects to /login with a generic error when completeSSOLogin rejects', async () => {
        mockComplete.mockRejectedValueOnce(new Error('network down'));
        window.location.hash = '#expires_at=2026-12-31T00:00:00Z';
        render(<SSOCompletePage />);
        await waitFor(() =>
            expect(mockNavigate).toHaveBeenCalledWith('/login?sso_error=' + encodeURIComponent('SSO sign-in failed'), {
                replace: true,
            })
        );
    });

    it('does not re-run SSO completion if the effect deps change after the first run', async () => {
        window.location.hash = '#expires_at=2026-12-31T00:00:00Z&return_to=/secrets';
        const { rerender } = render(<SSOCompletePage />);
        await waitFor(() => expect(mockComplete).toHaveBeenCalledTimes(1));
        await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/secrets', { replace: true }));

        // Simulate the effect's dependencies changing (e.g. React 18 StrictMode's
        // double-invoke, or a fresh `navigate` reference) — the `ran` ref guard
        // should skip a second run entirely.
        const secondNavigate = vi.fn();
        navState.navigate = secondNavigate;
        rerender(<SSOCompletePage />);

        expect(mockComplete).toHaveBeenCalledTimes(1);
        expect(secondNavigate).not.toHaveBeenCalled();
    });
});
