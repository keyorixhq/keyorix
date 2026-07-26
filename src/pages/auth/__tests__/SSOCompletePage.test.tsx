import { describe, it, expect, vi, beforeEach } from 'vitest';
import { waitFor } from '@testing-library/react';
import { render } from '../../../test/test-utils';
import { SSOCompletePage } from '../SSOCompletePage';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async (orig) => ({
    ...(await orig<typeof import('react-router-dom')>()),
    useNavigate: () => mockNavigate,
}));

const mockComplete = vi.fn().mockResolvedValue(undefined);
vi.mock('../../../store/authStore', () => ({
    useAuthStore: (sel: any) => sel({ completeSSOLogin: mockComplete }),
}));

describe('SSOCompletePage', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        window.location.hash = '';
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

    it('defaults to / when the fragment has no return_to', async () => {
        window.location.hash = '#expires_at=2026-12-31T00:00:00Z';
        render(<SSOCompletePage />);
        await waitFor(() => expect(mockComplete).toHaveBeenCalledWith('2026-12-31T00:00:00Z', undefined));
        await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/', { replace: true }));
    });
});
