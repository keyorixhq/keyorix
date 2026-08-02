import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '../../../test/test-utils';
import { ImpersonationBanner } from '../ImpersonationBanner';
import { ROUTES } from '../../../constants';
import type { ImpersonatedBy, User } from '../../../types';

// Mutable state read by the mocked useAuthStore selector below. vi.hoisted()
// is required because vi.mock() factories are hoisted above regular
// declarations, so any mutable value they close over must be created through
// vi.hoisted() to avoid a TDZ error.
const authState = vi.hoisted(() => ({
    user: null as Partial<User> | null,
    impersonatedBy: null as ImpersonatedBy | null,
}));

const endImpersonationMock = vi.hoisted(() => vi.fn());

// ImpersonationBanner reads the store with selectors (`useAuthStore((s) => s.user)`),
// so the mock must actually invoke the passed selector against a state object —
// a mock that ignores its argument and just returns the whole state would hand
// back the wrong value for each selected field.
vi.mock('../../../store/authStore', () => ({
    useAuthStore: (
        selector: (state: typeof authState & { endImpersonation: typeof endImpersonationMock }) => unknown
    ) => selector({ ...authState, endImpersonation: endImpersonationMock }),
}));

const navigateMock = vi.hoisted(() => vi.fn());

vi.mock('react-router-dom', async (importOriginal) => {
    const actual = await importOriginal<typeof import('react-router-dom')>();
    return {
        ...actual,
        useNavigate: () => navigateMock,
    };
});

describe('ImpersonationBanner', () => {
    beforeEach(() => {
        authState.user = null;
        authState.impersonatedBy = null;
        endImpersonationMock.mockReset();
        navigateMock.mockReset();
    });

    it('renders nothing when not impersonating', () => {
        const { container } = render(<ImpersonationBanner />);
        expect(container).toBeEmptyDOMElement();
    });

    it('renders the impersonated user by display name and the admin behind it', () => {
        authState.user = { displayName: 'Target User', username: 'target' };
        authState.impersonatedBy = { adminId: 1, adminUsername: 'admin1', adminDisplayName: 'Admin One' };
        render(<ImpersonationBanner />);

        expect(screen.getByRole('alert')).toBeInTheDocument();
        expect(screen.getByText('Target User')).toBeInTheDocument();
        expect(screen.getByText(/signed in as Admin One/)).toBeInTheDocument();
    });

    it('falls back to the username when the impersonated user has no display name', () => {
        authState.user = { username: 'target' };
        authState.impersonatedBy = { adminId: 1, adminUsername: 'admin1' };
        render(<ImpersonationBanner />);

        expect(screen.getByText('target')).toBeInTheDocument();
        // No adminDisplayName on impersonatedBy, so it falls back to adminUsername.
        expect(screen.getByText(/signed in as admin1/)).toBeInTheDocument();
    });

    it('falls back to a generic label when there is no impersonated-user record at all', () => {
        authState.user = null;
        authState.impersonatedBy = { adminId: 1, adminUsername: 'admin1' };
        render(<ImpersonationBanner />);

        expect(screen.getByText('another user')).toBeInTheDocument();
    });

    it('omits the "signed in as" clause entirely when neither admin name field is available', () => {
        authState.user = { displayName: 'Target User' };
        authState.impersonatedBy = { adminId: 1, adminUsername: '' };
        render(<ImpersonationBanner />);

        expect(screen.getByText('Target User')).toBeInTheDocument();
        expect(screen.queryByText(/signed in as/)).not.toBeInTheDocument();
    });

    it('ends impersonation and redirects to the dashboard on success', async () => {
        authState.user = { displayName: 'Target User' };
        authState.impersonatedBy = { adminId: 1, adminUsername: 'admin1' };
        endImpersonationMock.mockResolvedValue(undefined);
        render(<ImpersonationBanner />);

        fireEvent.click(screen.getByRole('button', { name: 'End Impersonation' }));

        await waitFor(() => expect(navigateMock).toHaveBeenCalledWith(ROUTES.DASHBOARD, { replace: true }));
        expect(endImpersonationMock).toHaveBeenCalledTimes(1);
    });

    it('shows a disabled "Ending…" state while the request is in flight', async () => {
        authState.user = { displayName: 'Target User' };
        authState.impersonatedBy = { adminId: 1, adminUsername: 'admin1' };
        let resolvePromise: () => void = () => {};
        endImpersonationMock.mockReturnValue(
            new Promise<void>((resolve) => {
                resolvePromise = resolve;
            })
        );
        render(<ImpersonationBanner />);

        fireEvent.click(screen.getByRole('button', { name: 'End Impersonation' }));

        const endingButton = await screen.findByRole('button', { name: 'Ending…' });
        expect(endingButton).toBeDisabled();

        resolvePromise();
        await waitFor(() => expect(navigateMock).toHaveBeenCalled());
    });

    it('shows a retry option and does not navigate away when ending impersonation fails', async () => {
        authState.user = { displayName: 'Target User' };
        authState.impersonatedBy = { adminId: 1, adminUsername: 'admin1' };
        endImpersonationMock.mockRejectedValue(new Error('network error'));
        render(<ImpersonationBanner />);

        fireEvent.click(screen.getByRole('button', { name: 'End Impersonation' }));

        expect(await screen.findByText(/Could not end impersonation/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
        expect(navigateMock).not.toHaveBeenCalled();
    });

    it('allows retrying after a failure and succeeds on the second attempt', async () => {
        authState.user = { displayName: 'Target User' };
        authState.impersonatedBy = { adminId: 1, adminUsername: 'admin1' };
        endImpersonationMock.mockRejectedValueOnce(new Error('network error'));
        endImpersonationMock.mockResolvedValueOnce(undefined);
        render(<ImpersonationBanner />);

        fireEvent.click(screen.getByRole('button', { name: 'End Impersonation' }));
        await screen.findByRole('button', { name: 'Retry' });

        fireEvent.click(screen.getByRole('button', { name: 'Retry' }));

        await waitFor(() => expect(navigateMock).toHaveBeenCalledWith(ROUTES.DASHBOARD, { replace: true }));
        expect(endImpersonationMock).toHaveBeenCalledTimes(2);
    });
});
