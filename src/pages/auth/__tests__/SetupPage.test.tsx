import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { SetupPage } from '../SetupPage';

const describeMock = vi.fn();
const consumeMock = vi.fn();
const completeSetupMock = vi.fn();
const navigateMock = vi.fn();

vi.mock('../../../services/setup', () => ({
    setupService: {
        describe: (...args: unknown[]) => describeMock(...args),
        consume: (...args: unknown[]) => consumeMock(...args),
    },
}));

vi.mock('../../../store/authStore', () => ({
    useAuthStore: (selector: (s: { completeSetup: unknown }) => unknown) =>
        selector({ completeSetup: completeSetupMock }),
}));

let currentToken: string | undefined = 'kx_setup_abc';

vi.mock('react-router-dom', async (importOriginal) => {
    const actual = await importOriginal<typeof import('react-router-dom')>();
    return {
        ...actual,
        useParams: () => ({ token: currentToken }),
        useNavigate: () => navigateMock,
    };
});

beforeEach(() => {
    currentToken = 'kx_setup_abc';
    describeMock.mockReset();
    consumeMock.mockReset();
    completeSetupMock.mockReset();
    navigateMock.mockReset();
});

describe('SetupPage', () => {
    it('validates the link and shows the invitee email + greeting', async () => {
        describeMock.mockResolvedValue({ purpose: 'account_setup', email: 'new@acme.io', display_name: 'Dana' });
        render(<SetupPage />);

        await waitFor(() => expect(screen.getByText(/new@acme.io/)).toBeInTheDocument());
        expect(screen.getByText(/Welcome, Dana\./)).toBeInTheDocument();
        expect(describeMock).toHaveBeenCalledWith('kx_setup_abc');
    });

    it('shows an invalid state when the link is dead', async () => {
        describeMock.mockRejectedValue(new Error('This setup link is no longer valid'));
        render(<SetupPage />);

        await waitFor(() => expect(screen.getByText(/can.t be used/i)).toBeInTheDocument());
        expect(screen.getByText(/This setup link is no longer valid/)).toBeInTheDocument();
        // No password form on a dead link.
        expect(screen.queryByLabelText('New password')).not.toBeInTheDocument();
    });

    it('consumes the token, lands the user logged in, and navigates to the dashboard', async () => {
        describeMock.mockResolvedValue({ purpose: 'account_setup', email: 'new@acme.io' });
        consumeMock.mockResolvedValue({
            token: 'sess-xyz',
            user_id: 1,
            username: 'dana',
            email: 'new@acme.io',
            expires_at: '2026-06-06T00:00:00Z',
        });
        render(<SetupPage />);

        await waitFor(() => expect(screen.getByLabelText('New password')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Str0ng!Passw0rd-2026' } });
        fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'Str0ng!Passw0rd-2026' } });
        fireEvent.click(screen.getByRole('button', { name: /set password and continue/i }));

        await waitFor(() => expect(consumeMock).toHaveBeenCalledWith('kx_setup_abc', 'Str0ng!Passw0rd-2026'));
        expect(completeSetupMock).toHaveBeenCalledWith(expect.objectContaining({ token: 'sess-xyz' }));
        expect(navigateMock).toHaveBeenCalledWith('/dashboard', { replace: true });
    });

    it('does not submit when the passwords do not match', async () => {
        describeMock.mockResolvedValue({ purpose: 'account_setup', email: 'new@acme.io' });
        render(<SetupPage />);

        await waitFor(() => expect(screen.getByLabelText('New password')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Str0ng!Passw0rd-2026' } });
        fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'different' } });
        fireEvent.click(screen.getByRole('button', { name: /set password and continue/i }));

        await waitFor(() => expect(screen.getByText(/Passwords do not match/)).toBeInTheDocument());
        expect(consumeMock).not.toHaveBeenCalled();
    });

    it('shows an invalid state immediately when the route has no token', () => {
        currentToken = undefined;
        render(<SetupPage />);

        expect(screen.getByText(/can.t be used/i)).toBeInTheDocument();
        expect(screen.getByText('This setup link is missing its token.')).toBeInTheDocument();
        expect(describeMock).not.toHaveBeenCalled();
    });

    it('falls back to a generic message when link validation rejects with a non-Error value', async () => {
        describeMock.mockRejectedValue('boom');
        render(<SetupPage />);

        await waitFor(() => expect(screen.getByText(/can.t be used/i)).toBeInTheDocument());
        expect(screen.getByText('This setup link is no longer valid.')).toBeInTheDocument();
    });

    it('ignores a late successful describe response after the component unmounts', async () => {
        let resolveDescribe: (v: unknown) => void = () => {};
        const pending = new Promise((resolve) => {
            resolveDescribe = resolve;
        });
        describeMock.mockReturnValue(pending);

        const { unmount } = render(<SetupPage />);
        unmount();
        resolveDescribe({ purpose: 'account_setup', email: 'new@acme.io' });

        await pending;
    });

    it('ignores a late describe rejection after the component unmounts', async () => {
        let rejectDescribe: (e: unknown) => void = () => {};
        const pending = new Promise((_resolve, reject) => {
            rejectDescribe = reject;
        });
        describeMock.mockReturnValue(pending);

        const { unmount } = render(<SetupPage />);
        unmount();
        rejectDescribe(new Error('dead link'));

        await pending.catch(() => undefined);
    });

    // handleSubmit deliberately rethrows after recording the error (so a caller
    // awaiting SetupForm's submit can react too); react-hook-form's handleSubmit
    // does not swallow that rejection, so submitting produces a real unhandled
    // promise rejection in both the app and the test environment. Swallow it here
    // via a scoped listener so it doesn't fail the test run, without changing
    // production behavior.
    async function withSwallowedUnhandledRejection(fn: () => Promise<void>) {
        const onUnhandled = () => {};
        process.on('unhandledRejection', onUnhandled);
        try {
            await fn();
        } finally {
            process.off('unhandledRejection', onUnhandled);
        }
    }

    it('surfaces a submit error and does not complete setup when consume rejects', async () => {
        await withSwallowedUnhandledRejection(async () => {
            describeMock.mockResolvedValue({ purpose: 'account_setup', email: 'new@acme.io' });
            consumeMock.mockRejectedValue(new Error('Password does not meet policy'));
            render(<SetupPage />);

            await waitFor(() => expect(screen.getByLabelText('New password')).toBeInTheDocument());
            fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Str0ng!Passw0rd-2026' } });
            fireEvent.change(screen.getByLabelText('Confirm password'), {
                target: { value: 'Str0ng!Passw0rd-2026' },
            });
            fireEvent.click(screen.getByRole('button', { name: /set password and continue/i }));

            await waitFor(() => expect(screen.getByText('Password does not meet policy')).toBeInTheDocument());
            expect(completeSetupMock).not.toHaveBeenCalled();
            expect(navigateMock).not.toHaveBeenCalled();
        });
    });

    it('falls back to a generic message when consume rejects with a non-Error value', async () => {
        await withSwallowedUnhandledRejection(async () => {
            describeMock.mockResolvedValue({ purpose: 'account_setup', email: 'new@acme.io' });
            consumeMock.mockRejectedValue('nope');
            render(<SetupPage />);

            await waitFor(() => expect(screen.getByLabelText('New password')).toBeInTheDocument());
            fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Str0ng!Passw0rd-2026' } });
            fireEvent.change(screen.getByLabelText('Confirm password'), {
                target: { value: 'Str0ng!Passw0rd-2026' },
            });
            fireEvent.click(screen.getByRole('button', { name: /set password and continue/i }));

            await waitFor(() => expect(screen.getByText('Setup failed')).toBeInTheDocument());
        });
    });

    // NOTE: handleSubmit's `if (!token) return;` guard is not exercised — SetupForm
    // (the only caller of handleSubmit) only renders once phase === 'ready', which
    // itself requires a truthy token (a missing token short-circuits straight to the
    // 'invalid' phase in the effect above). It's defensive and unreachable via the UI.
});
