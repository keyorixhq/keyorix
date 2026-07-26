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

vi.mock('react-router-dom', async (importOriginal) => {
    const actual = await importOriginal<typeof import('react-router-dom')>();
    return {
        ...actual,
        useParams: () => ({ token: 'kx_setup_abc' }),
        useNavigate: () => navigateMock,
    };
});

beforeEach(() => {
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
});
