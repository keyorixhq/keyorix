import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { StaleAccountsSection } from '../StaleAccountsSection';

const resendMutate = vi.fn();
const suspendMutate = vi.fn();
const { copyToClipboardMock } = vi.hoisted(() => ({ copyToClipboardMock: vi.fn() }));

const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();

let mockStale: any[] = [
    { id: 7, username: 'ci-bot', display_name: 'CI Bot', email: 'ci@demo.test', created_at: tenDaysAgo },
];

vi.mock('../api', () => ({
    useStaleAccounts: () => ({ data: mockStale }),
    useResendSetupLink: () => ({ mutate: resendMutate, isPending: false }),
    useSuspendUser: () => ({ mutate: suspendMutate, isPending: false }),
}));

vi.mock('../../../utils', () => ({
    copyToClipboard: copyToClipboardMock,
}));

beforeEach(() => {
    resendMutate.mockClear();
    suspendMutate.mockClear();
    copyToClipboardMock.mockReset();
    copyToClipboardMock.mockResolvedValue(undefined);
    mockStale = [{ id: 7, username: 'ci-bot', display_name: 'CI Bot', email: 'ci@demo.test', created_at: tenDaysAgo }];
});

describe('StaleAccountsSection', () => {
    it('renders the stale count and per-row detail', () => {
        render(<StaleAccountsSection />);
        expect(screen.getByText(/1 account pending setup for over 7 days/i)).toBeInTheDocument();
        expect(screen.getByText('CI Bot')).toBeInTheDocument();
        expect(screen.getByText(/ci@demo\.test · 10 days pending/i)).toBeInTheDocument();
    });

    it('renders nothing when there are no stale accounts', () => {
        mockStale = [];
        const { container } = render(<StaleAccountsSection />);
        expect(container).toBeEmptyDOMElement();
    });

    it('pluralizes the count when there is more than one stale account', () => {
        mockStale = [
            { id: 7, username: 'ci-bot', display_name: 'CI Bot', email: 'ci@demo.test', created_at: tenDaysAgo },
            { id: 8, username: 'ci-bot-2', display_name: '', email: 'ci2@demo.test', created_at: tenDaysAgo },
        ];
        render(<StaleAccountsSection />);
        expect(screen.getByText(/2 accounts pending setup for over 7 days/i)).toBeInTheDocument();
        // Falls back to username when display_name is empty.
        expect(screen.getByText('ci-bot-2')).toBeInTheDocument();
    });

    it('can be dismissed', () => {
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByTitle(/dismiss/i));
        expect(screen.queryByText(/pending setup for over 7 days/i)).not.toBeInTheDocument();
    });

    it('resends the setup link for the row', () => {
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /resend link/i }));
        expect(resendMutate).toHaveBeenCalledTimes(1);
        expect(resendMutate.mock.calls[0][0]).toBe(7);
    });

    it('copies the admin setup link to clipboard on success and reports it', async () => {
        resendMutate.mockImplementation((_id, opts) =>
            opts.onSuccess({ link_for_admin: 'https://example.test/setup/abc' })
        );
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /resend link/i }));
        expect(copyToClipboardMock).toHaveBeenCalledWith('https://example.test/setup/abc');
        expect(await screen.findByText(/setup link for ci@demo\.test copied to clipboard/i)).toBeInTheDocument();
    });

    it('falls back to a manual-copy message when clipboard copy fails', async () => {
        copyToClipboardMock.mockRejectedValue(new Error('denied'));
        resendMutate.mockImplementation((_id, opts) =>
            opts.onSuccess({ link_for_admin: 'https://example.test/setup/abc' })
        );
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /resend link/i }));
        expect(
            await screen.findByText(/setup link reissued for ci@demo\.test \(copy it from the user detail page\)/i)
        ).toBeInTheDocument();
    });

    it('reports a plain re-sent message when there is no admin link to copy', async () => {
        resendMutate.mockImplementation((_id, opts) => opts.onSuccess({}));
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /resend link/i }));
        expect(await screen.findByText(/setup link re-sent to ci@demo\.test\./i)).toBeInTheDocument();
    });

    it('surfaces a server error message when resend fails', async () => {
        resendMutate.mockImplementation((_id, opts) =>
            opts.onError({ response: { data: { error: 'mail server down' } } })
        );
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /resend link/i }));
        expect(await screen.findByText('mail server down')).toBeInTheDocument();
    });

    it('falls back to a generic message when resend fails without a server error', async () => {
        resendMutate.mockImplementation((_id, opts) => opts.onError({}));
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /resend link/i }));
        expect(await screen.findByText('Failed to resend setup link.')).toBeInTheDocument();
    });

    it('requires a confirm step before revoking (suspending)', () => {
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }));
        // First click only reveals the confirm button; no mutation yet.
        expect(suspendMutate).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
        expect(suspendMutate).toHaveBeenCalledTimes(1);
        expect(suspendMutate.mock.calls[0][0]).toBe(7);
    });

    it('cancels the revoke confirmation without suspending', () => {
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }));
        fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));
        expect(suspendMutate).not.toHaveBeenCalled();
        // Back to the initial "Revoke" affordance.
        expect(screen.getByRole('button', { name: /^revoke$/i })).toBeInTheDocument();
    });

    it('resets the confirm state on successful revoke', () => {
        suspendMutate.mockImplementation((_id, opts) => opts.onSuccess());
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }));
        fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
        expect(suspendMutate).toHaveBeenCalledTimes(1);
        // Back to the initial "Revoke" affordance, confirm/cancel are gone.
        expect(screen.getByRole('button', { name: /^revoke$/i })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^confirm$/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^cancel$/i })).not.toBeInTheDocument();
    });

    it('surfaces a server error message when revoke fails', async () => {
        suspendMutate.mockImplementation((_id, opts) => opts.onError({ response: { data: { error: 'nope' } } }));
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }));
        fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
        await waitFor(() => expect(screen.getByText('nope')).toBeInTheDocument());
    });

    it('falls back to a generic message when revoke fails without a server error', async () => {
        suspendMutate.mockImplementation((_id, opts) => opts.onError({}));
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }));
        fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
        await waitFor(() => expect(screen.getByText('Failed to revoke account.')).toBeInTheDocument());
    });
});
