import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { StaleAccountsSection } from '../StaleAccountsSection';

const resendMutate = vi.fn();
const suspendMutate = vi.fn();

const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();

vi.mock('../api', () => ({
    useStaleAccounts: () => ({
        data: [{ id: 7, username: 'ci-bot', display_name: 'CI Bot', email: 'ci@demo.test', created_at: tenDaysAgo }],
    }),
    useResendSetupLink: () => ({ mutate: resendMutate, isPending: false }),
    useSuspendUser: () => ({ mutate: suspendMutate, isPending: false }),
}));

beforeEach(() => {
    resendMutate.mockClear();
    suspendMutate.mockClear();
});

describe('StaleAccountsSection', () => {
    it('renders the stale count and per-row detail', () => {
        render(<StaleAccountsSection />);
        expect(screen.getByText(/1 account pending setup for over 7 days/i)).toBeInTheDocument();
        expect(screen.getByText('CI Bot')).toBeInTheDocument();
        expect(screen.getByText(/ci@demo\.test · 10 days pending/i)).toBeInTheDocument();
    });

    it('resends the setup link for the row', () => {
        render(<StaleAccountsSection />);
        fireEvent.click(screen.getByRole('button', { name: /resend link/i }));
        expect(resendMutate).toHaveBeenCalledTimes(1);
        expect(resendMutate.mock.calls[0][0]).toBe(7);
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
});
