import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { MfaSection } from '../MfaSection';

let recoveryStatus: { remaining: number; total: number };
const enrollMutate = vi.fn();
const activateMutate = vi.fn();
const disableMutate = vi.fn();
const regenerateMutate = vi.fn();

vi.mock('../index', () => ({
    useMfaRecoveryStatus: () => ({ data: recoveryStatus, isLoading: false, isError: false }),
    useEnrollMfa: () => ({ mutate: enrollMutate, isPending: false }),
    useActivateMfa: () => ({ mutate: activateMutate, isPending: false }),
    useDisableMfa: () => ({ mutateAsync: disableMutate, isPending: false }),
    useRegenerateRecoveryCodes: () => ({ mutateAsync: regenerateMutate, isPending: false }),
}));

beforeEach(() => {
    recoveryStatus = { remaining: 0, total: 0 };
    enrollMutate.mockClear();
    activateMutate.mockClear();
    disableMutate.mockClear();
    regenerateMutate.mockClear();
});

describe('MfaSection', () => {
    it('shows an Enable action when MFA is off', () => {
        render(<MfaSection />);
        expect(screen.getByText('Two-Factor Authentication')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Enable' })).toBeInTheDocument();
        expect(screen.queryByText('Enabled')).not.toBeInTheDocument();
        expect(screen.getByText(/second factor at login/i)).toBeInTheDocument();
    });

    it('shows status + management when MFA is on', () => {
        recoveryStatus = { remaining: 8, total: 10 };
        render(<MfaSection />);
        expect(screen.getByText('Enabled')).toBeInTheDocument();
        expect(screen.getByText('8 of 10 recovery codes remaining')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Disable' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Regenerate codes' })).toBeInTheDocument();
        // Not low on codes → no warning.
        expect(screen.queryByText(/running low/i)).not.toBeInTheDocument();
    });

    it('warns when recovery codes are running low', () => {
        recoveryStatus = { remaining: 2, total: 10 };
        render(<MfaSection />);
        expect(screen.getByText(/running low on recovery codes/i)).toBeInTheDocument();
    });

    it('opens the enrolment modal and begins enrolment on Enable', () => {
        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));
        expect(screen.getByText('Set up two-factor authentication')).toBeInTheDocument();
        // The modal kicks off enrolment.
        expect(enrollMutate).toHaveBeenCalled();
    });

    it('opens the regenerate re-auth modal', () => {
        recoveryStatus = { remaining: 5, total: 10 };
        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate codes' }));
        expect(screen.getByText('Regenerate recovery codes')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Regenerate' })).toBeInTheDocument();
    });

    it('opens the disable re-auth modal', () => {
        recoveryStatus = { remaining: 5, total: 10 };
        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
        expect(screen.getByText('Disable two-factor authentication')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument();
    });
});
