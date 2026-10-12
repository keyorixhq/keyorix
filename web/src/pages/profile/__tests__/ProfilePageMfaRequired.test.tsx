import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { ProfilePage } from '../ProfilePage';

// #2924: with security.require_mfa on, a session without MFA is confined to the enrolment
// endpoints and every other call answers 403 MFAEnrollmentRequired. services/client.ts
// redirects to /profile?tab=security&mfa=required; this proves the page that redirect
// lands on opens the Security tab and tells the user why, with the REAL MfaSection and
// hooks and the server's real behaviour for the recovery-code status call (a 403).

const recoveryCodesStatus = vi.fn();
const enroll = vi.fn();

vi.mock('../../../store/authStore', () => {
    const user = { id: 1, username: 'admin', displayName: 'Admin', email: 'admin@example.com' };
    const useAuthStore: any = () => ({ user, setUser: vi.fn() });
    useAuthStore.getState = () => ({ clearPasswordChangeRequired: vi.fn() });
    return { useAuthStore };
});
vi.mock('../../../services/mfa', () => ({
    mfaApi: {
        recoveryCodesStatus: () => recoveryCodesStatus(),
        enroll: () => enroll(),
        activate: vi.fn(),
        disable: vi.fn(),
        regenerateRecoveryCodes: vi.fn(),
    },
}));
vi.mock('../../../features/projects/api', () => ({
    useProjects: () => ({ data: [] }),
    useProjectEnvironments: () => ({ data: [] }),
}));

function enrolmentRequired403() {
    return Object.assign(new Error('Request failed with status code 403'), {
        response: {
            status: 403,
            data: { error: 'MFAEnrollmentRequired', message: 'This deployment requires multi-factor authentication.' },
        },
    });
}

beforeEach(() => {
    vi.clearAllMocks();
    recoveryCodesStatus.mockRejectedValue(enrolmentRequired403());
    enroll.mockResolvedValue({ secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x' });
});

afterEach(() => {
    window.history.pushState({}, '', '/');
});

describe('#2924 ProfilePage after an MFAEnrollmentRequired redirect', () => {
    it('opens the Security tab, explains why, and offers Enable', async () => {
        window.history.pushState({}, '', '/profile?tab=security&mfa=required');
        render(<ProfilePage />);

        expect(await screen.findByText('Set up two-factor authentication to continue')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Enable' })).toBeInTheDocument();
        // The 403 on the status call is expected here, not a load failure.
        expect(screen.queryByText(/could not load two-factor status/i)).not.toBeInTheDocument();

        // And it is a working way in: Enable starts the enrolment.
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));
        await waitFor(() => expect(enroll).toHaveBeenCalled());
    });

    it('stays on Basic Info with no banner for an ordinary visit to /profile', async () => {
        window.history.pushState({}, '', '/profile');
        render(<ProfilePage />);

        expect(screen.getByLabelText('Display Name')).toBeInTheDocument();
        expect(screen.queryByText('Set up two-factor authentication to continue')).not.toBeInTheDocument();
    });

    it('does not show the banner once MFA is on', async () => {
        recoveryCodesStatus.mockReset();
        recoveryCodesStatus.mockResolvedValue({ remaining: 8, total: 10 });
        window.history.pushState({}, '', '/profile?tab=security&mfa=required');
        render(<ProfilePage />);

        expect(await screen.findByText('Enabled')).toBeInTheDocument();
        expect(screen.queryByText('Set up two-factor authentication to continue')).not.toBeInTheDocument();
    });
});
