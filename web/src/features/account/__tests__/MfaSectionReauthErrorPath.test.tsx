import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider, onlineManager } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router';
import { MfaSection } from '../MfaSection';
import { queryClientDefaultOptions } from '../../../lib/queryClient';

// #2738 — the Disable-2FA dialog hung forever after one rejected attempt: spinner up,
// no error text, no further request, and closing and reopening the dialog did not clear
// it. Only a full page reload did.
//
// Deliberately NOT the sibling MfaSection.test.tsx harness. That one mocks ../index
// wholesale, so every mutation's pending state is a static boolean a test sets by hand —
// which is precisely why this shipped broken: the hang IS the real mutation's pending
// state, and a hand-set boolean can neither get stuck nor be reset. Here the REAL hooks
// run against a QueryClient carrying the PRODUCTION mutation defaults (see
// web/src/lib/queryClient.ts), with only the HTTP service layer stubbed. Mirroring those
// defaults is load-bearing: the old `retry: 1` is half the bug.
//
// Which of these are RED on main, stated so a green run is not read as more than it is:
//   - "exactly one request per click" and its Regenerate twin: RED. Main sends two, so one
//     click spent TWO of the per-account lockout slots internal/core's requireReauth
//     records on every refusal.
//   - "a request that cannot complete says so, and closing the dialog clears it": RED.
//     react-query pauses a mutation while onlineManager reports offline, and a paused
//     mutation's promise never settles -- on main that meant a silent spinner that
//     survived closing and reopening the dialog, because the pending flag was read off a
//     mutation object outliving it. This is the mechanism behind the report.
//   - "labels the field for what the backend accepts": RED. The old label invited the
//     account password, which this endpoint always refuses once MFA is enrolled.
//   - "shows the server reason and stays usable" and "a stale error does not survive into
//     a reopened dialog": GREEN on main once the retry delay is waited out. They are
//     regression guards for the properties the fix must not lose, not reproductions.

const disable = vi.fn();
const regenerate = vi.fn();
const recoveryCodesStatus = vi.fn();

vi.mock('../../../services/mfa', () => ({
    mfaApi: {
        enroll: vi.fn(),
        activate: vi.fn(),
        disable: (proof: { code: string }) => disable(proof),
        recoveryCodesStatus: () => recoveryCodesStatus(),
        regenerateRecoveryCodes: (proof: { code: string }) => regenerate(proof),
    },
}));

// reauthRefusal is shaped exactly like server/http/handlers/helpers.go's sendError, which
// is what requireReauth's refusal produces on POST /api/v1/auth/mfa/disable.
function reauthRefusal() {
    return Object.assign(new Error('Request failed with status code 400'), {
        response: { status: 400, data: { success: false, error: 'Error', message: 'invalid code or password' } },
    });
}

// The mutation policy is IMPORTED from the app's own module, never re-declared here: a
// hand-copied policy would have let this file go green against the very configuration
// #2738 is about. Only the query half is overridden, and only to keep tests fast.
function renderWithProductionMutationDefaults(ui: React.ReactElement) {
    const queryClient = new QueryClient({
        defaultOptions: {
            ...queryClientDefaultOptions,
            queries: { ...queryClientDefaultOptions.queries, retry: false, gcTime: 0 },
        },
    });
    return render(
        <QueryClientProvider client={queryClient}>
            <BrowserRouter>{ui}</BrowserRouter>
        </QueryClientProvider>
    );
}

// codeField finds the re-auth input by a PREFIX that matches the fixed label
// ("Authenticator code") as well as the old one ("Authenticator code or password"). That
// is deliberate: every behavioural test below must fail on main for the behaviour it
// names, not on a label lookup that never resolves. The label text itself is asserted
// once, on its own, in the last test.
function codeField() {
    return screen.getByLabelText(/^Authenticator code/i);
}

async function openDisableDialog() {
    await waitFor(() => expect(screen.getByRole('button', { name: 'Disable' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
    return codeField();
}

beforeEach(() => {
    vi.clearAllMocks();
    recoveryCodesStatus.mockResolvedValue({ remaining: 8, total: 10 });
});

afterEach(() => {
    onlineManager.setOnline(true);
});

describe('#2738 Disable-2FA dialog', () => {
    it('sends exactly one request per click when the server refuses the code', async () => {
        // requireReauth calls recordFailedLogin on every rejection, feeding the same
        // per-account lockout the second login factor uses. A retried 4xx therefore
        // charged the operator two attempts for one click.
        disable.mockRejectedValue(reauthRefusal());
        renderWithProductionMutationDefaults(<MfaSection />);

        fireEvent.change(await openDisableDialog(), { target: { value: '000000' } });
        fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }));

        await waitFor(() => expect(screen.getByText(/invalid code or password/i)).toBeInTheDocument(), {
            // Generous on purpose: on main the pointless retry delayed this by a second,
            // and a tight timeout would make these tests fail on the DELAY rather than on
            // the property each one actually names. See the red/green note in the PR.
            timeout: 6000,
        });
        // Settle any retry the policy might still schedule before counting.
        await new Promise((r) => setTimeout(r, 1500));
        expect(disable).toHaveBeenCalledTimes(1);
    }, 20000);

    it('shows the server reason and stays usable for a second attempt in the same dialog', async () => {
        disable.mockRejectedValue(reauthRefusal());
        renderWithProductionMutationDefaults(<MfaSection />);

        fireEvent.change(await openDisableDialog(), { target: { value: '000000' } });
        fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }));
        await waitFor(() => expect(screen.getByText(/invalid code or password/i)).toBeInTheDocument(), {
            // Generous on purpose: on main the pointless retry delayed this by a second,
            // and a tight timeout would make these tests fail on the DELAY rather than on
            // the property each one actually names. See the red/green note in the PR.
            timeout: 6000,
        });

        // Recovered: no stale spinner, and a second submit really reaches the server.
        const confirm = screen.getByRole('button', { name: 'Disable 2FA' });
        await waitFor(() => expect(confirm).not.toBeDisabled());
        expect(confirm.querySelector('svg.animate-spin')).not.toBeInTheDocument();

        disable.mockResolvedValue(undefined);
        fireEvent.change(codeField(), { target: { value: '123456' } });
        fireEvent.click(confirm);
        await waitFor(() => expect(disable).toHaveBeenCalledTimes(2));
        expect(disable).toHaveBeenLastCalledWith({ code: '123456' });
        // Success closes the dialog.
        await waitFor(() => expect(screen.queryByText('Disable two-factor authentication')).not.toBeInTheDocument());
    }, 20000);

    it('a stale error does not survive into a reopened dialog', async () => {
        disable.mockRejectedValue(reauthRefusal());
        renderWithProductionMutationDefaults(<MfaSection />);

        fireEvent.change(await openDisableDialog(), { target: { value: '000000' } });
        fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }));
        await waitFor(() => expect(screen.getByText(/invalid code or password/i)).toBeInTheDocument(), {
            // Generous on purpose: on main the pointless retry delayed this by a second,
            // and a tight timeout would make these tests fail on the DELAY rather than on
            // the property each one actually names. See the red/green note in the PR.
            timeout: 6000,
        });

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        fireEvent.click(screen.getByRole('button', { name: 'Disable' }));

        expect(screen.queryByText(/invalid code or password/i)).not.toBeInTheDocument();
        expect(codeField()).toHaveValue('');
    }, 20000);

    it('a request that cannot complete says so, and closing the dialog clears it', async () => {
        // This is the exact mechanism behind the report: offline, react-query pauses the
        // mutation, its promise never settles, so nothing the submit handler awaits ever
        // runs. On main the dialog went silent and the confirm button stayed disabled for
        // the rest of the page's lifetime — reopening it did not help, because the
        // pending flag was read off a mutation object that outlives the dialog.
        disable.mockRejectedValue(reauthRefusal());
        renderWithProductionMutationDefaults(<MfaSection />);

        fireEvent.change(await openDisableDialog(), { target: { value: '000000' } });
        onlineManager.setOnline(false);
        fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }));

        // Not silent any more.
        await waitFor(() => expect(screen.getByText(/waiting for a network connection/i)).toBeInTheDocument());
        expect(disable).not.toHaveBeenCalled();

        // Recoverable without a page reload: close, reopen, and the dialog works.
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        fireEvent.click(screen.getByRole('button', { name: 'Disable' }));

        const confirm = screen.getByRole('button', { name: 'Disable 2FA' });
        expect(screen.queryByText(/waiting for a network connection/i)).not.toBeInTheDocument();
        fireEvent.change(codeField(), { target: { value: '123456' } });
        expect(confirm).not.toBeDisabled();
        expect(confirm.querySelector('svg.animate-spin')).not.toBeInTheDocument();
    }, 20000);

    it('labels the field for what the backend accepts, and refuses to submit a password', async () => {
        // internal/core's requireReauth refuses the account password alone once a second
        // factor is enrolled, and its password-accepting branch additionally needs a live
        // MFAStepUpPurposeReauth grant no web login mints. The old label ("Authenticator
        // code or password") invited exactly the submission the server always refuses.
        renderWithProductionMutationDefaults(<MfaSection />);
        const field = await openDisableDialog();

        expect(screen.queryByLabelText(/or password/i)).not.toBeInTheDocument();
        expect(screen.getByText(/your password is not accepted here/i)).toBeInTheDocument();

        fireEvent.change(field, { target: { value: 'my-account-password' } });
        const confirm = screen.getByRole('button', { name: 'Disable 2FA' });
        expect(confirm).toBeDisabled();
        fireEvent.click(confirm);
        await waitFor(() => expect(disable).not.toHaveBeenCalled());
    }, 20000);

    it('the Regenerate-codes dialog behaves the same way (same component, same bug)', async () => {
        regenerate.mockRejectedValue(reauthRefusal());
        renderWithProductionMutationDefaults(<MfaSection />);

        await waitFor(() => expect(screen.getByRole('button', { name: 'Regenerate codes' })).toBeInTheDocument());
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate codes' }));
        fireEvent.change(codeField(), { target: { value: '000000' } });
        fireEvent.click(screen.getByRole('button', { name: 'Regenerate' }));

        await waitFor(() => expect(screen.getByText(/invalid code or password/i)).toBeInTheDocument(), {
            // Generous on purpose: on main the pointless retry delayed this by a second,
            // and a tight timeout would make these tests fail on the DELAY rather than on
            // the property each one actually names. See the red/green note in the PR.
            timeout: 6000,
        });
        await new Promise((r) => setTimeout(r, 1500));
        expect(regenerate).toHaveBeenCalledTimes(1);

        const confirm = screen.getByRole('button', { name: 'Regenerate' });
        await waitFor(() => expect(confirm).not.toBeDisabled());

        regenerate.mockResolvedValue(['new-1', 'new-2']);
        fireEvent.change(codeField(), { target: { value: '123456' } });
        fireEvent.click(confirm);
        expect(await screen.findByText('new-1')).toBeInTheDocument();
    }, 20000);
});
