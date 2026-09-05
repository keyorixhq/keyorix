import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act, waitFor } from '../../../test/test-utils';
import { GlobalInviteUserModal } from '../GlobalInviteUserModal';

const mutate = vi.fn();
let isPending = false;

vi.mock('../api', () => ({
    useCreateGlobalInvitation: () => ({ mutate, isPending }),
}));

// The copy button must route through the shared copyToClipboard() util (which
// clears the clipboard again after a timeout) rather than calling
// navigator.clipboard.writeText() directly -- mock it so the assertion below can
// tell the two apart. A regression back to the raw call would leave this spy
// uncalled even though "Copied" still renders (the raw call sets copied state
// too), which is why asserting on the label alone doesn't catch the bypass.
const copyToClipboard = vi.fn().mockResolvedValue(undefined);
vi.mock('../../../utils', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../utils')>();
    return { ...actual, copyToClipboard: (...args: unknown[]) => copyToClipboard(...args) };
});

// The Headless UI Modal shell isn't the unit under test (and needs an
// IntersectionObserver constructor the jsdom setup doesn't provide) — render its
// children directly when open.
vi.mock('../../../components/ui/Modal', () => ({
    Modal: ({ isOpen, children }: any) => (isOpen ? <div>{children}</div> : null),
}));

// ProjectAssignmentsPicker fetches projects via React Query; stub it out — its own
// behaviour is covered by its own test. The modal only needs the system-role +
// email plumbing exercised here. It exposes a button to push a fake assignment so
// tests can exercise the assignments.map(...) callback in handleSubmit.
// NB: the path is relative to this test file, resolving to src/features/admin —
// the same module the component imports via its own '../admin' (relative to
// src/features/invitations).
vi.mock('../../admin', () => ({
    ProjectAssignmentsPicker: ({ onChange }: any) => (
        <div data-testid="assignments-picker">
            <button
                type="button"
                onClick={() => onChange([{ project_id: 7, role: 'project_developer', extra: 'ignored' }])}
            >
                add-assignment
            </button>
        </div>
    ),
}));

const onClose = vi.fn();

beforeEach(() => {
    mutate.mockReset();
    onClose.mockReset();
    copyToClipboard.mockClear();
    isPending = false;
});

describe('GlobalInviteUserModal', () => {
    it('submits email + system role + (empty) assignments', () => {
        render(<GlobalInviteUserModal isOpen onClose={onClose} />);

        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), {
            target: { value: 'carol@x.io' },
        });
        // System role select → system_auditor
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'system_auditor' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(mutate).toHaveBeenCalledTimes(1);
        expect(mutate.mock.calls[0][0]).toMatchObject({
            email: 'carol@x.io',
            role: 'system_auditor',
            assignments: [],
        });
    });

    it('blocks an invalid email and does not call the mutation', () => {
        render(<GlobalInviteUserModal isOpen onClose={onClose} />);

        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), {
            target: { value: 'not-an-email' },
        });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(mutate).not.toHaveBeenCalled();
        expect(screen.getByText(/valid email/i)).toBeInTheDocument();
    });

    it('shows the out-of-band setup link with a Copy button on success', () => {
        mutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                invitation: { id: 12 },
                setup_link: {
                    email: 'carol@x.io',
                    channel: 'out_of_band',
                    delivered: false,
                    link_for_admin: 'https://k/x/abc',
                },
            })
        );

        render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'carol@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(screen.getByText('https://k/x/abc')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /copy/i })).toBeInTheDocument();
    });

    it('shows actionable copy when the domain allowlist rejects the invite', () => {
        mutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'email domain is not on the allowlist' } } })
        );

        render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'e@evil.example' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(screen.getByText(/contact a system admin to update the allowlist/i)).toBeInTheDocument();
    });

    it('surfaces a delivery error when the link could not be sent', () => {
        mutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({ invitation: { id: 13 }, delivery_error: 'base_url unset' })
        );

        render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'e@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(screen.getByText(/base_url unset/)).toBeInTheDocument();
    });

    it('falls back to a default message when the delivery error is empty', () => {
        mutate.mockImplementation((_vars, opts) => opts.onSuccess({ invitation: { id: 14 } }));

        render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'e@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(screen.getByText(/the setup link could not be delivered\./i)).toBeInTheDocument();
    });

    it('includes mapped assignments in the submitted payload', () => {
        render(<GlobalInviteUserModal isOpen onClose={onClose} />);

        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'carol@x.io' } });
        fireEvent.click(screen.getByText('add-assignment'));
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(mutate.mock.calls[0][0].assignments).toEqual([{ project_id: 7, role: 'project_developer' }]);
    });

    it('resets fields and calls onClose on Cancel (not pending)', () => {
        const { rerender } = render(<GlobalInviteUserModal isOpen onClose={onClose} />);

        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'temp@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /cancel/i }));

        expect(onClose).toHaveBeenCalledTimes(1);

        // The component instance persists across isOpen toggles (only the Modal's
        // children are hidden) — reopening shows the state was actually reset.
        rerender(<GlobalInviteUserModal isOpen onClose={onClose} />);
        expect(screen.getByPlaceholderText('jane@example.com')).toHaveValue('');
    });

    it('Cancel is a no-op while the invitation is pending', () => {
        isPending = true;
        render(<GlobalInviteUserModal isOpen onClose={onClose} />);

        expect(screen.getByRole('button', { name: /sending…/i })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /cancel/i }));

        expect(onClose).not.toHaveBeenCalled();
    });

    it('copies the setup link via the shared copyToClipboard util and shows "Copied"', async () => {
        mutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                invitation: { id: 12 },
                setup_link: {
                    email: 'carol@x.io',
                    channel: 'out_of_band',
                    delivered: false,
                    link_for_admin: 'https://k/x/abc',
                },
            })
        );

        render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'carol@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));
        fireEvent.click(screen.getByRole('button', { name: /^copy$/i }));

        // The load-bearing assertion: a regression back to a raw
        // navigator.clipboard.writeText() call would still flip the label to
        // "Copied" (that state update doesn't depend on which copy path ran), so
        // asserting on the label alone can't tell the two apart -- only this
        // spy can.
        expect(copyToClipboard).toHaveBeenCalledWith('https://k/x/abc');
        // handleCopy now routes through the async copyToClipboard util, so the
        // "Copied" label flip lands on a microtask after the click, not
        // synchronously -- wait for it rather than asserting immediately.
        await waitFor(() => expect(screen.getByRole('button', { name: /copied/i })).toBeInTheDocument());
    });

    it('shows the email-delivery success copy (no link_for_admin) with the channel', () => {
        mutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                invitation: { id: 15 },
                setup_link: { email: 'delivered@x.io', channel: 'smtp', delivered: true },
            })
        );

        render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'delivered@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(screen.getByText(/a setup link was sent to/i)).toBeInTheDocument();
        expect(screen.getByText(/via smtp/i)).toBeInTheDocument();
    });

    it('Done is a no-op while the invitation is (still) pending, unlike Cancel', () => {
        // Unlike Cancel, the "Done" button on the success view isn't gated by a
        // `disabled={invite.isPending}` prop — handleClose's own internal guard is
        // the only thing standing between a stale in-flight request and a premature
        // close/reset. Simulate that window by flipping isPending back on after the
        // success view is already showing.
        mutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                invitation: { id: 20 },
                setup_link: {
                    email: 'carol@x.io',
                    channel: 'out_of_band',
                    delivered: false,
                    link_for_admin: 'https://k/x/done',
                },
            })
        );

        const { rerender } = render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'carol@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(screen.getByText('https://k/x/done')).toBeInTheDocument();

        isPending = true;
        rerender(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.click(screen.getByRole('button', { name: /^done$/i }));

        expect(onClose).not.toHaveBeenCalled();
        // reset() didn't run either — the success view (and its link) is still shown.
        expect(screen.getByText('https://k/x/done')).toBeInTheDocument();
    });

    it('falls back to the server-returned email in the success banner when the field was cleared mid-flight', () => {
        // The email input has no disabled={invite.isPending} guard, so a user can
        // clear it while the request is still in flight. sentEmail (derived from the
        // live input) then goes blank before onSuccess fires, and the banner should
        // fall back to the email the server echoes back on the created invitation.
        let onSuccess: ((res: any) => void) | undefined;
        mutate.mockImplementation((_vars, opts) => {
            onSuccess = opts.onSuccess;
        });

        render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'carol@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: '' } });

        act(() => {
            onSuccess?.({
                invitation: { id: 21 },
                setup_link: {
                    email: 'server@x.io',
                    channel: 'smtp',
                    delivered: true,
                    link_for_admin: 'https://k/x/fallback',
                },
            });
        });

        expect(screen.getByText('Invitation created for server@x.io.')).toBeInTheDocument();
    });

    it('omits the "via <channel>" clause when no channel is present', () => {
        mutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                invitation: { id: 16 },
                setup_link: { email: 'delivered2@x.io', channel: '', delivered: true },
            })
        );

        render(<GlobalInviteUserModal isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText('jane@example.com'), { target: { value: 'delivered2@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));

        expect(screen.getByText(/a setup link was sent to/i)).toBeInTheDocument();
        expect(screen.queryByText(/via /i)).not.toBeInTheDocument();
    });
});
