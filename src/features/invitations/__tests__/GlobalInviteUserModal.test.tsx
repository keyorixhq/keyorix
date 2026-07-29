import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { GlobalInviteUserModal } from '../GlobalInviteUserModal';

const mutate = vi.fn();

vi.mock('../api', () => ({
    useCreateGlobalInvitation: () => ({ mutate, isPending: false }),
}));

// The Headless UI Modal shell isn't the unit under test (and needs an
// IntersectionObserver constructor the jsdom setup doesn't provide) — render its
// children directly when open.
vi.mock('../../../components/ui/Modal', () => ({
    Modal: ({ isOpen, children }: any) => (isOpen ? <div>{children}</div> : null),
}));

// ProjectAssignmentsPicker fetches projects via React Query; stub it out — its own
// behaviour is covered by its own test. The modal only needs the system-role +
// email plumbing exercised here.
vi.mock('../admin', () => ({
    ProjectAssignmentsPicker: () => <div data-testid="assignments-picker" />,
}));

const onClose = vi.fn();

beforeEach(() => {
    mutate.mockReset();
    onClose.mockReset();
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
});
