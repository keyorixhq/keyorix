import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { ProjectInvitationsSection } from '../ProjectInvitationsSection';

const revoke = vi.fn();

// ISO timestamp `days` ago.
const daysAgo = (days: number) => new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

let invitations: any[] = [];

vi.mock('../api', () => ({
    useProjectInvitations: () => ({ data: invitations }),
    useRevokeInvitation: () => ({ mutate: revoke, isPending: false }),
}));

beforeEach(() => {
    revoke.mockReset();
});

describe('ProjectInvitationsSection — stale warnings', () => {
    it('flags a pending invite older than 7 days as stale with a banner', () => {
        invitations = [
            {
                id: 1,
                projectId: 3,
                email: 'old@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(10),
            },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.getByText('Stale')).toBeInTheDocument();
        expect(screen.getByText(/1 invitation has been pending over a week/i)).toBeInTheDocument();
        expect(screen.getByText(/pending 10 days/i)).toBeInTheDocument();
    });

    it('does not flag a recent pending invite', () => {
        invitations = [
            {
                id: 2,
                projectId: 3,
                email: 'fresh@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(2),
            },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.queryByText('Stale')).not.toBeInTheDocument();
        expect(screen.queryByText(/pending over a week/i)).not.toBeInTheDocument();
    });

    it('does not flag an old non-pending invite (accepted/revoked age out cleanly)', () => {
        invitations = [
            {
                id: 3,
                projectId: 3,
                email: 'done@demo.test',
                role: 'project_viewer',
                state: 'accepted',
                invitedBy: 1,
                createdAt: daysAgo(30),
            },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.queryByText('Stale')).not.toBeInTheDocument();
    });

    it('pluralizes and counts multiple stale invites, ordering them first', () => {
        invitations = [
            {
                id: 4,
                projectId: 3,
                email: 'fresh@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(1),
            },
            {
                id: 5,
                projectId: 3,
                email: 'old1@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(8),
            },
            {
                id: 6,
                projectId: 3,
                email: 'old2@demo.test',
                role: 'project_developer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(20),
            },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.getByText(/2 invitations have been pending over a week/i)).toBeInTheDocument();
        // Stale ones sort to the top: the first two emails rendered are the stale pair.
        const emails = screen.getAllByText(/@demo\.test$/).map((n) => n.textContent);
        expect(emails.slice(0, 2)).toEqual(expect.arrayContaining(['old1@demo.test', 'old2@demo.test']));
        expect(emails[2]).toBe('fresh@demo.test');
    });

    it('renders nothing when there are no invitations', () => {
        invitations = [];
        const { container } = render(<ProjectInvitationsSection projectId={3} />);
        expect(container).toBeEmptyDOMElement();
    });

    it('sorts a non-pending invite after a pending one (comparator both-branches)', () => {
        // A single-item array never invokes the sort comparator at all, so a
        // dedicated multi-item, mixed-state fixture is needed to actually exercise
        // the `state === 'pending' ? 1 : 2` ranking branch for a non-pending item.
        invitations = [
            {
                id: 7,
                projectId: 3,
                email: 'accepted@demo.test',
                role: 'project_viewer',
                state: 'accepted',
                invitedBy: 1,
                createdAt: daysAgo(1),
            },
            {
                id: 8,
                projectId: 3,
                email: 'pending@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(1),
            },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        const emails = screen.getAllByText(/@demo\.test$/).map((n) => n.textContent);
        expect(emails).toEqual(['pending@demo.test', 'accepted@demo.test']);
    });

    it('falls back to the muted badge style for revoked/expired states', () => {
        invitations = [
            {
                id: 9,
                projectId: 3,
                email: 'gone@demo.test',
                role: 'project_viewer',
                state: 'expired',
                invitedBy: 1,
                createdAt: daysAgo(30),
            },
        ];
        render(<ProjectInvitationsSection projectId={3} />);
        expect(screen.getByText('expired')).toBeInTheDocument();
    });

    it('shows the expiry date for a non-stale pending invite with expiresAt', () => {
        const expiresAt = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
        invitations = [
            {
                id: 10,
                projectId: 3,
                email: 'expiring@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(1),
                expiresAt,
            },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.getByText(new RegExp(`expires ${new Date(expiresAt).toLocaleDateString()}`))).toBeInTheDocument();
    });

    it('does not blow up when expiresAt is unparseable', () => {
        invitations = [
            {
                id: 11,
                projectId: 3,
                email: 'badexpiry@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(1),
                expiresAt: 'not-a-date',
            },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.getByText(/expires/i)).toBeInTheDocument();
    });

    it('revoking an invitation surfaces the server error message', () => {
        invitations = [
            {
                id: 12,
                projectId: 3,
                email: 'revokeme@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(1),
            },
        ];
        revoke.mockImplementation((_id, opts) =>
            opts.onError({ response: { data: { message: 'cannot revoke: already accepted' } } })
        );
        render(<ProjectInvitationsSection projectId={3} />);

        fireEvent.click(screen.getByTitle('Revoke invitation'));

        expect(revoke).toHaveBeenCalledWith(12, expect.anything());
        expect(screen.getByText('cannot revoke: already accepted')).toBeInTheDocument();
    });

    it('falls back to err.response.data.error when message is absent', () => {
        invitations = [
            {
                id: 13,
                projectId: 3,
                email: 'revokeme2@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(1),
            },
        ];
        revoke.mockImplementation((_id, opts) => opts.onError({ response: { data: { error: 'server_error' } } }));
        render(<ProjectInvitationsSection projectId={3} />);

        fireEvent.click(screen.getByTitle('Revoke invitation'));

        expect(screen.getByText('server_error')).toBeInTheDocument();
    });

    it('falls back to a default message when neither message nor error is present', () => {
        invitations = [
            {
                id: 14,
                projectId: 3,
                email: 'revokeme3@demo.test',
                role: 'project_viewer',
                state: 'pending',
                invitedBy: 1,
                createdAt: daysAgo(1),
            },
        ];
        revoke.mockImplementation((_id, opts) => opts.onError({}));
        render(<ProjectInvitationsSection projectId={3} />);

        fireEvent.click(screen.getByTitle('Revoke invitation'));

        expect(screen.getByText('Failed to revoke invitation.')).toBeInTheDocument();
    });
});
