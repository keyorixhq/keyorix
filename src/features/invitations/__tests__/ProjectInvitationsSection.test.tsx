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
    revoke.mockClear();
});

describe('ProjectInvitationsSection — stale warnings', () => {
    it('flags a pending invite older than 7 days as stale with a banner', () => {
        invitations = [
            { id: 1, projectId: 3, email: 'old@demo.test', role: 'project_viewer', state: 'pending', invitedBy: 1, createdAt: daysAgo(10) },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.getByText('Stale')).toBeInTheDocument();
        expect(screen.getByText(/1 invitation has been pending over a week/i)).toBeInTheDocument();
        expect(screen.getByText(/pending 10 days/i)).toBeInTheDocument();
    });

    it('does not flag a recent pending invite', () => {
        invitations = [
            { id: 2, projectId: 3, email: 'fresh@demo.test', role: 'project_viewer', state: 'pending', invitedBy: 1, createdAt: daysAgo(2) },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.queryByText('Stale')).not.toBeInTheDocument();
        expect(screen.queryByText(/pending over a week/i)).not.toBeInTheDocument();
    });

    it('does not flag an old non-pending invite (accepted/revoked age out cleanly)', () => {
        invitations = [
            { id: 3, projectId: 3, email: 'done@demo.test', role: 'project_viewer', state: 'accepted', invitedBy: 1, createdAt: daysAgo(30) },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.queryByText('Stale')).not.toBeInTheDocument();
    });

    it('pluralizes and counts multiple stale invites, ordering them first', () => {
        invitations = [
            { id: 4, projectId: 3, email: 'fresh@demo.test', role: 'project_viewer', state: 'pending', invitedBy: 1, createdAt: daysAgo(1) },
            { id: 5, projectId: 3, email: 'old1@demo.test', role: 'project_viewer', state: 'pending', invitedBy: 1, createdAt: daysAgo(8) },
            { id: 6, projectId: 3, email: 'old2@demo.test', role: 'project_developer', state: 'pending', invitedBy: 1, createdAt: daysAgo(20) },
        ];
        render(<ProjectInvitationsSection projectId={3} />);

        expect(screen.getByText(/2 invitations have been pending over a week/i)).toBeInTheDocument();
        // Stale ones sort to the top: the first two emails rendered are the stale pair.
        const emails = screen.getAllByText(/@demo\.test$/).map(n => n.textContent);
        expect(emails.slice(0, 2)).toEqual(expect.arrayContaining(['old1@demo.test', 'old2@demo.test']));
        expect(emails[2]).toBe('fresh@demo.test');
    });
});
