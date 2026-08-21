import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { PendingOnboardingSection } from '../PendingOnboardingSection';

const mutate = vi.fn();

// ISO timestamp `days` ago.
const daysAgo = (days: number) => new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

const defaultMemberships = () => [
    {
        id: 1,
        projectId: 3,
        userId: 42,
        role: 'project_developer',
        state: 'invited',
        invitedAt: '2026-07-01T00:00:00Z',
    },
    { id: 2, projectId: 3, userId: 43, role: 'project_viewer', state: 'identity_verified' },
    { id: 3, projectId: 3, userId: 44, role: 'project_viewer', state: 'provisioned' },
    { id: 4, projectId: 3, userId: 45, role: 'project_admin', state: 'active' },
];

let memberships: any[] = defaultMemberships();

vi.mock('../../projects/api', () => ({
    useProjectMemberships: () => ({ data: memberships }),
    useTransitionMembership: () => ({ mutate, isPending: false }),
}));

const users = [
    { id: 42, username: 'alice', displayName: 'Alice A', email: 'alice@demo.test' },
    { id: 43, username: 'bob', displayName: 'Bob B', email: 'bob@demo.test' },
    { id: 44, username: 'carol', displayName: 'Carol C', email: 'carol@demo.test' },
    { id: 45, username: 'dave', displayName: 'Dave D', email: 'dave@demo.test' },
];

beforeEach(() => {
    mutate.mockReset();
    memberships = defaultMemberships();
});

describe('PendingOnboardingSection', () => {
    it('shows only non-active, non-revoked memberships with a count', () => {
        render(<PendingOnboardingSection projectId={3} users={users} />);

        expect(screen.getByText('Pending onboarding (3)')).toBeInTheDocument();
        expect(screen.getByText('Alice A')).toBeInTheDocument();
        expect(screen.getByText('Bob B')).toBeInTheDocument();
        expect(screen.getByText('Carol C')).toBeInTheDocument();
        expect(screen.queryByText('Dave D')).not.toBeInTheDocument(); // active — not shown
    });

    it('shows the right next-action label per state', () => {
        render(<PendingOnboardingSection projectId={3} users={users} />);

        expect(screen.getByRole('button', { name: 'Mark identity verified' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Mark account provisioned' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Activate — grants project role' })).toBeInTheDocument();
    });

    it('advances a membership with the correct action', () => {
        render(<PendingOnboardingSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: 'Mark identity verified' }));

        expect(mutate).toHaveBeenCalledTimes(1);
        expect(mutate.mock.calls[0][0]).toEqual({ membershipId: 1, action: 'verify' });
    });

    it('shows the invited-days-ago hint', () => {
        render(<PendingOnboardingSection projectId={3} users={users} />);
        expect(screen.getByText(/invited \d+ days? ago/)).toBeInTheDocument();
    });

    it('renders nothing when every membership is active or revoked', () => {
        memberships = [
            { id: 4, projectId: 3, userId: 45, role: 'project_admin', state: 'active' },
            { id: 5, projectId: 3, userId: 46, role: 'project_viewer', state: 'revoked' },
        ];
        const { container } = render(<PendingOnboardingSection projectId={3} users={users} />);
        expect(container).toBeEmptyDOMElement();
    });

    it('uses the singular "day" when invited exactly 1 day ago', () => {
        memberships = [
            { id: 1, projectId: 3, userId: 42, role: 'project_developer', state: 'invited', invitedAt: daysAgo(1) },
        ];
        render(<PendingOnboardingSection projectId={3} users={users} />);
        expect(screen.getByText(/invited 1 day ago/)).toBeInTheDocument();
        expect(screen.queryByText(/invited 1 days ago/)).not.toBeInTheDocument();
    });

    it('does not blow up and hides the days hint when invitedAt is unparseable', () => {
        memberships = [
            {
                id: 1,
                projectId: 3,
                userId: 42,
                role: 'project_developer',
                state: 'invited',
                invitedAt: 'not-a-date',
            },
        ];
        render(<PendingOnboardingSection projectId={3} users={users} />);
        expect(screen.queryByText(/invited/)).not.toBeInTheDocument();
    });

    it('falls back through user label variants: unknown user, username-only, and bare id', () => {
        memberships = [
            { id: 1, projectId: 3, userId: 999, role: 'project_developer', state: 'invited' }, // no matching user
            { id: 2, projectId: 3, userId: 43, role: 'project_viewer', state: 'identity_verified' },
        ];
        render(
            <PendingOnboardingSection
                projectId={3}
                users={[{ id: 43, username: 'bob' }]} // no displayName, no email
            />
        );

        expect(screen.getByText('Unknown user')).toBeInTheDocument();
        expect(screen.getByText('bob')).toBeInTheDocument();
    });

    it('falls back to "user <id>" when a matched user has no displayName, username, or email', () => {
        memberships = [{ id: 1, projectId: 3, userId: 50, role: 'project_developer', state: 'invited' }];
        render(<PendingOnboardingSection projectId={3} users={[{ id: 50 }]} />);

        expect(screen.getByText('user 50')).toBeInTheDocument();
    });

    it('falls back to the raw state string when it has no known label', () => {
        memberships = [{ id: 1, projectId: 3, userId: 42, role: 'project_developer', state: 'some_unmapped_state' }];
        render(<PendingOnboardingSection projectId={3} users={users} />);

        expect(screen.getByText('some_unmapped_state')).toBeInTheDocument();
        // No known next action for an unmapped state — only the revoke button renders.
        expect(screen.queryByRole('button', { name: /Mark|Activate/ })).not.toBeInTheDocument();
    });

    it('revokes (cancels) an onboarding membership', () => {
        memberships = [
            { id: 1, projectId: 3, userId: 42, role: 'project_developer', state: 'invited', invitedAt: daysAgo(1) },
        ];
        render(<PendingOnboardingSection projectId={3} users={users} />);

        fireEvent.click(screen.getByTitle('Cancel onboarding'));

        expect(mutate).toHaveBeenCalledTimes(1);
        expect(mutate.mock.calls[0][0]).toEqual({ membershipId: 1, action: 'revoke' });
    });

    it('surfaces the error message from a failed transition', () => {
        memberships = [
            { id: 1, projectId: 3, userId: 42, role: 'project_developer', state: 'invited', invitedAt: daysAgo(1) },
        ];
        mutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'membership locked' } } })
        );
        render(<PendingOnboardingSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: 'Mark identity verified' }));

        expect(screen.getByText('membership locked')).toBeInTheDocument();
    });

    it('falls back to err.response.data.error when message is absent', () => {
        memberships = [
            { id: 1, projectId: 3, userId: 42, role: 'project_developer', state: 'invited', invitedAt: daysAgo(1) },
        ];
        mutate.mockImplementation((_vars, opts) => opts.onError({ response: { data: { error: 'conflict' } } }));
        render(<PendingOnboardingSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: 'Mark identity verified' }));

        expect(screen.getByText('conflict')).toBeInTheDocument();
    });

    it('falls back to a default message when neither message nor error is present', () => {
        memberships = [
            { id: 1, projectId: 3, userId: 42, role: 'project_developer', state: 'invited', invitedAt: daysAgo(1) },
        ];
        mutate.mockImplementation((_vars, opts) => opts.onError({}));
        render(<PendingOnboardingSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: 'Mark identity verified' }));

        expect(screen.getByText('Failed to update onboarding.')).toBeInTheDocument();
    });
});
