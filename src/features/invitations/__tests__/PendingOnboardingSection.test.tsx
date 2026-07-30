import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { PendingOnboardingSection } from '../PendingOnboardingSection';

const mutate = vi.fn();

vi.mock('../../projects/api', () => ({
    useProjectMemberships: () => ({
        data: [
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
        ],
    }),
    useTransitionMembership: () => ({ mutate, isPending: false }),
}));

const users = [
    { id: 42, username: 'alice', displayName: 'Alice A', email: 'alice@demo.test' },
    { id: 43, username: 'bob', displayName: 'Bob B', email: 'bob@demo.test' },
    { id: 44, username: 'carol', displayName: 'Carol C', email: 'carol@demo.test' },
    { id: 45, username: 'dave', displayName: 'Dave D', email: 'dave@demo.test' },
];

beforeEach(() => {
    mutate.mockClear();
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
});
