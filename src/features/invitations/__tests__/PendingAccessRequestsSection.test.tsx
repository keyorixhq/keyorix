import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { PendingAccessRequestsSection } from '../PendingAccessRequestsSection';

const mutate = vi.fn();

vi.mock('../api', () => ({
    useProjectAccessRequests: () => ({
        data: [
            { id: 1, projectId: 3, userId: 42, suggestedRole: 'project_developer', grantedRole: '', state: 'pending', reason: 'need write' },
            { id: 2, projectId: 3, userId: 99, suggestedRole: 'project_viewer', grantedRole: 'project_viewer', state: 'approved', reason: '' },
        ],
    }),
    useResolveAccessRequest: () => ({ mutate, isPending: false }),
}));

const users = [{ id: 42, username: 'alice', displayName: 'Alice A', email: 'alice@demo.test' }];

beforeEach(() => {
    mutate.mockClear();
});

describe('PendingAccessRequestsSection', () => {
    it('shows only pending requests with a count badge and resolves the user name', () => {
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        expect(screen.getByText('Pending requests')).toBeInTheDocument();
        expect(screen.getByText('1')).toBeInTheDocument(); // count badge: 1 pending, not 2
        expect(screen.getByText('Alice A')).toBeInTheDocument(); // resolved from users
        expect(screen.getByText('“need write”')).toBeInTheDocument();
    });

    it('approves with the suggested role pre-selected', () => {
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: /approve/i }));

        expect(mutate).toHaveBeenCalledTimes(1);
        expect(mutate.mock.calls[0][0]).toMatchObject({
            requestId: 1,
            action: 'approve',
            grantedRole: 'project_developer',
        });
    });

    it('reject reveals a reason field and confirms with the reason', () => {
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: /^reject$/i }));
        const input = screen.getByPlaceholderText('Reason (optional)');
        fireEvent.change(input, { target: { value: 'duplicate' } });
        fireEvent.click(screen.getByRole('button', { name: /confirm reject/i }));

        expect(mutate.mock.calls[0][0]).toMatchObject({
            requestId: 1,
            action: 'reject',
            reason: 'duplicate',
        });
    });
});
