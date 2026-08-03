import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { PendingAccessRequestsSection } from '../PendingAccessRequestsSection';

const mutate = vi.fn();

const defaultRequests = () => [
    {
        id: 1,
        projectId: 3,
        userId: 42,
        suggestedRole: 'project_developer',
        grantedRole: '',
        state: 'pending',
        reason: 'need write',
        approvalsReceived: 1,
        requiredApprovals: 2,
    },
    {
        id: 2,
        projectId: 3,
        userId: 99,
        suggestedRole: 'project_viewer',
        grantedRole: 'project_viewer',
        state: 'approved',
        reason: '',
        approvalsReceived: 0,
        requiredApprovals: 1,
    },
];

let requests: any[] = defaultRequests();

vi.mock('../api', () => ({
    useProjectAccessRequests: () => ({ data: requests }),
    useResolveAccessRequest: () => ({ mutate, isPending: false }),
}));

const users = [{ id: 42, username: 'alice', displayName: 'Alice A', email: 'alice@demo.test' }];

beforeEach(() => {
    mutate.mockReset();
    requests = defaultRequests();
});

describe('PendingAccessRequestsSection', () => {
    it('shows only pending requests with a count badge and resolves the user name', () => {
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        expect(screen.getByText('Pending requests')).toBeInTheDocument();
        expect(screen.getByText('1')).toBeInTheDocument(); // count badge: 1 pending, not 2
        expect(screen.getByText('Alice A')).toBeInTheDocument(); // resolved from users
        expect(screen.getByText('“need write”')).toBeInTheDocument();
    });

    it('shows the dual-control approval progress when more than one approval is required', () => {
        render(<PendingAccessRequestsSection projectId={3} users={users} />);
        expect(screen.getByText('1 of 2 approvals')).toBeInTheDocument();
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

    it('renders nothing when there are no pending requests', () => {
        requests = [defaultRequests()[1]]; // only the 'approved' one
        const { container } = render(<PendingAccessRequestsSection projectId={3} users={users} />);
        expect(container).toBeEmptyDOMElement();
    });

    it('defaults the grant role to viewer, and the name/subtitle to fallbacks, when suggestedRole/user info is missing', () => {
        requests = [
            {
                id: 5,
                projectId: 3,
                userId: 77, // not present in `users`
                suggestedRole: '',
                grantedRole: '',
                state: 'pending',
                reason: '',
                approvalsReceived: 0,
                requiredApprovals: 1,
            },
        ];
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        expect(screen.getByText('User #77')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /approve/i }));
        expect(mutate.mock.calls[0][0]).toMatchObject({
            requestId: 5,
            action: 'approve',
            grantedRole: 'project_viewer',
        });
    });

    it('falls back to username and "requested <role>" when displayName/email are absent', () => {
        requests = [
            {
                id: 6,
                projectId: 3,
                userId: 78,
                suggestedRole: 'project_admin',
                grantedRole: '',
                state: 'pending',
                reason: '',
                approvalsReceived: 0,
                requiredApprovals: 1,
            },
        ];
        render(<PendingAccessRequestsSection projectId={3} users={[{ id: 78, username: 'bobby' }]} />);

        expect(screen.getByText('bobby')).toBeInTheDocument();
        expect(screen.getByText(/requested Admin/i)).toBeInTheDocument();
    });

    it('changing the grant-role select passes the newly selected role on approve', () => {
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        fireEvent.change(screen.getByTitle('Role to grant on approval'), { target: { value: 'project_admin' } });
        fireEvent.click(screen.getByRole('button', { name: /approve/i }));

        expect(mutate.mock.calls[0][0]).toMatchObject({ grantedRole: 'project_admin' });
    });

    it('reject Cancel hides the reason form without submitting', () => {
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: /^reject$/i }));
        fireEvent.change(screen.getByPlaceholderText('Reason (optional)'), { target: { value: 'oops' } });
        fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));

        expect(mutate).not.toHaveBeenCalled();
        expect(screen.queryByPlaceholderText('Reason (optional)')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /^reject$/i })).toBeInTheDocument();
    });

    it('reject confirm success closes the reason form again', () => {
        mutate.mockImplementation((_vars, opts) => opts.onSuccess());
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: /^reject$/i }));
        fireEvent.click(screen.getByRole('button', { name: /confirm reject/i }));

        expect(screen.queryByPlaceholderText('Reason (optional)')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /^reject$/i })).toBeInTheDocument();
    });

    it('surfaces the message from a failed resolve (approve)', () => {
        mutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'dual control required' } } })
        );
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: /approve/i }));

        expect(screen.getByText('dual control required')).toBeInTheDocument();
    });

    it('falls back to err.response.data.error when message is absent', () => {
        mutate.mockImplementation((_vars, opts) => opts.onError({ response: { data: { error: 'conflict' } } }));
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: /approve/i }));

        expect(screen.getByText('conflict')).toBeInTheDocument();
    });

    it('falls back to a default message when neither message nor error is present', () => {
        mutate.mockImplementation((_vars, opts) => opts.onError({}));
        render(<PendingAccessRequestsSection projectId={3} users={users} />);

        fireEvent.click(screen.getByRole('button', { name: /approve/i }));

        expect(screen.getByText('Failed to resolve request.')).toBeInTheDocument();
    });
});
