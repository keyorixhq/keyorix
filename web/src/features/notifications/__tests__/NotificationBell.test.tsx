import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { NotificationBell } from '../NotificationBell';

const markReadMutate = vi.fn();
const markAllMutate = vi.fn();
const navigate = vi.fn();

const baseNotifications = [
    {
        id: 1,
        type: 'access_request.approved',
        title: 'Approved',
        message: 'granted',
        link: '/projects/1',
        is_read: false,
        created_at: new Date().toISOString(),
    },
    {
        id: 2,
        type: 'x',
        title: 'Already read',
        message: 'm2',
        link: '',
        is_read: true,
        created_at: new Date().toISOString(),
    },
];

// Mutable so individual tests can swap in different unread counts / notification
// lists without redefining the whole mock factory (vi.mock factories can't
// close over per-test locals).
let mockData: { unread_count: number; notifications: typeof baseNotifications } | undefined = {
    unread_count: 2,
    notifications: baseNotifications,
};

vi.mock('react-router', async (orig) => {
    const actual = (await orig()) as object;
    return { ...actual, useNavigate: () => navigate };
});

vi.mock('../api', () => ({
    useNotifications: () => ({ data: mockData }),
    useMarkNotificationRead: () => ({ mutate: markReadMutate, isPending: false }),
    useMarkAllNotificationsRead: () => ({ mutate: markAllMutate, isPending: false }),
}));

beforeEach(() => {
    markReadMutate.mockClear();
    markAllMutate.mockClear();
    navigate.mockClear();
    mockData = { unread_count: 2, notifications: baseNotifications };
});

describe('NotificationBell', () => {
    it('shows the unread-count badge', () => {
        render(<NotificationBell />);
        expect(screen.getByText('2')).toBeInTheDocument();
    });

    it('opens the dropdown and lists notifications', () => {
        render(<NotificationBell />);
        fireEvent.click(screen.getByRole('button', { name: /notifications/i }));
        expect(screen.getByText('Approved')).toBeInTheDocument();
        expect(screen.getByText('Already read')).toBeInTheDocument();
    });

    it('clicking an unread item marks it read and navigates to its link', () => {
        render(<NotificationBell />);
        fireEvent.click(screen.getByRole('button', { name: /notifications/i }));
        fireEvent.click(screen.getByText('Approved'));
        expect(markReadMutate).toHaveBeenCalledWith(1);
        expect(navigate).toHaveBeenCalledWith('/projects/1');
    });

    it('clicking an already-read item with no link does not mark-read or navigate', () => {
        render(<NotificationBell />);
        fireEvent.click(screen.getByRole('button', { name: /notifications/i }));
        fireEvent.click(screen.getByText('Already read'));
        expect(markReadMutate).not.toHaveBeenCalled();
        expect(navigate).not.toHaveBeenCalled();
    });

    it('Mark all read triggers the mutation', () => {
        render(<NotificationBell />);
        fireEvent.click(screen.getByRole('button', { name: /notifications/i }));
        fireEvent.click(screen.getByRole('button', { name: /mark all read/i }));
        expect(markAllMutate).toHaveBeenCalled();
    });

    it('caps the badge at "9+" once unread count exceeds nine', () => {
        mockData = { ...mockData, unread_count: 15 };
        render(<NotificationBell />);
        expect(screen.getByText('9+')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Notifications (15 unread)' })).toBeInTheDocument();
    });

    it('hides the badge and "Mark all read" when there are no unread notifications', () => {
        mockData = { unread_count: 0, notifications: baseNotifications };
        render(<NotificationBell />);
        expect(screen.queryByText('2')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Notifications' }));
        expect(screen.queryByRole('button', { name: /mark all read/i })).not.toBeInTheDocument();
    });

    it('shows the empty state when there are no notifications', () => {
        mockData = { unread_count: 0, notifications: [] };
        render(<NotificationBell />);
        fireEvent.click(screen.getByRole('button', { name: /notifications/i }));
        expect(screen.getByText('You’re all caught up.')).toBeInTheDocument();
    });

    it('closes the dropdown when the backdrop is clicked', () => {
        const { container } = render(<NotificationBell />);
        fireEvent.click(screen.getByRole('button', { name: /notifications/i }));
        expect(screen.getByText('Approved')).toBeInTheDocument();

        const backdrop = container.querySelector('.fixed.inset-0.z-40');
        expect(backdrop).not.toBeNull();
        fireEvent.click(backdrop as Element);
        expect(screen.queryByText('Approved')).not.toBeInTheDocument();
    });

    it('falls back to an empty list and zero unread count when the query has no data yet', () => {
        mockData = undefined;
        render(<NotificationBell />);
        expect(screen.queryByText('2')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Notifications' }));
        expect(screen.getByText('You’re all caught up.')).toBeInTheDocument();
    });

    it('renders relative time labels for minutes/hours/days-old notifications', () => {
        const now = Date.now();
        mockData = {
            unread_count: 0,
            notifications: [
                {
                    id: 3,
                    type: 'x',
                    title: 'Minutes old',
                    message: 'm',
                    link: '',
                    is_read: true,
                    created_at: new Date(now - 5 * 60 * 1000).toISOString(),
                },
                {
                    id: 4,
                    type: 'x',
                    title: 'Hours old',
                    message: 'h',
                    link: '',
                    is_read: true,
                    created_at: new Date(now - 3 * 60 * 60 * 1000).toISOString(),
                },
                {
                    id: 5,
                    type: 'x',
                    title: 'Days old',
                    message: 'd',
                    link: '',
                    is_read: true,
                    created_at: new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString(),
                },
            ],
        };
        render(<NotificationBell />);
        fireEvent.click(screen.getByRole('button', { name: /notifications/i }));
        expect(screen.getByText('5m ago')).toBeInTheDocument();
        expect(screen.getByText('3h ago')).toBeInTheDocument();
        expect(screen.getByText('2d ago')).toBeInTheDocument();
    });
});
