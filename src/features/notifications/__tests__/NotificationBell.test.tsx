import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { NotificationBell } from '../NotificationBell';

const markReadMutate = vi.fn();
const markAllMutate = vi.fn();
const navigate = vi.fn();

vi.mock('react-router-dom', async (orig) => {
    const actual = (await orig()) as object;
    return { ...actual, useNavigate: () => navigate };
});

vi.mock('../api', () => ({
    useNotifications: () => ({
        data: {
            unread_count: 2,
            notifications: [
                { id: 1, type: 'access_request.approved', title: 'Approved', message: 'granted', link: '/projects/1', is_read: false, created_at: new Date().toISOString() },
                { id: 2, type: 'x', title: 'Already read', message: 'm2', link: '', is_read: true, created_at: new Date().toISOString() },
            ],
        },
    }),
    useMarkNotificationRead: () => ({ mutate: markReadMutate, isPending: false }),
    useMarkAllNotificationsRead: () => ({ mutate: markAllMutate, isPending: false }),
}));

beforeEach(() => {
    markReadMutate.mockClear();
    markAllMutate.mockClear();
    navigate.mockClear();
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

    it('Mark all read triggers the mutation', () => {
        render(<NotificationBell />);
        fireEvent.click(screen.getByRole('button', { name: /notifications/i }));
        fireEvent.click(screen.getByRole('button', { name: /mark all read/i }));
        expect(markAllMutate).toHaveBeenCalled();
    });
});
