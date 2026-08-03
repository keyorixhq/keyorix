import { apiClient } from './client';

// In-app notifications (ADR-024). Self-scoped to the signed-in user; surfaced by
// the header bell. The Go DTO is snake_case.

export interface NotificationItem {
    id: number;
    type: string;
    title: string;
    message: string;
    link: string;
    is_read: boolean;
    created_at: string;
    project_id?: number;
}

export interface NotificationList {
    notifications: NotificationItem[];
    unread_count: number;
}

export const notificationsApi = {
    async list(params?: { unread?: boolean; limit?: number }): Promise<NotificationList> {
        const response = await apiClient.get('/api/v1/notifications', {
            params: {
                ...(params?.unread ? { unread: 'true' } : {}),
                ...(params?.limit ? { limit: params.limit } : {}),
            },
        });
        const d = response.data?.data ?? response.data ?? {};
        return { notifications: d.notifications ?? [], unread_count: d.unread_count ?? 0 };
    },

    async markRead(id: number): Promise<void> {
        await apiClient.post(`/api/v1/notifications/${id}/read`);
    },

    async markAllRead(): Promise<void> {
        await apiClient.post('/api/v1/notifications/read-all');
    },
};
