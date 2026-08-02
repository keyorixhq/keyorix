import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: { get: vi.fn(), post: vi.fn() },
}));

import { apiClient } from '../client';
import { notificationsApi } from '../notifications';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
};

beforeEach(() => vi.clearAllMocks());

describe('notificationsApi', () => {
    it('list unwraps {notifications, unread_count} and passes unread/limit params', async () => {
        mocked.get.mockResolvedValue({
            data: { data: { notifications: [{ id: 1, title: 'A' }], unread_count: 3 } },
        });
        const res = await notificationsApi.list({ unread: true, limit: 20 });
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/notifications', { params: { unread: 'true', limit: 20 } });
        expect(res.unread_count).toBe(3);
        expect(res.notifications).toHaveLength(1);
    });

    it('list defaults to empty when data is missing', async () => {
        mocked.get.mockResolvedValue({ data: {} });
        const res = await notificationsApi.list();
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/notifications', { params: {} });
        expect(res).toEqual({ notifications: [], unread_count: 0 });
    });

    it('list falls back to the {} default when response.data itself is falsy', async () => {
        mocked.get.mockResolvedValue({ data: null });
        const res = await notificationsApi.list();
        expect(res).toEqual({ notifications: [], unread_count: 0 });
    });

    it('markRead and markAllRead post to the right paths', async () => {
        mocked.post.mockResolvedValue({ data: {} });
        await notificationsApi.markRead(7);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/notifications/7/read');
        await notificationsApi.markAllRead();
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/notifications/read-all');
    });
});
