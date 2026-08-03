import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/notifications', () => ({
    notificationsApi: {
        list: vi.fn(),
        markRead: vi.fn(),
        markAllRead: vi.fn(),
    },
}));

import { notificationsApi } from '../../../services/notifications';
import { useNotifications, useMarkNotificationRead, useMarkAllNotificationsRead } from '../api';

const mockApi = notificationsApi as unknown as Record<string, ReturnType<typeof vi.fn>>;

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => {
    vi.clearAllMocks();
});

describe('useNotifications', () => {
    it('fetches the notification list with a limit of 20', async () => {
        mockApi.list!.mockResolvedValueOnce({ notifications: [{ id: 1 }], unread_count: 1 });
        const { result } = renderHook(() => useNotifications(), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockApi.list).toHaveBeenCalledWith({ limit: 20 });
        expect(result.current.data).toEqual({ notifications: [{ id: 1 }], unread_count: 1 });
    });
});

describe('useMarkNotificationRead', () => {
    it('marks a notification read and invalidates the notifications query', async () => {
        mockApi.markRead!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useMarkNotificationRead(), { wrapper });

        act(() => {
            result.current.mutate(5);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockApi.markRead).toHaveBeenCalledWith(5);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['notifications'] });
    });
});

describe('useMarkAllNotificationsRead', () => {
    it('marks all notifications read and invalidates the notifications query', async () => {
        mockApi.markAllRead!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useMarkAllNotificationsRead(), { wrapper });

        act(() => {
            result.current.mutate();
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockApi.markAllRead).toHaveBeenCalled();
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['notifications'] });
    });
});
