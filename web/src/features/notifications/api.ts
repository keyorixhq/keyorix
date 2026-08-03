import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { notificationsApi } from '../../services/notifications';

const KEY = ['notifications'];

// useNotifications backs the header bell. It polls so the unread badge stays
// fresh without a websocket. admin/non-admin alike have notifications, so there
// is no gate; a transient failure just leaves the last value (retry: false).
export const useNotifications = () =>
    useQuery({
        queryKey: KEY,
        queryFn: () => notificationsApi.list({ limit: 20 }),
        refetchInterval: 60 * 1000,
        refetchOnWindowFocus: true,
        retry: false,
        staleTime: 30 * 1000,
    });

export const useMarkNotificationRead = () => {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => notificationsApi.markRead(id),
        onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
    });
};

export const useMarkAllNotificationsRead = () => {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: () => notificationsApi.markAllRead(),
        onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
    });
};
