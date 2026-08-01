import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { notificationChannelsApi, NotificationChannelPayload } from '../../services/notificationChannels';

const CHANNELS_KEY = ['notification-channels'];
const retryPolicyKey = (id: number) => ['notification-channels', id, 'retry-policy'];

export const useNotificationChannels = () =>
    useQuery({
        queryKey: CHANNELS_KEY,
        queryFn: () => notificationChannelsApi.list(),
        staleTime: 60 * 1000,
    });

export const useCreateNotificationChannel = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (body: NotificationChannelPayload) => notificationChannelsApi.create(body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: CHANNELS_KEY }),
    });
};

export const useUpdateNotificationChannel = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, body }: { id: number; body: NotificationChannelPayload }) =>
            notificationChannelsApi.update(id, body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: CHANNELS_KEY }),
    });
};

export const useDeleteNotificationChannel = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => notificationChannelsApi.delete(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: CHANNELS_KEY }),
    });
};

export const useRetryPolicy = (channelId: number | null) =>
    useQuery({
        queryKey: retryPolicyKey(channelId ?? -1),
        queryFn: () => notificationChannelsApi.getRetryPolicy(channelId!),
        enabled: channelId !== null,
        staleTime: 60 * 1000,
    });

export const useSetRetryPolicy = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, body }: { id: number; body: { max_retries: number; retry_backoff_ms: number } }) =>
            notificationChannelsApi.setRetryPolicy(id, body),
        onSuccess: (_data, { id }) => queryClient.invalidateQueries({ queryKey: retryPolicyKey(id) }),
    });
};
