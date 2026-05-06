import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../services/client';

export const useAuditLog = (params?: {
    page?: number;
    pageSize?: number;
    type?: string;
}) => {
    return useQuery({
        queryKey: ['audit-log', params],
        queryFn: async () => {
            // Try the real DB-backed activity feed first
            const response = await apiClient.get('/api/v1/dashboard/activity', { params: { page: params?.page ?? 1, pageSize: params?.pageSize ?? 50 } });
            const feed = response.data.data;
            const items = (feed.items ?? []).map((item: any) => ({
                id: item.id,
                type: item.type,
                secretName: item.secretName,
                timestamp: item.timestamp,
                actor: item.actor,
            }));
            return { data: items, total: feed.total ?? 0 };
        },
    });
};
