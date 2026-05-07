import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../services/client';

export interface AuditLogEntry {
    id: number;
    event_type: string;
    actor: string;
    description: string;
    timestamp: string;
}

export const useAuditLog = (params?: {
    page?: number;
    pageSize?: number;
    action?: string;
    projectId?: number;
}) => {
    return useQuery({
        queryKey: ['audit-log', params],
        queryFn: async () => {
            const response = await apiClient.get('/api/v1/audit/logs', {
                params: {
                    page: params?.page ?? 1,
                    page_size: params?.pageSize ?? 50,
                    ...(params?.action ? { action: params.action } : {}),
                    ...(params?.projectId ? { project_id: params.projectId } : {}),
                },
            });
            const data = response.data.data;
            return {
                data: (data.logs ?? []) as AuditLogEntry[],
                total: data.total ?? 0,
                page: data.page ?? 1,
                pageSize: data.page_size ?? 50,
                totalPages: data.total_pages ?? 1,
            };
        },
    });
};
