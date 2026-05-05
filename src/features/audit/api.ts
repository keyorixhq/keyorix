import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '../../services/dashboard';

export const useAuditLog = (params?: {
    page?: number;
    pageSize?: number;
    type?: string;
}) => {
    return useQuery({
        queryKey: ['audit-log', params],
        queryFn: () => dashboardApi.getActivity(params),
    });
};
