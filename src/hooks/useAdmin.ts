import { useQuery } from '@tanstack/react-query';
import { apiService } from '../services/api';
import { queryKeys } from '../lib/queryClient';
// Types are imported in the query functions as needed

// Admin query hooks
export const useAdminStats = () => {
    return useQuery({
        queryKey: queryKeys.admin.stats(),
        queryFn: () => apiService.admin.getStats(),
        staleTime: 2 * 60 * 1000, // 2 minutes
        refetchInterval: 5 * 60 * 1000, // Refetch every 5 minutes
    });
};

export const useAdminUsers = (params?: {
    page?: number;
    pageSize?: number;
    search?: string;
}) => {
    return useQuery({
        queryKey: queryKeys.admin.users(params),
        queryFn: () => apiService.admin.getUsers(params),
        enabled: true,
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
};

export const useAdminRoles = () => {
    return useQuery({
        queryKey: queryKeys.admin.roles(),
        queryFn: () => apiService.admin.getRoles(),
        staleTime: 10 * 60 * 1000, // 10 minutes - roles don't change often
    });
};

export const useAdminAuditLogs = (params?: {
    page?: number;
    pageSize?: number;
    userId?: number;
    action?: string;
    startDate?: string;
    endDate?: string;
}) => {
    return useQuery({
        queryKey: queryKeys.admin.audit(params),
        queryFn: () => apiService.admin.getAuditLogs(params),
        enabled: true,
        staleTime: 1 * 60 * 1000, // 1 minute - audit logs should be fresh
    });
};