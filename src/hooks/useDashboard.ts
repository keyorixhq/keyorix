import { useQuery } from '@tanstack/react-query';
import { apiService } from '../services/api';
import { queryKeys } from '../lib/queryClient';
// Types are imported in the query functions as needed

// Dashboard query hooks
export const useDashboardStats = () => {
    return useQuery({
        queryKey: queryKeys.dashboard.stats(),
        queryFn: () => apiService.dashboard.getStats(),
        staleTime: 2 * 60 * 1000, // 2 minutes
        refetchInterval: 5 * 60 * 1000, // Refetch every 5 minutes
    });
};

export const useDashboardActivity = (params?: {
    page?: number;
    pageSize?: number;
    type?: string;
}) => {
    return useQuery({
        queryKey: queryKeys.dashboard.activity(params),
        queryFn: () => apiService.dashboard.getActivity(params),
        staleTime: 1 * 60 * 1000, // 1 minute
        refetchInterval: 2 * 60 * 1000, // Refetch every 2 minutes
    });
};

// Users query hooks
export const useUsers = (params?: {
    page?: number;
    pageSize?: number;
    search?: string;
}) => {
    return useQuery({
        queryKey: queryKeys.users.list(params),
        queryFn: () => apiService.users.list(params),
        enabled: true,
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
};

export const useUser = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.users.detail(id),
        queryFn: () => apiService.users.get(id),
        enabled: enabled && id > 0,
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
};

// Groups query hooks
export const useGroups = (params?: {
    page?: number;
    pageSize?: number;
    search?: string;
}) => {
    return useQuery({
        queryKey: queryKeys.groups.list(params),
        queryFn: () => apiService.groups.list(params),
        enabled: true,
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
};

export const useGroup = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.groups.detail(id),
        queryFn: () => apiService.groups.get(id),
        enabled: enabled && id > 0,
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
};