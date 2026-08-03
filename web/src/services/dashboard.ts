import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, DashboardStats, ActivityItem } from '../types';

export const dashboardApi = {
    async getStats(): Promise<DashboardStats> {
        const response = await apiClient.get<ApiResponse<DashboardStats>>('/api/v1/dashboard/stats');
        return response.data.data;
    },

    async getActivity(params?: {
        page?: number;
        pageSize?: number;
        type?: string;
    }): Promise<PaginatedResponse<ActivityItem>> {
        const response = await apiClient.get<ApiResponse<any>>('/api/v1/dashboard/activity', { params });
        const feed = response.data.data;
        return {
            data: feed.items ?? [],
            total: feed.total ?? 0,
            page: feed.page ?? 1,
            pageSize: feed.pageSize ?? 10,
            totalPages: Math.max(1, Math.ceil((feed.total ?? 0) / (feed.pageSize ?? 10))),
        };
    },
};
