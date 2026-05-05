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
        const response = await apiClient.get<ApiResponse<PaginatedResponse<ActivityItem>>>(
            '/api/v1/dashboard/activity',
            { params }
        );
        return response.data.data;
    },
};
