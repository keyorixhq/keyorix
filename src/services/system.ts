import { apiClient } from './client';
import { ApiResponse } from '../types';

export const systemApi = {
    async getInfo(): Promise<any> {
        const response = await apiClient.get<ApiResponse<any>>('/api/v1/system/info');
        return response.data.data;
    },

    async getMetrics(): Promise<any> {
        const response = await apiClient.get<ApiResponse<any>>('/api/v1/system/metrics');
        return response.data.data;
    },
};
