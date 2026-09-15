import { apiClient } from './client';
import { ApiResponse, Recipient } from '../types';
import { API_ENDPOINTS } from '../constants';

export const groupsApi = {
    // The server returns { groups: [...], total } under the ApiResponse `data`
    // envelope — not a PaginatedResponse. Type it to match so callers read
    // `.groups` (reading `.data` here silently yielded an empty list).
    async list(params?: { page?: number; pageSize?: number; search?: string }): Promise<{ groups: any[]; total: number }> {
        const response = await apiClient.get<ApiResponse<{ groups: any[]; total: number }>>(API_ENDPOINTS.GROUPS.LIST, {
            params,
        });
        return response.data.data;
    },

    async get(id: number): Promise<any> {
        const response = await apiClient.get<ApiResponse<any>>(API_ENDPOINTS.GROUPS.GET(id));
        return response.data.data;
    },

    async search(query: string): Promise<Recipient[]> {
        const response = await apiClient.get<ApiResponse<Recipient[]>>(API_ENDPOINTS.GROUPS.SEARCH, {
            params: { q: query },
        });
        return response.data.data;
    },
};
