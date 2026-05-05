import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, Recipient } from '../types';
import { API_ENDPOINTS } from '../constants';

export const groupsApi = {
    async list(params?: {
        page?: number;
        pageSize?: number;
        search?: string;
    }): Promise<PaginatedResponse<any>> {
        const response = await apiClient.get<ApiResponse<PaginatedResponse<any>>>(
            API_ENDPOINTS.GROUPS.LIST,
            { params }
        );
        return response.data.data;
    },

    async get(id: number): Promise<any> {
        const response = await apiClient.get<ApiResponse<any>>(API_ENDPOINTS.GROUPS.GET(id));
        return response.data.data;
    },

    async search(query: string): Promise<Recipient[]> {
        const response = await apiClient.get<ApiResponse<Recipient[]>>(
            API_ENDPOINTS.GROUPS.SEARCH,
            { params: { q: query } }
        );
        return response.data.data;
    },
};
