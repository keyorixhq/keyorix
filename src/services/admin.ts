import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, User } from '../types';
import { API_ENDPOINTS } from '../constants';

export const adminApi = {
    async getStats(): Promise<any> {
        const response = await apiClient.get<ApiResponse<any>>(API_ENDPOINTS.ADMIN.STATS);
        return response.data.data;
    },

    async getUsers(params?: {
        page?: number;
        pageSize?: number;
        search?: string;
    }): Promise<PaginatedResponse<User>> {
        const response = await apiClient.get<ApiResponse<PaginatedResponse<User>>>(
            API_ENDPOINTS.ADMIN.USERS,
            { params }
        );
        return response.data.data;
    },

    async getRoles(): Promise<any[]> {
        const response = await apiClient.get<ApiResponse<any[]>>(API_ENDPOINTS.ADMIN.ROLES);
        return response.data.data;
    },

    async getAuditLogs(params?: {
        page?: number;
        pageSize?: number;
        userId?: number;
        action?: string;
        startDate?: string;
        endDate?: string;
    }): Promise<PaginatedResponse<any>> {
        const response = await apiClient.get<ApiResponse<PaginatedResponse<any>>>(
            API_ENDPOINTS.ADMIN.AUDIT,
            { params }
        );
        return response.data.data;
    },
};
