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

    async getUserRoles(userId: number): Promise<{ id: number; name: string }[]> {
        const response = await apiClient.get<ApiResponse<{ roles: { id: number; name: string }[] }>>(
            `/api/v1/users/${userId}/roles`
        );
        return response.data.data?.roles ?? [];
    },

    async updateUserRoles(userId: number, roleIds: number[]): Promise<void> {
        await apiClient.put(`/api/v1/users/${userId}/roles`, { role_ids: roleIds });
    },
};
