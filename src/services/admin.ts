import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, User } from '../types';

// Normalize role object — handles Go-serialized uppercase field names
function normalizeRole(r: any): { id: number; name: string; description: string } {
    return {
        id: r.id ?? r.ID ?? 0,
        name: r.name ?? r.Name ?? '',
        description: r.description ?? r.Description ?? '',
    };
}

export const adminApi = {
    async getStats(): Promise<any> {
        const response = await apiClient.get<ApiResponse<any>>('/api/v1/dashboard/stats');
        return response.data.data;
    },

    async getUsers(params?: {
        page?: number;
        pageSize?: number;
        search?: string;
    }): Promise<PaginatedResponse<User>> {
        const response = await apiClient.get<ApiResponse<PaginatedResponse<User>>>(
            '/api/v1/users',
            { params }
        );
        return response.data.data;
    },

    async getRoles(): Promise<{ id: number; name: string; description: string }[]> {
        const response = await apiClient.get('/api/v1/roles');
        const data = response.data.data;
        const roles = Array.isArray(data) ? data : (data?.roles ?? []);
        return roles.map(normalizeRole);
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
            '/api/v1/audit/logs',
            { params }
        );
        return response.data.data;
    },

    async getUserRoles(userId: number): Promise<{ id: number; name: string }[]> {
        const response = await apiClient.get(
            `/api/v1/users/${userId}/roles`
        );
        const data = response.data.data;
        const roles = data?.roles ?? data ?? [];
        return Array.isArray(roles) ? roles.map(normalizeRole) : [];
    },

    async updateUserRoles(userId: number, roleIds: number[]): Promise<void> {
        await apiClient.put(`/api/v1/users/${userId}/roles`, { role_ids: roleIds });
    },

    // Start impersonating a user. Returns a session token for the target user;
    // the caller swaps the active session to it (authStore.startImpersonation).
    async impersonate(userId: number): Promise<ImpersonationResponse> {
        const response = await apiClient.post<ApiResponse<ImpersonationResponse>>(
            '/api/v1/admin/impersonate',
            { user_id: userId }
        );
        return response.data.data;
    },
};

export interface ImpersonationResponse {
    token: string;
    expires_at?: string;
    user_id: number;
    username: string;
    display_name?: string;
    impersonated_by: number;
}
