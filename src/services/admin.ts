import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, User } from '../types';
import type { Permission } from '../types/rbac';

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

    // A user's effective permission set — the de-duplicated union across their roles
    // (the server already excludes expired time-bound grants).
    async getUserPermissions(userId: number): Promise<Permission[]> {
        const response = await apiClient.get(`/api/v1/users/${userId}/permissions`);
        const data = response.data.data;
        const permissions = data?.permissions ?? data ?? [];
        return Array.isArray(permissions) ? permissions : [];
    },

    // On-demand triggers for the scheduled notification/alert jobs (system.write).
    async runAnomalyAlerts(): Promise<{ alerted: number }> {
        const response = await apiClient.post<ApiResponse<{ alerted: number }>>('/api/v1/admin/jobs/anomaly-alerts', {});
        return response.data.data;
    },
    async runRotationReminders(): Promise<{ sent: number }> {
        const response = await apiClient.post<ApiResponse<{ sent: number }>>('/api/v1/admin/jobs/rotation-reminders', {});
        return response.data.data;
    },
    async runExpiryReminders(): Promise<{ sent: number }> {
        const response = await apiClient.post<ApiResponse<{ sent: number }>>('/api/v1/admin/jobs/expiry-reminders', {});
        return response.data.data;
    },
    async runComplianceDigest(): Promise<{ sent: boolean }> {
        const response = await apiClient.post<ApiResponse<{ sent: boolean }>>('/api/v1/admin/jobs/compliance-digest', {});
        return response.data.data;
    },

    // Convert a service-account-shaped user into a project machine identity (ADR-023).
    // Unless keep_user is set, the source user is suspended.
    async migrateUserToMachine(
        projectId: number,
        body: { username: string; identity_type?: string; name?: string; keep_user?: boolean },
    ): Promise<{ machine_identity: { id: number; name: string } }> {
        const response = await apiClient.post(
            `/api/v1/projects/${projectId}/machine-identities/migrate-from-user`,
            body,
        );
        return response.data.data;
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
