import { apiClient } from './client';

// Self-service account API (My Account page). All endpoints are scoped to the
// authenticated user — see the Go backend's /api/v1/auth/* self-service routes.

export interface AccountProfile {
    id: number;
    username: string;
    email: string;
    display_name: string;
    is_active: boolean;
    created_at?: string;
    last_login_at?: string | null;
}

export interface AccountSession {
    id: number;
    user_agent: string;
    ip_address: string;
    created_at: string;
    expires_at: string | null;
    last_seen_at: string | null;
    current: boolean;
}

function toArray<T>(data: unknown): T[] {
    return Array.isArray(data) ? (data as T[]) : [];
}

export const accountApi = {
    async updateProfile(body: { display_name: string; email: string }): Promise<AccountProfile> {
        const response = await apiClient.put('/api/v1/auth/profile', body);
        return response.data.data as AccountProfile;
    },

    async changePassword(body: { current_password: string; new_password: string }): Promise<void> {
        await apiClient.post('/api/v1/auth/change-password', body);
    },

    async listSessions(): Promise<AccountSession[]> {
        const response = await apiClient.get('/api/v1/auth/sessions');
        return toArray<AccountSession>(response.data.data);
    },

    async revokeSession(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/auth/sessions/${id}`);
    },
};
