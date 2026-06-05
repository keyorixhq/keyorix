import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, User, Recipient } from '../types';
import { API_ENDPOINTS } from '../constants';

// SetupLinkResult mirrors the backend ADR-028 credential-delivery outcome. In
// out-of-band mode `link_for_admin` is set for the admin to relay; in SMTP mode the
// link is sent and `delivered` is true.
export interface SetupLinkResult {
    email: string;
    channel: string; // smtp | out_of_band | log
    delivered: boolean;
    link_for_admin?: string;
}

// CreateUserResult is the POST /users response. The setup-link path nests the created
// user under `user` and the delivery outcome under `setup_link`; the classic path
// returns the user fields directly. Callers only read `setup_link`, so the rest stays
// loose.
export interface CreateUserResult {
    setup_link?: SetupLinkResult;
    [key: string]: any;
}

export const usersApi = {
    async list(params?: {
        page?: number;
        pageSize?: number;
        search?: string;
    }): Promise<PaginatedResponse<User>> {
        const response = await apiClient.get<ApiResponse<PaginatedResponse<User>>>(
            API_ENDPOINTS.USERS.LIST,
            { params }
        );
        return response.data.data;
    },

    async get(id: number): Promise<User> {
        const response = await apiClient.get<ApiResponse<User>>(API_ENDPOINTS.USERS.GET(id));
        return response.data.data;
    },

    async search(query: string): Promise<Recipient[]> {
        const response = await apiClient.get(API_ENDPOINTS.USERS.SEARCH, { params: { q: query } });
        const users = response.data.data?.users ?? [];
        return users.map((u: any) => ({
            id: u.id,
            name: u.username,
            type: 'user' as const,
            email: u.email,
        }));
    },

    async create(body: {
        username: string;
        email: string;
        display_name: string;
        // Optional when deliver_setup_link is set: the user sets their own password
        // via the setup link (ADR-028) instead of the admin choosing one.
        password?: string;
        deliver_setup_link?: boolean;
    }): Promise<CreateUserResult> {
        const response = await apiClient.post('/api/v1/users', body);
        return response.data?.data ?? response.data;
    },

    async update(id: number, body: object): Promise<any> {
        const response = await apiClient.put(`/api/v1/users/${id}`, body);
        return response.data;
    },

    async delete(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/users/${id}`);
    },

    async restore(id: number): Promise<void> {
        await apiClient.post(`/api/v1/users/${id}/restore`);
    },
};
