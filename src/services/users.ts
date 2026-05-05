import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, User, Recipient } from '../types';
import { API_ENDPOINTS } from '../constants';

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

    async create(body: { username: string; email: string; display_name: string; password: string }): Promise<any> {
        const response = await apiClient.post('/api/v1/users', body);
        return response.data;
    },

    async update(id: number, body: object): Promise<any> {
        const response = await apiClient.put(`/api/v1/users/${id}`, body);
        return response.data;
    },

    async delete(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/users/${id}`);
    },
};
