import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, ShareRecord, ShareFormData } from '../types';
import { API_ENDPOINTS } from '../constants';

export const sharingApi = {
    async list(params?: {
        page?: number;
        pageSize?: number;
        secretId?: number;
        recipientType?: 'user' | 'group';
    }): Promise<PaginatedResponse<ShareRecord>> {
        const response = await apiClient.get<ApiResponse<PaginatedResponse<ShareRecord>>>(
            API_ENDPOINTS.SHARING.LIST,
            { params }
        );
        return response.data.data;
    },

    async get(id: number): Promise<ShareRecord> {
        const response = await apiClient.get<ApiResponse<ShareRecord>>(API_ENDPOINTS.SHARING.GET(id));
        return response.data.data;
    },

    async create(data: ShareFormData & { secretId: number }): Promise<ShareRecord> {
        const response = await apiClient.post<ApiResponse<ShareRecord>>(
            API_ENDPOINTS.SHARING.CREATE(data.secretId),
            {
                recipient_id: data.recipientId,
                is_group: data.recipientType === 'group',
                permission: data.permission,
            }
        );
        return response.data.data;
    },

    async update(id: number, data: Partial<ShareFormData>): Promise<ShareRecord> {
        const response = await apiClient.put<ApiResponse<ShareRecord>>(
            API_ENDPOINTS.SHARING.UPDATE(id),
            data
        );
        return response.data.data;
    },

    async delete(id: number): Promise<void> {
        await apiClient.delete(API_ENDPOINTS.SHARING.DELETE(id));
    },

    async selfRemove(id: number): Promise<void> {
        await apiClient.post(API_ENDPOINTS.SHARING.SELF_REMOVE(id));
    },
};
