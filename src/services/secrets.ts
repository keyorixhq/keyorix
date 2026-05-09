import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, Secret, SecretFormData } from '../types';
import { API_ENDPOINTS } from '../constants';

export const secretsApi = {
    async list(params?: {
        page?: number;
        pageSize?: number;
        search?: string;
        type?: string;
        namespace?: string;
        zone?: string;
        environment?: string;
        environment_id?: number;
        project_id?: number;
        tags?: string[];
    }): Promise<PaginatedResponse<Secret>> {
        const response = await apiClient.get(API_ENDPOINTS.SECRETS.LIST, { params });
        const { secrets, total, page, page_size, total_pages } = response.data.data;
        const mappedSecrets: Secret[] = (secrets ?? []).map((s: any) => ({
            id: s.ID,
            name: s.Name,
            type: s.Type,
            isShared: s.IsShared ?? false,
            shareCount: s.share_count ?? 0,
            lastModified: s.UpdatedAt ?? s.CreatedAt ?? '',
            owner: s.CreatedBy ?? '',
            namespace: s.namespace_name ?? s.namespace ?? 'default',
            zone: s.zone_name ?? s.zone ?? '',
            environment: s.environment_name ?? s.environment ?? 'production',
            tags: [],
            permissions: [],
            metadata: {},
            Expiration: s.Expiration ?? null,
        }));
        return {
            data: mappedSecrets,
            total: total ?? 0,
            page: page ?? 1,
            pageSize: page_size ?? (params?.pageSize ?? 20),
            totalPages: total_pages ?? 1,
        };
    },

    async get(id: number): Promise<Secret> {
        const response = await apiClient.get<ApiResponse<Secret>>(API_ENDPOINTS.SECRETS.GET(id));
        return response.data.data;
    },

    async create(data: any): Promise<Secret> {
        const response = await apiClient.post<ApiResponse<Secret>>(API_ENDPOINTS.SECRETS.CREATE, data);
        return response.data.data;
    },

    async update(id: number, data: Partial<SecretFormData>): Promise<Secret> {
        const response = await apiClient.put<ApiResponse<Secret>>(API_ENDPOINTS.SECRETS.UPDATE(id), data);
        return response.data.data;
    },

    async delete(id: number): Promise<void> {
        await apiClient.delete(API_ENDPOINTS.SECRETS.DELETE(id));
    },

    async getVersions(id: number): Promise<{ EncryptedValue: string; VersionNumber: number; CreatedAt: string }[]> {
        const response = await apiClient.get(API_ENDPOINTS.SECRETS.VERSIONS(id));
        return response.data.data.versions ?? [];
    },

    async rotate(id: number, newValue: string) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/rotate`, { new_value: newValue });
        return response.data;
    },
};
