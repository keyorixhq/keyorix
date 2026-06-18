import { apiClient } from './client';
import { ApiResponse, PaginatedResponse, Secret, SecretFormData, SecretUsageStat, UnusedSecretStat, SecretRiskScore, SecretAccessor, SecretAccessLogEntry, SecretAuditEntry } from '../types';
import { API_ENDPOINTS } from '../constants';

export const secretsApi = {
    async list(params?: {
        page?: number;
        pageSize?: number;
        search?: string;
        type?: string;
        classification?: string;
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
            lastRotatedAt: s.LastRotatedAt ?? null,
            classification: s.Classification ?? s.classification ?? '',
            status: s.Status ?? s.status ?? 'active',
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

    // rollback restores the secret to a prior version's value as a new version.
    async rollback(id: number, version: number) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/rollback`, { version });
        return response.data;
    },

    // transferOwnership hands the secret to another user (the new owner). The server
    // requires the caller to be the current owner (or the owner to be gone).
    async transferOwnership(id: number, newOwnerId: number) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/transfer-ownership`, { new_owner_id: newOwnerId });
        return response.data;
    },

    // suspend freezes value reads of the secret (incident response); resume restores.
    async suspend(id: number, reason?: string) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/suspend`, reason ? { reason } : {});
        return response.data;
    },
    async resume(id: number) {
        const response = await apiClient.post(`/api/v1/secrets/${id}/resume`, {});
        return response.data;
    },

    // accessList returns the users who can read the secret (owner + direct + group
    // shares, members expanded) — GET /secrets/{id}/access.
    async accessList(id: number): Promise<SecretAccessor[]> {
        const response = await apiClient.get(`/api/v1/secrets/${id}/access`);
        return response.data.data?.accessors ?? [];
    },

    // accessLog returns the secret's recent reads (who/when/from where) —
    // GET /secrets/{id}/access-log?days=N.
    async accessLog(id: number, days = 30): Promise<SecretAccessLogEntry[]> {
        const response = await apiClient.get(`/api/v1/secrets/${id}/access-log`, { params: { days } });
        return response.data.data?.access_log ?? [];
    },

    // auditTrail returns the secret's lifecycle events (created/rotated/suspended/
    // shared/…) newest-first — GET /secrets/{id}/audit?limit=N. Never a value.
    async auditTrail(id: number, limit = 50): Promise<SecretAuditEntry[]> {
        const response = await apiClient.get(`/api/v1/secrets/${id}/audit`, { params: { limit } });
        return response.data.data?.audit ?? [];
    },

    // tags returns the secret's tags — GET /secrets/{id}/tags.
    async tags(id: number): Promise<string[]> {
        const response = await apiClient.get(`/api/v1/secrets/${id}/tags`);
        return response.data.data?.tags ?? [];
    },

    // setTags replaces the secret's tag set — PUT /secrets/{id}/tags. Returns the
    // stored (server-normalized) tags.
    async setTags(id: number, tags: string[]): Promise<string[]> {
        const response = await apiClient.put(`/api/v1/secrets/${id}/tags`, { tags });
        return response.data.data?.tags ?? [];
    },

    async mostAccessed(params?: { days?: number; limit?: number; projectId?: number }): Promise<SecretUsageStat[]> {
        const query: Record<string, unknown> = {};
        if (params?.days) query.days = params.days;
        if (params?.limit) query.limit = params.limit;
        if (params?.projectId) query.project_id = params.projectId;
        const response = await apiClient.get('/api/v1/secrets/usage/most-accessed', { params: query });
        return (response.data.data?.secrets ?? []) as SecretUsageStat[];
    },

    async unused(params?: { days?: number; projectId?: number }): Promise<UnusedSecretStat[]> {
        const query: Record<string, unknown> = {};
        if (params?.days) query.days = params.days;
        if (params?.projectId) query.project_id = params.projectId;
        const response = await apiClient.get('/api/v1/secrets/usage/unused', { params: query });
        return (response.data.data?.secrets ?? []) as UnusedSecretStat[];
    },

    async risk(id: number): Promise<SecretRiskScore> {
        const response = await apiClient.get<ApiResponse<SecretRiskScore>>(`/api/v1/secrets/${id}/risk`);
        return response.data.data;
    },

    // classify sets (or clears, with '') the secret's data-classification label
    // (ISO 27001 A.5.12) via PATCH /secrets/{id}/classification.
    async classify(id: number, classification: string): Promise<void> {
        await apiClient.patch(API_ENDPOINTS.SECRETS.CLASSIFY(id), { classification });
    },

    // setAutoRotate configures automated rotation (ADR-046/047) via
    // PATCH /secrets/{id}/auto-rotate: enable/disable, the generated-value shape
    // (length/charset), and an optional backend + ref to rotate an upstream credential.
    async setAutoRotate(
        id: number,
        opts: { enabled: boolean; length?: number; charset?: string; backend?: string; ref?: string },
    ): Promise<void> {
        await apiClient.patch(`/api/v1/secrets/${id}/auto-rotate`, {
            enabled: opts.enabled,
            length: opts.length ?? 0,
            charset: opts.charset ?? '',
            backend: opts.backend ?? '',
            ref: opts.ref ?? '',
        });
    },
};
