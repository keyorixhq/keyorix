import { apiClient } from './client';

// ADR-035 dynamic secrets: an operator registers a target database (a
// DynamicSecretConfig, project+environment scoped); callers issue short-lived
// leases that mint a role on the target; an auto-revoke sweep drops them at expiry.
// The admin DSN and each issued credential are encrypted server-side and never
// returned. Routes live under /api/v1/dynamic-secrets.
//
// The handler emits snake_case JSON; normalizers also tolerate PascalCase so the
// UI keeps working regardless.

export type DynamicBackend = 'postgres' | 'mysql' | 'mongodb' | 'redis';
export type LeaseStatus = 'active' | 'revoked' | 'expired' | 'revoke_failed';

export const DYNAMIC_BACKENDS: DynamicBackend[] = ['postgres', 'mysql', 'mongodb', 'redis'];

export interface DynamicSecretConfig {
    id: number;
    name: string;
    projectId: number;
    environmentId: number;
    backendType: DynamicBackend;
    creationTemplate: string;
    defaultTtlSeconds: number;
    maxTtlSeconds: number;
    classification: string;
    createdBy: string;
    createdAt?: string;
}

export interface DynamicSecretLease {
    leaseId: string;
    configId: number;
    roleName: string;
    status: LeaseStatus;
    revokeReason?: string;
    revokeError?: string;
    issuedAt?: string;
    expiresAt?: string;
    revokedAt?: string;
}

// The one-time credential returned on issue — shown once, never retrievable again.
export interface IssuedCredential {
    leaseId: string;
    username: string;
    password: string;
    expiresAt?: string;
}

export interface CreateDynamicConfigPayload {
    name: string;
    projectId: number;
    environmentId: number;
    backendType: DynamicBackend;
    adminDsn: string;
    creationTemplate: string;
    defaultTtlSeconds: number;
    maxTtlSeconds: number;
    classification: string;
}

const normalizeConfig = (c: any): DynamicSecretConfig => ({
    id: c.id ?? c.ID ?? 0,
    name: c.name ?? c.Name ?? '',
    projectId: c.project_id ?? c.ProjectID ?? c.projectId ?? 0,
    environmentId: c.environment_id ?? c.EnvironmentID ?? c.environmentId ?? 0,
    backendType: (c.backend_type ?? c.BackendType ?? c.backendType ?? 'postgres') as DynamicBackend,
    creationTemplate: c.creation_template ?? c.CreationTemplate ?? c.creationTemplate ?? '',
    defaultTtlSeconds: c.default_ttl_seconds ?? c.DefaultTTLSeconds ?? c.defaultTtlSeconds ?? 0,
    maxTtlSeconds: c.max_ttl_seconds ?? c.MaxTTLSeconds ?? c.maxTtlSeconds ?? 0,
    classification: c.classification ?? c.Classification ?? '',
    createdBy: c.created_by ?? c.CreatedBy ?? c.createdBy ?? '',
    createdAt: c.created_at ?? c.CreatedAt ?? c.createdAt ?? undefined,
});

const normalizeLease = (l: any): DynamicSecretLease => ({
    leaseId: l.lease_id ?? l.LeaseID ?? l.leaseId ?? '',
    configId: l.config_id ?? l.ConfigID ?? l.configId ?? 0,
    roleName: l.role_name ?? l.RoleName ?? l.roleName ?? '',
    status: (l.status ?? l.Status ?? 'active') as LeaseStatus,
    revokeReason: l.revoke_reason ?? l.RevokeReason ?? undefined,
    revokeError: l.revoke_error ?? l.RevokeError ?? undefined,
    issuedAt: l.issued_at ?? l.IssuedAt ?? undefined,
    expiresAt: l.expires_at ?? l.ExpiresAt ?? undefined,
    revokedAt: l.revoked_at ?? l.RevokedAt ?? undefined,
});

const unwrap = (resp: any) => resp.data?.data ?? resp.data;

export const dynamicSecretsApi = {
    async list(projectId: number, environmentId?: number): Promise<DynamicSecretConfig[]> {
        const params: Record<string, number> = { project_id: projectId };
        if (environmentId) params.environment_id = environmentId;
        const resp = await apiClient.get('/api/v1/dynamic-secrets/configs', { params });
        const rows = unwrap(resp) ?? [];
        return (Array.isArray(rows) ? rows : []).map(normalizeConfig);
    },

    async create(payload: CreateDynamicConfigPayload): Promise<DynamicSecretConfig> {
        const resp = await apiClient.post('/api/v1/dynamic-secrets/configs', {
            name: payload.name,
            project_id: payload.projectId,
            environment_id: payload.environmentId,
            backend_type: payload.backendType,
            admin_dsn: payload.adminDsn,
            creation_template: payload.creationTemplate,
            default_ttl_seconds: payload.defaultTtlSeconds,
            max_ttl_seconds: payload.maxTtlSeconds,
            classification: payload.classification,
        });
        return normalizeConfig(unwrap(resp));
    },

    async classify(id: number, classification: string): Promise<DynamicSecretConfig> {
        const resp = await apiClient.patch(`/api/v1/dynamic-secrets/configs/${id}/classification`, {
            classification,
        });
        return normalizeConfig(unwrap(resp));
    },

    async issue(id: number, ttlSeconds?: number): Promise<IssuedCredential> {
        const resp = await apiClient.post(`/api/v1/dynamic-secrets/configs/${id}/issue`, {
            ttl_seconds: ttlSeconds ?? 0,
        });
        const c = unwrap(resp);
        return {
            leaseId: c.lease_id ?? c.LeaseID ?? '',
            username: c.username ?? c.Username ?? '',
            password: c.password ?? c.Password ?? '',
            expiresAt: c.expires_at ?? c.ExpiresAt ?? undefined,
        };
    },

    async listLeases(configId: number): Promise<DynamicSecretLease[]> {
        const resp = await apiClient.get(`/api/v1/dynamic-secrets/configs/${configId}/leases`);
        const rows = unwrap(resp) ?? [];
        return (Array.isArray(rows) ? rows : []).map(normalizeLease);
    },

    async revokeLease(leaseId: string): Promise<void> {
        await apiClient.post(`/api/v1/dynamic-secrets/leases/${leaseId}/revoke`, {});
    },

    async revokeAll(configId: number): Promise<{ revoked: number; failed: number }> {
        const resp = await apiClient.post(`/api/v1/dynamic-secrets/configs/${configId}/revoke-all`, {});
        const c = unwrap(resp) ?? {};
        return { revoked: c.revoked ?? 0, failed: c.failed ?? 0 };
    },
};
