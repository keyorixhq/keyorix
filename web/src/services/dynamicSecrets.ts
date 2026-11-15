import { isAxiosError } from 'axios';
import { apiClient, apiErrorMessage } from './client';

// ADR-035 dynamic secrets: an operator registers a target database (a
// DynamicSecretConfig, project+environment scoped); callers issue short-lived
// leases that mint a role on the target; an auto-revoke sweep drops them at expiry.
// The admin DSN and each issued credential are encrypted server-side and never
// returned. Routes live under /api/v1/dynamic-secrets.
//
// The handler emits snake_case JSON; normalizers also tolerate PascalCase so the
// UI keeps working regardless.

export type DynamicBackend = 'postgres' | 'mysql' | 'mongodb' | 'redis' | 'aws-sts' | 'gcp' | 'azure';
export type LeaseStatus = 'active' | 'revoked' | 'expired' | 'revoke_failed';

export const DYNAMIC_BACKENDS: DynamicBackend[] = ['postgres', 'mysql', 'mongodb', 'redis', 'aws-sts', 'gcp', 'azure'];

// Cloud-IAM backends mint self-expiring tokens (not a DB role): their "admin DSN" is
// a JSON config, the issued credential comes back as `fields`, and the creation
// template is a session policy (aws-sts) or unused (gcp/azure).
export const CLOUD_BACKENDS: DynamicBackend[] = ['aws-sts', 'gcp', 'azure'];

export const isCloudBackend = (b: DynamicBackend): boolean => CLOUD_BACKENDS.includes(b);

// Placeholder JSON config shown in the create form for each cloud backend.
export const CLOUD_CONFIG_PLACEHOLDER: Record<string, string> = {
    'aws-sts': '{"role_arn":"arn:aws:iam::123456789012:role/keyorix-dyn","region":"eu-west-1","duration_seconds":3600}',
    gcp: '{"service_account":"sa@project.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]}',
    azure: '{"scopes":["https://management.azure.com/.default"]}',
};

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
// Database backends populate username/password; cloud-IAM backends populate fields
// (e.g. access_key_id / secret_access_key / session_token, or access_token).
export interface IssuedCredential {
    leaseId: string;
    username: string;
    password: string;
    fields?: Record<string, string>;
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

// A config whose stored admin DSN names a driver option the server has refused since #3952
// (GET .../configs/refused-admin-dsn). It carries option NAMES only, never a DSN or a value.
export interface RefusedAdminDsnConfig {
    id: number;
    name: string;
    projectId: number;
    environmentId: number;
    backendType: string;
    refusedOptions: string[];
    liveLeases: number;
}

export interface RefusedAdminDsnReport {
    configs: RefusedAdminDsnConfig[];
    // Configs whose admin DSN could not be decrypted, so they were not checked.
    unreadable: number;
}

// How PATCH .../configs/{id}/admin-dsn failed (see updateDynamicSecretConfigAdminDSN):
// 400 the server refused the new DSN, 409 live leases and the new DSN names a different host,
// 503 the audit log cannot record the change (nothing changed). Every other 4xx is
// 'forbidden': a caller without admin authority is answered 403 for a config that exists and
// for one that does not, and the UI must not tell the two apart (INV-WEB-06), so both read
// the same fixed text and the server's wording is dropped.
export type AdminDsnErrorKind = 'refused' | 'forbidden' | 'conflict' | 'audit_unavailable' | 'unknown';

export const ADMIN_DSN_FORBIDDEN_MESSAGE = 'You do not have admin authority on this config, or it no longer exists.';

const adminDsnErrorKind = (status: number | undefined): AdminDsnErrorKind => {
    if (status === undefined) return 'unknown';
    if (status === 400) return 'refused';
    if (status === 409) return 'conflict';
    if (status === 503) return 'audit_unavailable';
    if (status >= 400 && status < 500) return 'forbidden';
    return 'unknown';
};

// The only error the admin-DSN update lets out. An AxiosError carries the request body
// (`config.data`), which here IS the DSN, and react-query keeps a failed mutation's error in
// its MutationCache, so the raw error must never leave the service layer: this one holds a
// kind, a status and a message with the DSN scrubbed out of it, nothing else.
export class AdminDsnUpdateError extends Error {
    readonly kind: AdminDsnErrorKind;
    readonly status: number | undefined;

    constructor(kind: AdminDsnErrorKind, status: number | undefined, message: string) {
        super(message);
        this.name = 'AdminDsnUpdateError';
        this.kind = kind;
        this.status = status;
    }
}

const toAdminDsnUpdateError = (error: unknown, adminDsn: string): AdminDsnUpdateError => {
    const status = isAxiosError(error) ? error.response?.status : undefined;
    const kind = adminDsnErrorKind(status);
    if (kind === 'forbidden') return new AdminDsnUpdateError(kind, status, ADMIN_DSN_FORBIDDEN_MESSAGE);
    const message = apiErrorMessage(error, 'Failed to replace the admin DSN.');
    return new AdminDsnUpdateError(kind, status, adminDsn ? message.split(adminDsn).join('[redacted]') : message);
};

const normalizeRefused = (c: any): RefusedAdminDsnConfig => ({
    id: c.id ?? 0,
    name: c.name ?? '',
    projectId: c.project_id ?? 0,
    environmentId: c.environment_id ?? 0,
    backendType: c.backend_type ?? '',
    refusedOptions: Array.isArray(c.refused_options) ? c.refused_options.map(String) : [],
    liveLeases: c.live_leases ?? 0,
});

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

    async listRefusedAdminDsn(projectId: number): Promise<RefusedAdminDsnReport> {
        const resp = await apiClient.get('/api/v1/dynamic-secrets/configs/refused-admin-dsn', {
            params: { project_id: projectId },
        });
        const d = unwrap(resp) ?? {};
        return {
            configs: (Array.isArray(d.configs) ? d.configs : []).map(normalizeRefused),
            unreadable: d.unreadable ?? 0,
        };
    },

    // Replaces the stored admin DSN in place. The response is the sanitized config; it is
    // not returned, since the caller only needs to know it worked.
    async updateAdminDsn(id: number, adminDsn: string): Promise<void> {
        try {
            await apiClient.patch(`/api/v1/dynamic-secrets/configs/${id}/admin-dsn`, { admin_dsn: adminDsn });
        } catch (error) {
            throw toAdminDsnUpdateError(error, adminDsn);
        }
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
            fields: c.fields ?? c.Fields ?? undefined,
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
