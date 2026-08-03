import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        patch: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { dynamicSecretsApi } from '../dynamicSecrets';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    patch: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

// ── list ─────────────────────────────────────────────────────────────────────

describe('dynamicSecretsApi.list', () => {
    it('GETs configs with only project_id when environmentId is omitted, and normalizes snake_case rows', async () => {
        const row = {
            id: 1,
            name: 'prod-pg',
            project_id: 3,
            environment_id: 5,
            backend_type: 'postgres',
            creation_template: 'CREATE ROLE {{name}}',
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86400,
            classification: 'confidential',
            created_by: 'alice',
            created_at: '2026-01-01T00:00:00Z',
        };
        mocked.get.mockResolvedValueOnce({ data: { data: [row] } });

        const result = await dynamicSecretsApi.list(3);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/dynamic-secrets/configs', {
            params: { project_id: 3 },
        });
        expect(result).toEqual([
            {
                id: 1,
                name: 'prod-pg',
                projectId: 3,
                environmentId: 5,
                backendType: 'postgres',
                creationTemplate: 'CREATE ROLE {{name}}',
                defaultTtlSeconds: 3600,
                maxTtlSeconds: 86400,
                classification: 'confidential',
                createdBy: 'alice',
                createdAt: '2026-01-01T00:00:00Z',
            },
        ]);
    });

    it('adds environment_id to params when provided', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: [] } });

        await dynamicSecretsApi.list(3, 5);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/dynamic-secrets/configs', {
            params: { project_id: 3, environment_id: 5 },
        });
    });

    it('normalizes PascalCase rows and falls back to defaults for missing fields', async () => {
        mocked.get.mockResolvedValueOnce({
            data: { data: [{ ID: 2, ProjectID: 4, EnvironmentID: 6, BackendType: 'mysql' }] },
        });

        const result = await dynamicSecretsApi.list(4);

        expect(result[0]).toEqual({
            id: 2,
            name: '',
            projectId: 4,
            environmentId: 6,
            backendType: 'mysql',
            creationTemplate: '',
            defaultTtlSeconds: 0,
            maxTtlSeconds: 0,
            classification: '',
            createdBy: '',
            createdAt: undefined,
        });
    });

    it('falls back to the un-enveloped response body when resp.data.data is absent', async () => {
        mocked.get.mockResolvedValueOnce({ data: [{ id: 9, name: 'fallback' }] });

        const result = await dynamicSecretsApi.list(1);

        expect(result[0]).toMatchObject({ id: 9, name: 'fallback' });
    });

    it('returns [] when the unwrapped payload is not an array', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: {} } });

        await expect(dynamicSecretsApi.list(1)).resolves.toEqual([]);
    });

    it('defaults id to 0 when a config row has neither id nor ID', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: [{}] } });

        const result = await dynamicSecretsApi.list(1);

        expect(result[0]).toMatchObject({ id: 0 });
    });

    it('returns [] when the response has no .data at all (unwrap falls through to undefined)', async () => {
        mocked.get.mockResolvedValueOnce({});

        await expect(dynamicSecretsApi.list(1)).resolves.toEqual([]);
    });
});

// ── create ───────────────────────────────────────────────────────────────────

describe('dynamicSecretsApi.create', () => {
    it('POSTs the full payload in snake_case and returns the normalized created config', async () => {
        mocked.post.mockResolvedValueOnce({
            data: {
                data: {
                    id: 10,
                    name: 'staging-mysql',
                    project_id: 1,
                    environment_id: 2,
                    backend_type: 'mysql',
                    creation_template: 'CREATE USER {{name}}',
                    default_ttl_seconds: 900,
                    max_ttl_seconds: 3600,
                    classification: 'internal',
                    created_by: 'bob',
                },
            },
        });

        const result = await dynamicSecretsApi.create({
            name: 'staging-mysql',
            projectId: 1,
            environmentId: 2,
            backendType: 'mysql',
            adminDsn: 'mysql://admin:secret@host/db',
            creationTemplate: 'CREATE USER {{name}}',
            defaultTtlSeconds: 900,
            maxTtlSeconds: 3600,
            classification: 'internal',
        });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/dynamic-secrets/configs', {
            name: 'staging-mysql',
            project_id: 1,
            environment_id: 2,
            backend_type: 'mysql',
            admin_dsn: 'mysql://admin:secret@host/db',
            creation_template: 'CREATE USER {{name}}',
            default_ttl_seconds: 900,
            max_ttl_seconds: 3600,
            classification: 'internal',
        });
        expect(result).toMatchObject({
            id: 10,
            name: 'staging-mysql',
            projectId: 1,
            environmentId: 2,
            backendType: 'mysql',
            classification: 'internal',
            createdBy: 'bob',
        });
    });
});

// ── classify ─────────────────────────────────────────────────────────────────

describe('dynamicSecretsApi.classify', () => {
    it('PATCHes the classification sub-route and returns the normalized config', async () => {
        mocked.patch.mockResolvedValueOnce({
            data: { data: { id: 7, classification: 'restricted' } },
        });

        const result = await dynamicSecretsApi.classify(7, 'restricted');

        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/dynamic-secrets/configs/7/classification', {
            classification: 'restricted',
        });
        expect(result).toMatchObject({ id: 7, classification: 'restricted' });
    });
});

// ── issue ────────────────────────────────────────────────────────────────────

describe('dynamicSecretsApi.issue', () => {
    it('POSTs the given ttlSeconds and returns a normalized DB credential (snake_case)', async () => {
        mocked.post.mockResolvedValueOnce({
            data: {
                data: {
                    lease_id: 'lease-1',
                    username: 'app_user_abc',
                    password: 'hunter2',
                    expires_at: '2026-01-01T01:00:00Z',
                },
            },
        });

        const result = await dynamicSecretsApi.issue(3, 1800);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/dynamic-secrets/configs/3/issue', {
            ttl_seconds: 1800,
        });
        expect(result).toEqual({
            leaseId: 'lease-1',
            username: 'app_user_abc',
            password: 'hunter2',
            fields: undefined,
            expiresAt: '2026-01-01T01:00:00Z',
        });
    });

    it('defaults ttl_seconds to 0 when ttlSeconds is omitted', async () => {
        mocked.post.mockResolvedValueOnce({ data: { data: {} } });

        await dynamicSecretsApi.issue(3);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/dynamic-secrets/configs/3/issue', {
            ttl_seconds: 0,
        });
    });

    it('normalizes PascalCase cloud-backend credentials, including the fields map', async () => {
        mocked.post.mockResolvedValueOnce({
            data: {
                data: {
                    LeaseID: 'lease-2',
                    Fields: { access_key_id: 'AKIA...', secret_access_key: 'shh' },
                    ExpiresAt: '2026-01-01T02:00:00Z',
                },
            },
        });

        const result = await dynamicSecretsApi.issue(9, 3600);

        expect(result).toEqual({
            leaseId: 'lease-2',
            username: '',
            password: '',
            fields: { access_key_id: 'AKIA...', secret_access_key: 'shh' },
            expiresAt: '2026-01-01T02:00:00Z',
        });
    });
});

// ── listLeases ───────────────────────────────────────────────────────────────

describe('dynamicSecretsApi.listLeases', () => {
    it('GETs leases for a config and normalizes snake_case rows', async () => {
        const row = {
            lease_id: 'lease-3',
            config_id: 4,
            role_name: 'app_user_xyz',
            status: 'active',
            issued_at: '2026-01-01T00:00:00Z',
            expires_at: '2026-01-01T01:00:00Z',
        };
        mocked.get.mockResolvedValueOnce({ data: { data: [row] } });

        const result = await dynamicSecretsApi.listLeases(4);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/dynamic-secrets/configs/4/leases');
        expect(result).toEqual([
            {
                leaseId: 'lease-3',
                configId: 4,
                roleName: 'app_user_xyz',
                status: 'active',
                revokeReason: undefined,
                revokeError: undefined,
                issuedAt: '2026-01-01T00:00:00Z',
                expiresAt: '2026-01-01T01:00:00Z',
                revokedAt: undefined,
            },
        ]);
    });

    it('normalizes PascalCase revoked leases, including revoke reason/error', async () => {
        mocked.get.mockResolvedValueOnce({
            data: {
                data: [
                    {
                        LeaseID: 'lease-4',
                        ConfigID: 4,
                        RoleName: 'app_user_bad',
                        Status: 'revoke_failed',
                        RevokeReason: 'manual',
                        RevokeError: 'connection refused',
                        RevokedAt: '2026-01-01T03:00:00Z',
                    },
                ],
            },
        });

        const result = await dynamicSecretsApi.listLeases(4);

        expect(result[0]).toEqual({
            leaseId: 'lease-4',
            configId: 4,
            roleName: 'app_user_bad',
            status: 'revoke_failed',
            revokeReason: 'manual',
            revokeError: 'connection refused',
            issuedAt: undefined,
            expiresAt: undefined,
            revokedAt: '2026-01-01T03:00:00Z',
        });
    });

    it('returns [] when the config has no leases', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: {} } });

        await expect(dynamicSecretsApi.listLeases(4)).resolves.toEqual([]);
    });

    it('defaults all lease fields when a row has neither snake_case nor PascalCase keys', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: [{}] } });

        const result = await dynamicSecretsApi.listLeases(4);

        expect(result[0]).toMatchObject({ leaseId: '', configId: 0, roleName: '', status: 'active' });
    });

    it('returns [] when the response has no .data at all (unwrap falls through to undefined)', async () => {
        mocked.get.mockResolvedValueOnce({});

        await expect(dynamicSecretsApi.listLeases(4)).resolves.toEqual([]);
    });
});

// ── revokeLease ──────────────────────────────────────────────────────────────

describe('dynamicSecretsApi.revokeLease', () => {
    it('POSTs to the lease revoke sub-route with an empty body', async () => {
        mocked.post.mockResolvedValueOnce({ data: {} });

        await dynamicSecretsApi.revokeLease('lease-1');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/dynamic-secrets/leases/lease-1/revoke', {});
    });
});

// ── revokeAll ────────────────────────────────────────────────────────────────

describe('dynamicSecretsApi.revokeAll', () => {
    it('POSTs to the revoke-all sub-route and returns the revoked/failed counts', async () => {
        mocked.post.mockResolvedValueOnce({ data: { data: { revoked: 4, failed: 1 } } });

        const result = await dynamicSecretsApi.revokeAll(4);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/dynamic-secrets/configs/4/revoke-all', {});
        expect(result).toEqual({ revoked: 4, failed: 1 });
    });

    it('defaults revoked/failed to 0 when the response body is empty', async () => {
        mocked.post.mockResolvedValueOnce({ data: {} });

        const result = await dynamicSecretsApi.revokeAll(4);

        expect(result).toEqual({ revoked: 0, failed: 0 });
    });

    it('defaults revoked/failed to 0 when the response has no .data at all (unwrap falls through to undefined)', async () => {
        mocked.post.mockResolvedValueOnce({});

        const result = await dynamicSecretsApi.revokeAll(4);

        expect(result).toEqual({ revoked: 0, failed: 0 });
    });
});
