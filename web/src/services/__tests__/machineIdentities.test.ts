import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        patch: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { machineIdentitiesApi } from '../machineIdentities';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    patch: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

describe('machineIdentitiesApi.list', () => {
    it('unwraps {data:{machine_identities}} and normalizes PascalCase keys', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    machine_identities: [
                        {
                            ID: 5,
                            ProjectID: 3,
                            Name: 'ci-runner',
                            IdentityType: 'ci',
                            State: 'active',
                            Description: 'build pipeline',
                            CreatedBy: 1,
                            CreatedAt: '2026-06-05T00:00:00Z',
                        },
                    ],
                },
            },
        });

        const out = await machineIdentitiesApi.list(3);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/3/machine-identities');
        expect(out).toHaveLength(1);
        expect(out[0]).toMatchObject({
            id: 5,
            projectId: 3,
            name: 'ci-runner',
            identityType: 'ci',
            state: 'active',
            description: 'build pipeline',
            createdBy: 1,
        });
    });

    it('returns [] when the payload has no machine identities', async () => {
        mocked.get.mockResolvedValue({ data: { data: {} } });
        expect(await machineIdentitiesApi.list(1)).toEqual([]);
    });
});

describe('machineIdentitiesApi.create', () => {
    it('posts name + identity_type + description and unwraps {data:{machine_identity}}', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: {
                    machine_identity: { ID: 9, ProjectID: 2, Name: 'k8s-app', IdentityType: 'k8s', State: 'active' },
                },
            },
        });

        const m = await machineIdentitiesApi.create(2, 'k8s-app', 'k8s', 'prod workload');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/2/machine-identities', {
            name: 'k8s-app',
            identity_type: 'k8s',
            description: 'prod workload',
        });
        expect(m).toMatchObject({ id: 9, name: 'k8s-app', identityType: 'k8s' });
    });
});

describe('machineIdentitiesApi.transition', () => {
    it('puts the action on the machine sub-route', async () => {
        mocked.put.mockResolvedValue({
            data: { data: { machine_identity: { ID: 9, State: 'suspended', IdentityType: 'ci' } } },
        });

        const m = await machineIdentitiesApi.transition(2, 9, 'suspend');

        expect(mocked.put).toHaveBeenCalledWith('/api/v1/projects/2/machine-identities/9', {
            action: 'suspend',
        });
        expect(m.state).toBe('suspended');
    });

    it('falls back to bare data.data when machine_identity is absent', async () => {
        mocked.put.mockResolvedValue({ data: { data: { ID: 9, State: 'active' } } });

        const m = await machineIdentitiesApi.transition(2, 9, 'activate');

        expect(m.state).toBe('active');
    });

    it('falls back to bare response.data when data.data is absent', async () => {
        mocked.put.mockResolvedValue({ data: { ID: 9, State: 'revoked' } });

        const m = await machineIdentitiesApi.transition(2, 9, 'revoke');

        expect(m.state).toBe('revoked');
    });
});

describe('normalizeMachineIdentity defaults', () => {
    it('defaults every field on a sparse row (no PascalCase/snake_case keys at all)', async () => {
        mocked.get.mockResolvedValue({ data: { data: { machine_identities: [{}] } } });

        const out = await machineIdentitiesApi.list(1);

        expect(out[0]).toMatchObject({
            name: '',
            identityType: 'other',
            state: 'pending',
            description: '',
            createdBy: 0,
            classification: '',
            createdAt: undefined,
            updatedAt: undefined,
            lastSeenAt: undefined,
            revokedAt: undefined,
        });
    });

    it('normalizes snake_case fields when PascalCase is absent', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    machine_identities: [
                        {
                            id: 3,
                            project_id: 2,
                            identity_type: 'service',
                            state: 'suspended',
                            created_by: 5,
                            created_at: '2026-01-01T00:00:00Z',
                            updated_at: '2026-01-02T00:00:00Z',
                            last_seen_at: '2026-01-03T00:00:00Z',
                            revoked_at: '2026-01-04T00:00:00Z',
                        },
                    ],
                },
            },
        });

        const out = await machineIdentitiesApi.list(2);

        expect(out[0]).toMatchObject({
            id: 3,
            projectId: 2,
            identityType: 'service',
            state: 'suspended',
            createdBy: 5,
            createdAt: '2026-01-01T00:00:00Z',
            updatedAt: '2026-01-02T00:00:00Z',
            lastSeenAt: '2026-01-03T00:00:00Z',
            revokedAt: '2026-01-04T00:00:00Z',
        });
    });
});

describe('machineIdentitiesApi.create fallback shapes', () => {
    it('falls back to data.data when machine_identity is absent', async () => {
        mocked.post.mockResolvedValue({ data: { data: { ID: 4, Name: 'svc', State: 'pending' } } });

        const m = await machineIdentitiesApi.create(1, 'svc', 'service');

        expect(m).toMatchObject({ id: 4, name: 'svc' });
    });

    it('falls back to bare response.data when data.data is absent', async () => {
        mocked.post.mockResolvedValue({ data: { ID: 5, Name: 'bare', State: 'active' } });

        const m = await machineIdentitiesApi.create(1, 'bare', 'other');

        expect(m).toMatchObject({ id: 5, name: 'bare' });
    });
});

describe('machineIdentitiesApi.classify', () => {
    it('patches the classification sub-route and normalizes the returned identity', async () => {
        mocked.patch.mockResolvedValue({
            data: { data: { machine_identity: { ID: 9, Name: 'ci-runner', Classification: 'confidential' } } },
        });

        const m = await machineIdentitiesApi.classify(2, 9, 'confidential');

        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/projects/2/machine-identities/9/classification', {
            classification: 'confidential',
        });
        expect(m).toMatchObject({ id: 9, name: 'ci-runner', classification: 'confidential' });
    });

    it('falls back to bare response.data when neither wrapper is present', async () => {
        mocked.patch.mockResolvedValue({ data: { ID: 9, Classification: '' } });

        const m = await machineIdentitiesApi.classify(2, 9, '');

        expect(m.classification).toBe('');
    });
});

describe('machineIdentitiesApi.listTokens', () => {
    it('unwraps {data:{tokens}} and normalizes PascalCase fields', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    tokens: [
                        {
                            id: 1,
                            Name: 'ci-token',
                            TokenPrefix: 'kx_ci_',
                            LastUsedAt: '2026-01-01T00:00:00Z',
                            ExpiresAt: '2026-06-01T00:00:00Z',
                            Revoked: true,
                            Classification: 'internal',
                            CreatedAt: '2025-01-01T00:00:00Z',
                        },
                    ],
                },
            },
        });

        const out = await machineIdentitiesApi.listTokens(2, 9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/2/machine-identities/9/tokens');
        expect(out[0]).toEqual({
            id: 1,
            name: 'ci-token',
            prefix: 'kx_ci_',
            lastUsedAt: '2026-01-01T00:00:00Z',
            expiresAt: '2026-06-01T00:00:00Z',
            revoked: true,
            classification: 'internal',
            createdAt: '2025-01-01T00:00:00Z',
        });
    });

    it('normalizes lowercase/snake_case fields and defaults a sparse token', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    tokens: [{ name: 'lower', prefix: 'kx_a_', last_used_at: '2026-02-01T00:00:00Z' }, {}],
                },
            },
        });

        const out = await machineIdentitiesApi.listTokens(2, 9);

        expect(out[0]).toMatchObject({ id: 0, name: 'lower', prefix: 'kx_a_', lastUsedAt: '2026-02-01T00:00:00Z' });
        expect(out[1]).toEqual({
            id: 0,
            name: '',
            prefix: '',
            lastUsedAt: undefined,
            expiresAt: undefined,
            revoked: false,
            classification: '',
            createdAt: undefined,
        });
    });

    it('falls back to bare data.tokens, and to [] when neither wrapper is present', async () => {
        mocked.get.mockResolvedValueOnce({ data: { tokens: [{ name: 'bare' }] } });
        const bare = await machineIdentitiesApi.listTokens(2, 9);
        expect(bare[0]).toMatchObject({ name: 'bare' });

        mocked.get.mockResolvedValueOnce({ data: {} });
        await expect(machineIdentitiesApi.listTokens(2, 9)).resolves.toEqual([]);
    });
});

describe('machineIdentitiesApi.issueToken', () => {
    it('posts opts with defaults applied and unwraps the one-time token from data.data', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: {
                    token: 'kx_machine_raw_abc',
                    id: 7,
                    prefix: 'kx_a_',
                    expires_at: '2026-06-01T00:00:00Z',
                    classification: 'internal',
                },
            },
        });

        const issued = await machineIdentitiesApi.issueToken(2, 9, { name: 'ci token' });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/2/machine-identities/9/tokens', {
            name: 'ci token',
            expires_in_days: 0,
            classification: '',
        });
        expect(issued).toEqual({
            token: 'kx_machine_raw_abc',
            id: 7,
            prefix: 'kx_a_',
            expiresAt: '2026-06-01T00:00:00Z',
            classification: 'internal',
        });
    });

    it('forwards explicit expiresInDays and classification', async () => {
        mocked.post.mockResolvedValue({ data: { data: { token: 't', id: 1, prefix: 'p' } } });

        await machineIdentitiesApi.issueToken(2, 9, { name: 'n', expiresInDays: 30, classification: 'restricted' });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/2/machine-identities/9/tokens', {
            name: 'n',
            expires_in_days: 30,
            classification: 'restricted',
        });
    });

    it('falls back to bare response.data and defaults every field on an empty payload', async () => {
        mocked.post.mockResolvedValue({ data: {} });

        const issued = await machineIdentitiesApi.issueToken(2, 9, { name: 'n' });

        expect(issued).toEqual({
            token: '',
            id: 0,
            prefix: '',
            expiresAt: undefined,
            classification: '',
        });
    });

    it('normalizes PascalCase id/expiresAt/classification fallbacks', async () => {
        mocked.post.mockResolvedValue({
            data: { data: { token: 't', ID: 3, prefix: 'p', ExpiresAt: '2026-01-01T00:00:00Z', Classification: 'x' } },
        });

        const issued = await machineIdentitiesApi.issueToken(2, 9, { name: 'n' });

        expect(issued).toMatchObject({ id: 3, expiresAt: '2026-01-01T00:00:00Z', classification: 'x' });
    });
});

describe('machineIdentitiesApi.revokeToken', () => {
    it('deletes the token sub-route', async () => {
        mocked.delete.mockResolvedValue({});

        await machineIdentitiesApi.revokeToken(2, 9, 5);

        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/projects/2/machine-identities/9/tokens/5');
    });
});

describe('machineIdentitiesApi.classifyToken', () => {
    it('patches the token classification sub-route', async () => {
        mocked.patch.mockResolvedValue({});

        await machineIdentitiesApi.classifyToken(2, 9, 5, 'confidential');

        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/projects/2/machine-identities/9/tokens/5/classification', {
            classification: 'confidential',
        });
    });
});
