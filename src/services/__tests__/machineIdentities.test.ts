import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { machineIdentitiesApi } from '../machineIdentities';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
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
});
