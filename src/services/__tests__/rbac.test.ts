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
import { rbacApi } from '../rbac';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
    mocked.post.mockResolvedValue({ data: { data: {} } });
});

describe('rbacApi.assignRoleToGroup', () => {
    it('omits expires_at for a permanent grant', async () => {
        await rbacApi.assignRoleToGroup(7, 3);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/groups/7/roles', { role_id: 3 });
    });

    it('sends expires_at for a time-bound (JIT) grant', async () => {
        const iso = '2026-07-01T00:00:00.000Z';
        await rbacApi.assignRoleToGroup(7, 3, iso);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/groups/7/roles', {
            role_id: 3,
            expires_at: iso,
        });
    });
});

describe('rbacApi.getGroupSharedSecrets', () => {
    it('normalizes the server SecretNode rows (PascalCase) to id/name/type', async () => {
        mocked.get.mockResolvedValue({
            data: { data: { secrets: [{ ID: 1, Name: 'alpha', Type: 'password' }, { ID: 2, Name: 'beta', Type: 'token' }] } },
        });
        const out = await rbacApi.getGroupSharedSecrets(7);
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/groups/7/shared-secrets');
        expect(out).toEqual([
            { id: 1, name: 'alpha', type: 'password' },
            { id: 2, name: 'beta', type: 'token' },
        ]);
    });

    it('returns an empty array when there are no shared secrets', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: [] } } });
        expect(await rbacApi.getGroupSharedSecrets(7)).toEqual([]);
    });
});
