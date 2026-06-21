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
