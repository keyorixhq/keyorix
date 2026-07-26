import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get:    vi.fn(),
        post:   vi.fn(),
        put:    vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { adminApi } from '../admin';

const mock = apiClient as unknown as {
    get:    ReturnType<typeof vi.fn>;
    post:   ReturnType<typeof vi.fn>;
    put:    ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

function ok<T>(data: T) {
    return { data: { data } };
}

beforeEach(() => vi.clearAllMocks());

// ── getStats ──────────────────────────────────────────────────────────────────

describe('adminApi.getStats', () => {
    it('returns the data payload', async () => {
        mock.get.mockResolvedValueOnce(ok({ total_users: 5 }));
        await expect(adminApi.getStats()).resolves.toEqual({ total_users: 5 });
        expect(mock.get).toHaveBeenCalledWith('/api/v1/dashboard/stats');
    });
});

// ── getUsers ──────────────────────────────────────────────────────────────────

describe('adminApi.getUsers', () => {
    it('fetches users with pagination params', async () => {
        mock.get.mockResolvedValueOnce(ok({ items: [], total: 0 }));
        await adminApi.getUsers({ page: 2, pageSize: 25, search: 'bob' });
        expect(mock.get).toHaveBeenCalledWith('/api/v1/users', { params: { page: 2, pageSize: 25, search: 'bob' } });
    });

    it('omits params when called with no arguments', async () => {
        mock.get.mockResolvedValueOnce(ok({ items: [], total: 0 }));
        await adminApi.getUsers();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/users', { params: undefined });
    });
});

// ── getRoles ──────────────────────────────────────────────────────────────────

describe('adminApi.getRoles', () => {
    it('normalizes lowercase field names', async () => {
        mock.get.mockResolvedValueOnce(ok([{ id: 1, name: 'admin', description: 'Admins' }]));
        const roles = await adminApi.getRoles();
        expect(roles).toEqual([{ id: 1, name: 'admin', description: 'Admins' }]);
    });

    it('normalizes uppercase (Go-serialized) field names', async () => {
        mock.get.mockResolvedValueOnce(ok([{ ID: 2, Name: 'viewer', Description: 'Read only' }]));
        const roles = await adminApi.getRoles();
        expect(roles).toEqual([{ id: 2, name: 'viewer', description: 'Read only' }]);
    });

    it('handles {roles: [...]} wrapper shape', async () => {
        mock.get.mockResolvedValueOnce(ok({ roles: [{ id: 3, name: 'editor', description: '' }] }));
        const roles = await adminApi.getRoles();
        expect(roles[0]).toMatchObject({ id: 3, name: 'editor' });
    });

    it('returns [] for null/missing data', async () => {
        mock.get.mockResolvedValueOnce(ok(null));
        await expect(adminApi.getRoles()).resolves.toEqual([]);
    });
});

// ── getUserRoles ──────────────────────────────────────────────────────────────

describe('adminApi.getUserRoles', () => {
    it('fetches roles for a specific user', async () => {
        mock.get.mockResolvedValueOnce(ok([{ id: 1, name: 'admin', description: '' }]));
        const roles = await adminApi.getUserRoles(7);
        expect(mock.get).toHaveBeenCalledWith('/api/v1/users/7/roles');
        expect(roles[0]).toMatchObject({ id: 1, name: 'admin' });
    });

    it('unwraps the {roles: [...]} wrapper shape', async () => {
        mock.get.mockResolvedValueOnce(ok({ roles: [{ id: 2, name: 'editor', description: '' }] }));
        const roles = await adminApi.getUserRoles(7);
        expect(roles[0]).toMatchObject({ id: 2, name: 'editor' });
    });

    it('returns [] for an empty roles list', async () => {
        mock.get.mockResolvedValueOnce(ok({ roles: [] }));
        await expect(adminApi.getUserRoles(7)).resolves.toEqual([]);
    });
});

// ── updateUserRoles ───────────────────────────────────────────────────────────

describe('adminApi.updateUserRoles', () => {
    it('sends role_ids in the request body', async () => {
        mock.put.mockResolvedValueOnce(ok(null));
        await adminApi.updateUserRoles(7, [1, 3]);
        expect(mock.put).toHaveBeenCalledWith('/api/v1/users/7/roles', { role_ids: [1, 3] });
    });
});

// ── getUserPermissions ────────────────────────────────────────────────────────

describe('adminApi.getUserPermissions', () => {
    it('returns flat permissions array', async () => {
        const perms = [{ id: 1, name: 'secrets.read' }];
        mock.get.mockResolvedValueOnce(ok(perms));
        await expect(adminApi.getUserPermissions(7)).resolves.toEqual(perms);
    });

    it('unwraps {permissions: [...]} wrapper', async () => {
        const perms = [{ id: 2, name: 'secrets.write' }];
        mock.get.mockResolvedValueOnce(ok({ permissions: perms }));
        await expect(adminApi.getUserPermissions(7)).resolves.toEqual(perms);
    });

    it('returns [] for null data', async () => {
        mock.get.mockResolvedValueOnce(ok(null));
        await expect(adminApi.getUserPermissions(7)).resolves.toEqual([]);
    });
});

// ── impersonate ───────────────────────────────────────────────────────────────

describe('adminApi.impersonate', () => {
    it('posts to the impersonate endpoint and returns the response', async () => {
        const impersonation = { user_id: 5, username: 'bob', impersonated_by: 1 };
        mock.post.mockResolvedValueOnce(ok(impersonation));
        const result = await adminApi.impersonate(5);
        expect(mock.post).toHaveBeenCalledWith('/api/v1/admin/impersonate', { user_id: 5 });
        expect(result).toMatchObject({ user_id: 5, username: 'bob' });
    });
});

// ── on-demand job triggers ────────────────────────────────────────────────────

describe('adminApi on-demand jobs', () => {
    it('runAnomalyAlerts posts and returns {alerted}', async () => {
        mock.post.mockResolvedValueOnce(ok({ alerted: 3 }));
        await expect(adminApi.runAnomalyAlerts()).resolves.toEqual({ alerted: 3 });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/admin/jobs/anomaly-alerts', {});
    });

    it('runRotationReminders posts and returns {sent}', async () => {
        mock.post.mockResolvedValueOnce(ok({ sent: 7 }));
        await expect(adminApi.runRotationReminders()).resolves.toEqual({ sent: 7 });
    });

    it('runExpiryReminders posts and returns {sent}', async () => {
        mock.post.mockResolvedValueOnce(ok({ sent: 2 }));
        await expect(adminApi.runExpiryReminders()).resolves.toEqual({ sent: 2 });
    });

    it('runComplianceDigest posts and returns {sent}', async () => {
        mock.post.mockResolvedValueOnce(ok({ sent: true }));
        await expect(adminApi.runComplianceDigest()).resolves.toEqual({ sent: true });
    });
});

// ── migrateUserToMachine ──────────────────────────────────────────────────────

describe('adminApi.migrateUserToMachine', () => {
    it('posts to the migrate endpoint and returns machine_identity', async () => {
        const response = { machine_identity: { id: 10, name: 'svc-alice' } };
        mock.post.mockResolvedValueOnce(ok(response));
        const result = await adminApi.migrateUserToMachine(3, { username: 'alice' });
        expect(mock.post).toHaveBeenCalledWith(
            '/api/v1/projects/3/machine-identities/migrate-from-user',
            { username: 'alice' },
        );
        expect(result).toEqual(response);
    });
});

// ── getAuditLogs ──────────────────────────────────────────────────────────────

describe('adminApi.getAuditLogs', () => {
    it('passes filter params to the API', async () => {
        mock.get.mockResolvedValueOnce(ok({ items: [], total: 0 }));
        await adminApi.getAuditLogs({ userId: 1, action: 'login', page: 1 });
        expect(mock.get).toHaveBeenCalledWith(
            '/api/v1/audit/logs',
            { params: { userId: 1, action: 'login', page: 1 } },
        );
    });
});
