import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// useImpersonateUser reads useAuthStore.getState().checkAuth() directly (not via
// the hook's return value), so the mock needs a static getState() too. vi.hoisted()
// runs before the vi.mock() factory so this spy is in scope there.
const { checkAuth } = vi.hoisted(() => ({
    checkAuth: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../services/admin', () => ({
    adminApi: {
        getStats: vi.fn(),
        getUsers: vi.fn(),
        getRoles: vi.fn(),
        getAuditLogs: vi.fn(),
        getUserRoles: vi.fn(),
        updateUserRoles: vi.fn(),
        getUserPermissions: vi.fn(),
        runAnomalyAlerts: vi.fn(),
        runRotationReminders: vi.fn(),
        runExpiryReminders: vi.fn(),
        runComplianceDigest: vi.fn(),
        migrateUserToMachine: vi.fn(),
        impersonate: vi.fn(),
    },
}));

vi.mock('../../../services/users', () => ({
    usersApi: {
        list: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        restore: vi.fn(),
        suspend: vi.fn(),
        reactivate: vi.fn(),
        unlock: vi.fn(),
        requirePasswordReset: vi.fn(),
        revokeSessions: vi.fn(),
        resendSetupLink: vi.fn(),
        get: vi.fn(),
        getMemberships: vi.fn(),
        getStale: vi.fn(),
    },
}));

vi.mock('../../../services/client', () => ({
    apiClient: { get: vi.fn() },
}));

vi.mock('../../../store/authStore', () => ({
    useAuthStore: { getState: () => ({ checkAuth }) },
}));

import { adminApi } from '../../../services/admin';
import { usersApi } from '../../../services/users';
import { apiClient } from '../../../services/client';
import { queryKeys } from '../../../lib/queryClient';
import {
    useAdminStats,
    useAdminUsers,
    useAdminRoles,
    useAdminAuditLogs,
    useAdminUserList,
    useAdminCreateUser,
    useAdminUpdateUser,
    useAdminDeleteUser,
    useAdminRestoreUser,
    useSuspendUser,
    useReactivateUser,
    useUnlockUser,
    useRequirePasswordReset,
    useRevokeSessions,
    useResendSetupLink,
    useUserDetail,
    useUserMemberships,
    useStaleAccounts,
    useStalePATs,
    useMachineIdentitiesAuditReport,
    useStaleMachineTokens,
    useDeploymentHygiene,
    useDeploymentNameConformance,
    useUserRoles,
    useUserPermissions,
    useRunAnomalyAlerts,
    useRunRotationReminders,
    useRunExpiryReminders,
    useRunComplianceDigest,
    useMigrateUserToMachine,
    useUpdateUserRoles,
    useImpersonateUser,
} from '../api';

const admin = adminApi as unknown as Record<string, ReturnType<typeof vi.fn>>;
const users = usersApi as unknown as Record<string, ReturnType<typeof vi.fn>>;
const client = apiClient as unknown as { get: ReturnType<typeof vi.fn> };

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => {
    vi.clearAllMocks();
    checkAuth.mockResolvedValue(undefined);
});

// ── Admin stats / roles / audit ─────────────────────────────────────────────

describe('useAdminStats', () => {
    it('fetches admin stats and caches under the admin stats key', async () => {
        admin.getStats.mockResolvedValueOnce({ totalUsers: 5 });
        const { wrapper, queryClient } = createWrapper();
        const { result } = renderHook(() => useAdminStats(), { wrapper });

        expect(result.current.isLoading).toBe(true);
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.getStats).toHaveBeenCalledTimes(1);
        expect(result.current.data).toEqual({ totalUsers: 5 });
        expect(queryClient.getQueryData(queryKeys.admin.stats())).toEqual({ totalUsers: 5 });
    });
});

describe('useAdminUsers', () => {
    it('fetches users with the given params under the admin users key', async () => {
        admin.getUsers.mockResolvedValueOnce({ items: [], total: 0 });
        const params = { page: 2, pageSize: 10, search: 'bob' };
        const { wrapper, queryClient } = createWrapper();
        const { result } = renderHook(() => useAdminUsers(params), { wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.getUsers).toHaveBeenCalledWith(params);
        expect(queryClient.getQueryData(queryKeys.admin.users(params))).toEqual({ items: [], total: 0 });
    });

    it('fetches with no params when called bare', async () => {
        admin.getUsers.mockResolvedValueOnce({ items: [], total: 0 });
        const { result } = renderHook(() => useAdminUsers(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(admin.getUsers).toHaveBeenCalledWith(undefined);
    });
});

describe('useAdminRoles', () => {
    it('fetches roles under the admin roles key', async () => {
        admin.getRoles.mockResolvedValueOnce([{ id: 1, name: 'admin', description: '' }]);
        const { wrapper, queryClient } = createWrapper();
        const { result } = renderHook(() => useAdminRoles(), { wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.getRoles).toHaveBeenCalledTimes(1);
        expect(queryClient.getQueryData(queryKeys.admin.roles())).toEqual([{ id: 1, name: 'admin', description: '' }]);
    });
});

describe('useAdminAuditLogs', () => {
    it('fetches audit logs with the given params under the admin audit key', async () => {
        admin.getAuditLogs.mockResolvedValueOnce({ items: [], total: 0 });
        const params = { page: 1, userId: 7, action: 'login' };
        const { wrapper, queryClient } = createWrapper();
        const { result } = renderHook(() => useAdminAuditLogs(params), { wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.getAuditLogs).toHaveBeenCalledWith(params);
        expect(queryClient.getQueryData(queryKeys.admin.audit(params))).toEqual({ items: [], total: 0 });
    });
});

// ── User CRUD (used by AdminPage) ───────────────────────────────────────────

describe('useAdminUserList', () => {
    it('builds list params from page/search/pageSize', async () => {
        users.list.mockResolvedValueOnce({ items: [], total: 0 });
        const { result } = renderHook(() => useAdminUserList({ page: 1, search: '', pageSize: 20 }), {
            wrapper: createWrapper().wrapper,
        });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(users.list).toHaveBeenCalledWith({ page: 1, page_size: 20 });
    });

    it('adds search, include_deleted, and filter=inactive only when truthy', async () => {
        users.list.mockResolvedValueOnce({ items: [], total: 0 });
        const { result } = renderHook(
            () =>
                useAdminUserList({
                    page: 2,
                    search: 'bob',
                    pageSize: 10,
                    includeDeleted: true,
                    inactive: true,
                }),
            { wrapper: createWrapper().wrapper }
        );

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(users.list).toHaveBeenCalledWith({
            page: 2,
            page_size: 10,
            search: 'bob',
            include_deleted: true,
            filter: 'inactive',
        });
    });

    // BUG (documented, not fixed — out of scope for this coverage-only PR):
    // the queryKey is ['admin-users', page, search, includeDeleted, inactive] — it
    // does not include pageSize, even though pageSize is sent in the request params.
    // So changing only the page size (e.g. a "rows per page" selector left on the
    // same page/search/filters) does not change the query key, and react-query
    // serves the previously cached page instead of refetching at the new page size.
    it('does not refetch when only pageSize changes (query key omits pageSize)', async () => {
        users.list.mockResolvedValue({ items: [], total: 0 });
        const { wrapper } = createWrapper();
        const { result, rerender } = renderHook(
            ({ pageSize }: { pageSize: number }) => useAdminUserList({ page: 1, search: '', pageSize }),
            { wrapper, initialProps: { pageSize: 10 } }
        );

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(users.list).toHaveBeenCalledTimes(1);

        rerender({ pageSize: 25 });
        await act(async () => {});

        expect(users.list).toHaveBeenCalledTimes(1); // unchanged — the key didn't change
    });
});

describe('useAdminCreateUser', () => {
    it('creates a user and invalidates the admin-users list', async () => {
        users.create.mockResolvedValueOnce({ id: 1 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useAdminCreateUser(), { wrapper });
        const body = { username: 'bob', email: 'bob@x.com', display_name: 'Bob' };

        act(() => {
            result.current.mutate(body);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.create).toHaveBeenCalledWith(body);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
    });
});

describe('useAdminUpdateUser', () => {
    it('updates a user and invalidates the admin-users list', async () => {
        users.update.mockResolvedValueOnce({});
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useAdminUpdateUser(), { wrapper });

        act(() => {
            result.current.mutate({ id: 3, body: { display_name: 'New Name' } });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.update).toHaveBeenCalledWith(3, { display_name: 'New Name' });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
    });
});

describe('useAdminDeleteUser', () => {
    it('deletes a user and invalidates the admin-users list', async () => {
        users.delete.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useAdminDeleteUser(), { wrapper });

        act(() => {
            result.current.mutate(3);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.delete).toHaveBeenCalledWith(3);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
    });
});

describe('useAdminRestoreUser', () => {
    it('restores a user and invalidates the admin-users list', async () => {
        users.restore.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useAdminRestoreUser(), { wrapper });

        act(() => {
            result.current.mutate(3);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.restore).toHaveBeenCalledWith(3);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
    });
});

// ── ADR-025 account lifecycle ───────────────────────────────────────────────

describe('useSuspendUser', () => {
    it('suspends a user and invalidates admin-users, that user detail, and stale-accounts', async () => {
        users.suspend.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useSuspendUser(), { wrapper });

        act(() => {
            result.current.mutate(9);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.suspend).toHaveBeenCalledWith(9);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['user-detail', 9] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['stale-accounts'] });
    });
});

describe('useReactivateUser', () => {
    it('reactivates a user and invalidates admin-users, that user detail, and stale-accounts', async () => {
        users.reactivate.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useReactivateUser(), { wrapper });

        act(() => {
            result.current.mutate(9);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.reactivate).toHaveBeenCalledWith(9);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['user-detail', 9] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['stale-accounts'] });
    });
});

describe('useUnlockUser', () => {
    it('clears a lockout and invalidates admin-users, that user detail, and stale-accounts', async () => {
        users.unlock.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useUnlockUser(), { wrapper });

        act(() => {
            result.current.mutate(9);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.unlock).toHaveBeenCalledWith(9);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['user-detail', 9] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['stale-accounts'] });
    });
});

describe('useRequirePasswordReset', () => {
    it('flags a required password reset and invalidates admin-users, that user detail, and stale-accounts', async () => {
        users.requirePasswordReset.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRequirePasswordReset(), { wrapper });

        act(() => {
            result.current.mutate(9);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.requirePasswordReset).toHaveBeenCalledWith(9);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['user-detail', 9] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['stale-accounts'] });
    });
});

describe('useRevokeSessions', () => {
    it('force-logs-out a user and invalidates admin-users, that user detail, and stale-accounts', async () => {
        users.revokeSessions.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRevokeSessions(), { wrapper });

        act(() => {
            result.current.mutate(9);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.revokeSessions).toHaveBeenCalledWith(9);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['user-detail', 9] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['stale-accounts'] });
    });
});

describe('useResendSetupLink', () => {
    it('resends the setup link, returns the delivery outcome, and invalidates stale-accounts', async () => {
        users.resendSetupLink.mockResolvedValueOnce({ email: 'a@b.com', channel: 'smtp', delivered: true });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useResendSetupLink(), { wrapper });

        act(() => {
            result.current.mutate(4);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(users.resendSetupLink).toHaveBeenCalledWith(4);
        expect(result.current.data).toEqual({ email: 'a@b.com', channel: 'smtp', delivered: true });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['stale-accounts'] });
    });
});

describe('useUserDetail', () => {
    it('fetches user detail when userId is set', async () => {
        users.get.mockResolvedValueOnce({ id: 5, username: 'bob' });
        const { result } = renderHook(() => useUserDetail(5), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(users.get).toHaveBeenCalledWith(5);
    });

    it('does not fetch when userId is null', async () => {
        renderHook(() => useUserDetail(null), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(users.get).not.toHaveBeenCalled();
    });
});

describe('useUserMemberships', () => {
    it('fetches memberships when userId is set', async () => {
        users.getMemberships.mockResolvedValueOnce([
            { project_id: 1, project_name: 'P', role: 'viewer', state: 'active' },
        ]);
        const { result } = renderHook(() => useUserMemberships(5), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(users.getMemberships).toHaveBeenCalledWith(5);
    });

    it('does not fetch when userId is null', async () => {
        renderHook(() => useUserMemberships(null), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(users.getMemberships).not.toHaveBeenCalled();
    });
});

describe('useStaleAccounts', () => {
    it('fetches pending_first_login accounts stale by the default 7 days', async () => {
        users.getStale.mockResolvedValueOnce([{ id: 1 }]);
        const { result } = renderHook(() => useStaleAccounts(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(users.getStale).toHaveBeenCalledWith({ state: 'pending_first_login', days: 7 });
    });

    it('honors a custom days threshold', async () => {
        users.getStale.mockResolvedValueOnce([]);
        const { result } = renderHook(() => useStaleAccounts(14), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(users.getStale).toHaveBeenCalledWith({ state: 'pending_first_login', days: 14 });
    });
});

// ── Direct apiClient hygiene/inventory queries ──────────────────────────────

describe('useStalePATs', () => {
    it('fetches and unwraps the token list', async () => {
        client.get.mockResolvedValueOnce({ data: { data: { tokens: [{ id: 1 }] } } });
        const { result } = renderHook(() => useStalePATs(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(client.get).toHaveBeenCalledWith('/api/v1/pat-hygiene', { params: { days: 90 } });
        expect(result.current.data).toEqual([{ id: 1 }]);
    });

    it('falls back to an empty array and honors a custom days param', async () => {
        client.get.mockResolvedValueOnce({ data: {} });
        const { result } = renderHook(() => useStalePATs(30), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(client.get).toHaveBeenCalledWith('/api/v1/pat-hygiene', { params: { days: 30 } });
        expect(result.current.data).toEqual([]);
    });
});

describe('useMachineIdentitiesAuditReport', () => {
    it('unwraps the report from res.data.data', async () => {
        const report = { generated_at: 't', total_count: 1, stale_count: 0, revoked_count: 0, machines: [] };
        client.get.mockResolvedValueOnce({ data: { data: report } });
        const { result } = renderHook(() => useMachineIdentitiesAuditReport(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(client.get).toHaveBeenCalledWith('/api/v1/machine-identities/audit');
        expect(result.current.data).toEqual(report);
    });

    it('falls back to the empty report when the response is unshaped', async () => {
        client.get.mockResolvedValueOnce({ data: null });
        const { result } = renderHook(() => useMachineIdentitiesAuditReport(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({
            generated_at: '',
            total_count: 0,
            stale_count: 0,
            revoked_count: 0,
            machines: [],
        });
    });
});

describe('useStaleMachineTokens', () => {
    it('fetches and unwraps the token list with the default 90-day window', async () => {
        client.get.mockResolvedValueOnce({ data: { data: { tokens: [{ id: 2 }] } } });
        const { result } = renderHook(() => useStaleMachineTokens(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(client.get).toHaveBeenCalledWith('/api/v1/machine-token-hygiene', { params: { days: 90 } });
        expect(result.current.data).toEqual([{ id: 2 }]);
    });

    it('falls back to an empty array and honors a custom days param', async () => {
        client.get.mockResolvedValueOnce({ data: {} });
        const { result } = renderHook(() => useStaleMachineTokens(45), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(client.get).toHaveBeenCalledWith('/api/v1/machine-token-hygiene', { params: { days: 45 } });
        expect(result.current.data).toEqual([]);
    });
});

describe('useDeploymentHygiene', () => {
    it('unwraps the rollup from res.data.data', async () => {
        const hygiene = {
            totals: {
                orphaned_secrets: 1,
                unused_secrets: 0,
                expiring_secrets: 0,
                stale_machine_identities: 0,
                rotation_overdue: 0,
            },
            projects: [],
        };
        client.get.mockResolvedValueOnce({ data: { data: hygiene } });
        const { result } = renderHook(() => useDeploymentHygiene(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(client.get).toHaveBeenCalledWith('/api/v1/hygiene');
        expect(result.current.data).toEqual(hygiene);
    });

    it('falls back to zeroed totals and no projects when unshaped', async () => {
        client.get.mockResolvedValueOnce({ data: {} });
        const { result } = renderHook(() => useDeploymentHygiene(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({
            totals: {
                orphaned_secrets: 0,
                unused_secrets: 0,
                expiring_secrets: 0,
                stale_machine_identities: 0,
                rotation_overdue: 0,
            },
            projects: [],
        });
    });
});

describe('useDeploymentNameConformance', () => {
    it('unwraps the report from res.data.data', async () => {
        const report = {
            policy_enabled: true,
            total_secrets: 10,
            violations: [{ id: 1, name: 'bad', type: 'secret', reason: 'x', project_id: 1, project_name: 'P' }],
        };
        client.get.mockResolvedValueOnce({ data: { data: report } });
        const { result } = renderHook(() => useDeploymentNameConformance(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(client.get).toHaveBeenCalledWith('/api/v1/secrets/name-conformance');
        expect(result.current.data).toEqual(report);
    });

    it('falls back to a disabled policy with no violations when unshaped', async () => {
        client.get.mockResolvedValueOnce({ data: {} });
        const { result } = renderHook(() => useDeploymentNameConformance(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({ policy_enabled: false, total_secrets: 0, violations: [] });
    });
});

// ── Per-user roles / permissions ────────────────────────────────────────────

describe('useUserRoles', () => {
    it('fetches roles for a user when userId is set', async () => {
        admin.getUserRoles.mockResolvedValueOnce([{ id: 1, name: 'admin' }]);
        const { result } = renderHook(() => useUserRoles(5), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(admin.getUserRoles).toHaveBeenCalledWith(5);
    });

    it('does not fetch when userId is null', async () => {
        renderHook(() => useUserRoles(null), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(admin.getUserRoles).not.toHaveBeenCalled();
    });
});

describe('useUserPermissions', () => {
    it('fetches permissions for a user when userId is set', async () => {
        admin.getUserPermissions.mockResolvedValueOnce([{ resource: 'secrets', action: 'read' }]);
        const { result } = renderHook(() => useUserPermissions(5), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(admin.getUserPermissions).toHaveBeenCalledWith(5);
    });

    it('does not fetch when userId is null', async () => {
        renderHook(() => useUserPermissions(null), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(admin.getUserPermissions).not.toHaveBeenCalled();
    });
});

// ── Maintenance job triggers ─────────────────────────────────────────────────

describe('useRunAnomalyAlerts', () => {
    it('triggers the anomaly-alerts job and returns the alerted count', async () => {
        admin.runAnomalyAlerts.mockResolvedValueOnce({ alerted: 3 });
        const { result } = renderHook(() => useRunAnomalyAlerts(), { wrapper: createWrapper().wrapper });

        act(() => {
            result.current.mutate();
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.runAnomalyAlerts).toHaveBeenCalledTimes(1);
        expect(result.current.data).toEqual({ alerted: 3 });
    });
});

describe('useRunRotationReminders', () => {
    it('triggers the rotation-reminders job and returns the sent count', async () => {
        admin.runRotationReminders.mockResolvedValueOnce({ sent: 2 });
        const { result } = renderHook(() => useRunRotationReminders(), { wrapper: createWrapper().wrapper });

        act(() => {
            result.current.mutate();
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.runRotationReminders).toHaveBeenCalledTimes(1);
        expect(result.current.data).toEqual({ sent: 2 });
    });
});

describe('useRunExpiryReminders', () => {
    it('triggers the expiry-reminders job and returns the sent count', async () => {
        admin.runExpiryReminders.mockResolvedValueOnce({ sent: 4 });
        const { result } = renderHook(() => useRunExpiryReminders(), { wrapper: createWrapper().wrapper });

        act(() => {
            result.current.mutate();
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.runExpiryReminders).toHaveBeenCalledTimes(1);
        expect(result.current.data).toEqual({ sent: 4 });
    });
});

describe('useRunComplianceDigest', () => {
    it('triggers the compliance-digest job and reports whether it was sent', async () => {
        admin.runComplianceDigest.mockResolvedValueOnce({ sent: false });
        const { result } = renderHook(() => useRunComplianceDigest(), { wrapper: createWrapper().wrapper });

        act(() => {
            result.current.mutate();
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.runComplianceDigest).toHaveBeenCalledTimes(1);
        expect(result.current.data).toEqual({ sent: false });
    });
});

// ── Machine-identity migration / role updates / impersonation ──────────────

describe('useMigrateUserToMachine', () => {
    it('migrates a user to a machine identity and invalidates that user detail plus the admin-users list', async () => {
        admin.migrateUserToMachine.mockResolvedValueOnce({ machine_identity: { id: 1, name: 'svc' } });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useMigrateUserToMachine(), { wrapper });
        const vars = { projectId: 2, userId: 9, body: { username: 'svc-bot' } };

        act(() => {
            result.current.mutate(vars);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.migrateUserToMachine).toHaveBeenCalledWith(2, { username: 'svc-bot' });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['user-detail', 9] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
    });
});

describe('useUpdateUserRoles', () => {
    it('updates roles and invalidates that user’s roles plus the admin-users list', async () => {
        admin.updateUserRoles.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useUpdateUserRoles(), { wrapper });

        act(() => {
            result.current.mutate({ userId: 9, roleIds: [1, 2] });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.updateUserRoles).toHaveBeenCalledWith(9, [1, 2]);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['user-roles', 9] });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['admin-users'] });
    });
});

describe('useImpersonateUser', () => {
    it('impersonates the target user then re-syncs auth via checkAuth', async () => {
        admin.impersonate.mockResolvedValueOnce({ user_id: 9, username: 'bob', impersonated_by: 1 });
        const { result } = renderHook(() => useImpersonateUser(), { wrapper: createWrapper().wrapper });

        act(() => {
            result.current.mutate({ id: 9, username: 'bob' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(admin.impersonate).toHaveBeenCalledWith(9);
        expect(checkAuth).toHaveBeenCalledTimes(1);
    });
});
