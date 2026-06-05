import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../../services/admin';
import { usersApi } from '../../services/users';
import { queryKeys } from '../../lib/queryClient';
import { useAuthStore } from '../../store/authStore';
import type { User } from '../../types';

// ── Admin stats / roles / audit (admin-specific endpoints) ─────────────────

export const useAdminStats = () => {
    return useQuery({
        queryKey: queryKeys.admin.stats(),
        queryFn: () => adminApi.getStats(),
        staleTime: 2 * 60 * 1000,
        refetchInterval: 5 * 60 * 1000,
    });
};

export const useAdminUsers = (params?: {
    page?: number;
    pageSize?: number;
    search?: string;
}) => {
    return useQuery({
        queryKey: queryKeys.admin.users(params),
        queryFn: () => adminApi.getUsers(params),
        enabled: true,
        staleTime: 5 * 60 * 1000,
    });
};

export const useAdminRoles = () => {
    return useQuery({
        queryKey: queryKeys.admin.roles(),
        queryFn: () => adminApi.getRoles(),
        staleTime: 10 * 60 * 1000,
    });
};

export const useAdminAuditLogs = (params?: {
    page?: number;
    pageSize?: number;
    userId?: number;
    action?: string;
    startDate?: string;
    endDate?: string;
}) => {
    return useQuery({
        queryKey: queryKeys.admin.audit(params),
        queryFn: () => adminApi.getAuditLogs(params),
        enabled: true,
        staleTime: 1 * 60 * 1000,
    });
};

// ── User CRUD (used by AdminPage — operates on /api/v1/users) ─────────────

export const useAdminUserList = ({
    page,
    search,
    pageSize,
    includeDeleted,
    inactive,
}: {
    page: number;
    search: string;
    pageSize: number;
    includeDeleted?: boolean;
    inactive?: boolean;
}) => {
    return useQuery({
        queryKey: ['admin-users', page, search, includeDeleted, inactive],
        queryFn: () => {
            const params: Record<string, any> = { page, page_size: pageSize };
            if (search) params.search = search;
            if (includeDeleted) params.include_deleted = true;
            if (inactive) params.filter = 'inactive';
            return usersApi.list(params as any);
        },
        retry: 1,
    });
};

export const useAdminCreateUser = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (body: {
            username: string;
            email: string;
            display_name: string;
            password?: string;
            deliver_setup_link?: boolean;
        }) => usersApi.create(body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin-users'] }),
    });
};

export const useAdminUpdateUser = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, body }: { id: number; body: object }) =>
            usersApi.update(id, body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin-users'] }),
    });
};

export const useAdminDeleteUser = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => usersApi.delete(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin-users'] }),
    });
};

export const useAdminRestoreUser = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => usersApi.restore(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin-users'] }),
    });
};

export const useUserRoles = (userId: number | null) => {
    return useQuery({
        queryKey: ['user-roles', userId],
        queryFn: () => adminApi.getUserRoles(userId!),
        enabled: userId !== null,
    });
};

export const useUpdateUserRoles = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ userId, roleIds }: { userId: number; roleIds: number[] }) =>
            adminApi.updateUserRoles(userId, roleIds),
        onSuccess: (_data, { userId }) => {
            queryClient.invalidateQueries({ queryKey: ['user-roles', userId] });
            queryClient.invalidateQueries({ queryKey: ['admin-users'] });
        },
    });
};

// ── Impersonation ─────────────────────────────────────────────────────────────

// useImpersonateUser starts impersonating a user: it requests an impersonation
// token, swaps the active session to it (stashing the admin's), and refreshes
// the impersonated user's full profile. The caller navigates on success.
export const useImpersonateUser = () =>
    useMutation({
        mutationFn: async (target: { id: number; username: string; display_name?: string }) => {
            const resp = await adminApi.impersonate(target.id);
            const store = useAuthStore.getState();
            const impersonatedUser: User = {
                id: resp.user_id,
                username: resp.username,
                displayName: resp.display_name || resp.username,
                email: '',
                role: 'user',
                roles: [],
                permissions: [],
                preferences: {
                    language: 'en',
                    timezone: 'UTC',
                    theme: 'system',
                    notifications: { email: true, browser: true, sharing: true, security: true },
                },
                lastLogin: new Date().toISOString(),
            };
            store.startImpersonation(resp.token, impersonatedUser);
            // Refresh roles/permissions/email for the impersonated identity.
            await store.checkAuth();
        },
    });
