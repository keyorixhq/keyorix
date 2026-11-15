import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/dynamicSecrets', () => ({
    dynamicSecretsApi: {
        list: vi.fn(),
        listLeases: vi.fn(),
        create: vi.fn(),
        classify: vi.fn(),
        issue: vi.fn(),
        revokeLease: vi.fn(),
        revokeAll: vi.fn(),
        listRefusedAdminDsn: vi.fn(),
        updateAdminDsn: vi.fn(),
    },
}));

import { dynamicSecretsApi } from '../../../services/dynamicSecrets';
import {
    DYNAMIC_SECRET_KEYS,
    useRefusedAdminDsn,
    useUpdateDynamicConfigAdminDSN,
    useDynamicConfigs,
    useDynamicLeases,
    useCreateDynamicConfig,
    useClassifyDynamicConfig,
    useIssueLease,
    useRevokeLease,
    useRevokeAllLeases,
} from '../api';

const mock = dynamicSecretsApi as unknown as {
    list: ReturnType<typeof vi.fn>;
    listLeases: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
    classify: ReturnType<typeof vi.fn>;
    issue: ReturnType<typeof vi.fn>;
    revokeLease: ReturnType<typeof vi.fn>;
    revokeAll: ReturnType<typeof vi.fn>;
    listRefusedAdminDsn: ReturnType<typeof vi.fn>;
    updateAdminDsn: ReturnType<typeof vi.fn>;
};

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => vi.clearAllMocks());

describe('useDynamicConfigs', () => {
    it('fetches configs scoped to a project and environment', async () => {
        mock.list.mockResolvedValueOnce([{ id: 1 }]);
        const { result } = renderHook(() => useDynamicConfigs(5, 2), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.list).toHaveBeenCalledWith(5, 2);
        expect(result.current.data).toEqual([{ id: 1 }]);
    });

    it('does not fetch when projectId is falsy', async () => {
        renderHook(() => useDynamicConfigs(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.list).not.toHaveBeenCalled();
    });
});

describe('useDynamicLeases', () => {
    it('fetches leases for a config', async () => {
        mock.listLeases.mockResolvedValueOnce([{ id: 'lease-1' }]);
        const { result } = renderHook(() => useDynamicLeases(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.listLeases).toHaveBeenCalledWith(3);
    });

    it('does not fetch when configId is falsy', async () => {
        renderHook(() => useDynamicLeases(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.listLeases).not.toHaveBeenCalled();
    });

    it('does not fetch when enabled=false, even with a valid configId', async () => {
        renderHook(() => useDynamicLeases(3, false), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.listLeases).not.toHaveBeenCalled();
    });
});

describe('useCreateDynamicConfig', () => {
    it('creates a config and invalidates the dynamic-secrets query', async () => {
        const payload = { project_id: 5, environment_id: 2 } as any;
        mock.create.mockResolvedValueOnce({ id: 1 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useCreateDynamicConfig(), { wrapper });

        act(() => {
            result.current.mutate(payload);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.create).toHaveBeenCalledWith(payload);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: DYNAMIC_SECRET_KEYS.all });
    });
});

describe('useClassifyDynamicConfig', () => {
    it('classifies a config and invalidates the dynamic-secrets query', async () => {
        mock.classify.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useClassifyDynamicConfig(), { wrapper });

        act(() => {
            result.current.mutate({ id: 1, classification: 'confidential' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.classify).toHaveBeenCalledWith(1, 'confidential');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: DYNAMIC_SECRET_KEYS.all });
    });
});

describe('useIssueLease', () => {
    it('issues a lease with an optional TTL and invalidates that config’s leases', async () => {
        mock.issue.mockResolvedValueOnce({ id: 'lease-1' });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useIssueLease(3), { wrapper });

        act(() => {
            result.current.mutate(3600);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.issue).toHaveBeenCalledWith(3, 3600);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: DYNAMIC_SECRET_KEYS.leases(3) });
    });

    // G28: the response is a one-time credential (often a plaintext password).
    // Without a short gcTime override, react-query's MutationCache would retain
    // it for the default 5 minutes after the last observer unmounts.
    it('does not retain the issued credential in the MutationCache once the component unmounts', async () => {
        mock.issue.mockResolvedValueOnce({ leaseId: 'lease-1', password: 'idle-plaintext-password' });
        const { wrapper, queryClient } = createWrapper();
        const { result, unmount } = renderHook(() => useIssueLease(3), { wrapper });

        act(() => {
            result.current.mutate(undefined);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(queryClient.getMutationCache().getAll()).toHaveLength(1);

        unmount();
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });
});

describe('useRevokeLease', () => {
    it('revokes a lease by id and invalidates that config’s leases', async () => {
        mock.revokeLease.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRevokeLease(3), { wrapper });

        act(() => {
            result.current.mutate('lease-1');
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.revokeLease).toHaveBeenCalledWith('lease-1');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: DYNAMIC_SECRET_KEYS.leases(3) });
    });
});

describe('useRevokeAllLeases', () => {
    it('revokes all leases for a config and invalidates that config’s leases', async () => {
        mock.revokeAll.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRevokeAllLeases(3), { wrapper });

        act(() => {
            result.current.mutate();
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.revokeAll).toHaveBeenCalledWith(3);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: DYNAMIC_SECRET_KEYS.leases(3) });
    });
});

const SECRET_DSN = 'postgres://admin:hunter2-s3cret@db.internal:5432/app';

describe('useRefusedAdminDsn', () => {
    it('fetches the project report under a key made of ids only', async () => {
        mock.listRefusedAdminDsn.mockResolvedValueOnce({ configs: [{ id: 7 }], unreadable: 0 });
        const { wrapper, queryClient } = createWrapper();
        const { result } = renderHook(() => useRefusedAdminDsn(5), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.listRefusedAdminDsn).toHaveBeenCalledWith(5);
        expect(
            queryClient
                .getQueryCache()
                .getAll()
                .map((q) => q.queryKey)
        ).toEqual([DYNAMIC_SECRET_KEYS.refusedAdminDsn(5)]);
    });

    it('does not fetch without a project, or when disabled (roles that cannot manage configs)', async () => {
        renderHook(() => useRefusedAdminDsn(0), { wrapper: createWrapper().wrapper });
        renderHook(() => useRefusedAdminDsn(5, false), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.listRefusedAdminDsn).not.toHaveBeenCalled();
    });

    it('does not retry a refusal (a 403 must not thrash)', async () => {
        mock.listRefusedAdminDsn.mockRejectedValue(new Error('403'));
        const { result } = renderHook(() => useRefusedAdminDsn(5), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isError).toBe(true));
        expect(mock.listRefusedAdminDsn).toHaveBeenCalledTimes(1);
    });
});

describe('useUpdateDynamicConfigAdminDSN', () => {
    it('replaces the DSN and invalidates every dynamic-secrets query (configs list and refused report)', async () => {
        mock.updateAdminDsn.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useUpdateDynamicConfigAdminDSN(), { wrapper });

        act(() => {
            result.current.mutate({ id: 7, adminDsn: SECRET_DSN });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.updateAdminDsn).toHaveBeenCalledWith(7, SECRET_DSN);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: DYNAMIC_SECRET_KEYS.all });
        expect(DYNAMIC_SECRET_KEYS.list(5, 2).slice(0, DYNAMIC_SECRET_KEYS.all.length)).toEqual(
            DYNAMIC_SECRET_KEYS.all
        );
        expect(DYNAMIC_SECRET_KEYS.refusedAdminDsn(5).slice(0, DYNAMIC_SECRET_KEYS.all.length)).toEqual(
            DYNAMIC_SECRET_KEYS.all
        );
    });

    it('surfaces a failure and does not invalidate', async () => {
        const failure = new Error('refused');
        mock.updateAdminDsn.mockRejectedValueOnce(failure);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useUpdateDynamicConfigAdminDSN(), { wrapper });

        act(() => {
            result.current.mutate({ id: 7, adminDsn: SECRET_DSN });
        });
        await waitFor(() => expect(result.current.isError).toBe(true));

        expect(result.current.error).toBe(failure);
        expect(invalidateSpy).not.toHaveBeenCalled();
    });

    it('never puts the DSN in a query cache key, and drops the mutation (variables included) on unmount', async () => {
        mock.updateAdminDsn.mockResolvedValueOnce(undefined);
        mock.list.mockResolvedValue([]);
        mock.listRefusedAdminDsn.mockResolvedValue({ configs: [], unreadable: 0 });
        const { wrapper, queryClient } = createWrapper();
        const { result, unmount } = renderHook(
            () => ({
                configs: useDynamicConfigs(5, 2),
                refused: useRefusedAdminDsn(5),
                update: useUpdateDynamicConfigAdminDSN(),
            }),
            { wrapper }
        );
        await waitFor(() => expect(result.current.refused.isSuccess).toBe(true));

        act(() => {
            result.current.update.mutate({ id: 7, adminDsn: SECRET_DSN });
        });
        await waitFor(() => expect(result.current.update.isSuccess).toBe(true));

        const keys = JSON.stringify(
            queryClient
                .getQueryCache()
                .getAll()
                .map((q) => q.queryKey)
        );
        expect(keys).not.toContain('hunter2');
        expect(keys).not.toContain('postgres://');

        unmount();
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });
});

describe('useUpdateDynamicConfigAdminDSN forbidden', () => {
    it('invalidates the lists on forbidden (which covers a config that is gone), but not for other failures', async () => {
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useUpdateDynamicConfigAdminDSN(), { wrapper });

        mock.updateAdminDsn.mockRejectedValueOnce(Object.assign(new Error('refused'), { kind: 'refused' }));
        act(() => {
            result.current.mutate({ id: 7, adminDsn: SECRET_DSN });
        });
        await waitFor(() => expect(result.current.isError).toBe(true));
        expect(invalidateSpy).not.toHaveBeenCalled();

        mock.updateAdminDsn.mockRejectedValueOnce(Object.assign(new Error('gone'), { kind: 'forbidden' }));
        act(() => {
            result.current.mutate({ id: 7, adminDsn: SECRET_DSN });
        });
        await waitFor(() => expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: DYNAMIC_SECRET_KEYS.all }));
    });
});
