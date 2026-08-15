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
    },
}));

import { dynamicSecretsApi } from '../../../services/dynamicSecrets';
import {
    DYNAMIC_SECRET_KEYS,
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
