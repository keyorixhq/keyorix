import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/machineIdentities', () => ({
    machineIdentitiesApi: {
        list: vi.fn(),
        create: vi.fn(),
        transition: vi.fn(),
        classify: vi.fn(),
        listTokens: vi.fn(),
        issueToken: vi.fn(),
        revokeToken: vi.fn(),
        classifyToken: vi.fn(),
    },
}));

import { machineIdentitiesApi } from '../../../services/machineIdentities';
import {
    MACHINE_IDENTITY_KEYS,
    useMachineIdentities,
    useCreateMachineIdentity,
    useTransitionMachineIdentity,
    useClassifyMachineIdentity,
    useMachineTokens,
    useIssueMachineToken,
    useRevokeMachineToken,
    useClassifyMachineToken,
} from '../api';

const mock = machineIdentitiesApi as unknown as {
    list: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
    transition: ReturnType<typeof vi.fn>;
    classify: ReturnType<typeof vi.fn>;
    listTokens: ReturnType<typeof vi.fn>;
    issueToken: ReturnType<typeof vi.fn>;
    revokeToken: ReturnType<typeof vi.fn>;
    classifyToken: ReturnType<typeof vi.fn>;
};

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => vi.clearAllMocks());

describe('useMachineIdentities', () => {
    it('fetches identities for a project', async () => {
        mock.list.mockResolvedValueOnce([{ id: 1 }]);
        const { result } = renderHook(() => useMachineIdentities(5), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.list).toHaveBeenCalledWith(5);
    });

    it('does not fetch when projectId is falsy', async () => {
        renderHook(() => useMachineIdentities(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.list).not.toHaveBeenCalled();
    });
});

describe('useCreateMachineIdentity', () => {
    it('creates an identity and invalidates that project’s list', async () => {
        mock.create.mockResolvedValueOnce({ id: 1 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useCreateMachineIdentity(5), { wrapper });

        act(() => {
            result.current.mutate({ name: 'svc-alice', identityType: 'service', description: 'CI deploy' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.create).toHaveBeenCalledWith(5, 'svc-alice', 'service', 'CI deploy');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: MACHINE_IDENTITY_KEYS.list(5) });
    });
});

describe('useTransitionMachineIdentity', () => {
    it('transitions an identity and invalidates that project’s list', async () => {
        mock.transition.mockResolvedValueOnce({ id: 1, status: 'suspended' });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useTransitionMachineIdentity(5), { wrapper });

        act(() => {
            result.current.mutate({ machineId: 1, action: 'suspend' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.transition).toHaveBeenCalledWith(5, 1, 'suspend');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: MACHINE_IDENTITY_KEYS.list(5) });
    });
});

describe('useClassifyMachineIdentity', () => {
    it('classifies an identity and invalidates that project’s list', async () => {
        mock.classify.mockResolvedValueOnce({ id: 1 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useClassifyMachineIdentity(5), { wrapper });

        act(() => {
            result.current.mutate({ machineId: 1, classification: 'confidential' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.classify).toHaveBeenCalledWith(5, 1, 'confidential');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: MACHINE_IDENTITY_KEYS.list(5) });
    });
});

describe('useMachineTokens', () => {
    it('fetches tokens for a machine identity', async () => {
        mock.listTokens.mockResolvedValueOnce([{ id: 1 }]);
        const { result } = renderHook(() => useMachineTokens(5, 1), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.listTokens).toHaveBeenCalledWith(5, 1);
    });

    it('does not fetch when projectId or machineId is falsy', async () => {
        renderHook(() => useMachineTokens(0, 1), { wrapper: createWrapper().wrapper });
        renderHook(() => useMachineTokens(5, 0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.listTokens).not.toHaveBeenCalled();
    });

    it('does not fetch when enabled=false', async () => {
        renderHook(() => useMachineTokens(5, 1, false), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.listTokens).not.toHaveBeenCalled();
    });
});

describe('useIssueMachineToken', () => {
    it('issues a token and invalidates that machine’s tokens', async () => {
        mock.issueToken.mockResolvedValueOnce({ id: 1, token: 'tok_abc' });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useIssueMachineToken(5, 1), { wrapper });

        act(() => {
            result.current.mutate({ name: 'ci-token', expiresInDays: 90 });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.issueToken).toHaveBeenCalledWith(5, 1, { name: 'ci-token', expiresInDays: 90 });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: MACHINE_IDENTITY_KEYS.tokens(5, 1) });
    });

    // G28: the response is a one-time bearer token (plaintext). Without a short
    // gcTime override, react-query's MutationCache would retain it for the
    // default 5 minutes after the last observer unmounts.
    it('does not retain the issued token in the MutationCache once the component unmounts', async () => {
        mock.issueToken.mockResolvedValueOnce({ id: 1, token: 'tok_plaintext_abc' });
        const { wrapper, queryClient } = createWrapper();
        const { result, unmount } = renderHook(() => useIssueMachineToken(5, 1), { wrapper });

        act(() => {
            result.current.mutate({ name: 'ci-token' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(queryClient.getMutationCache().getAll()).toHaveLength(1);

        unmount();
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });
});

describe('useRevokeMachineToken', () => {
    it('revokes a token and invalidates that machine’s tokens', async () => {
        mock.revokeToken.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRevokeMachineToken(5, 1), { wrapper });

        act(() => {
            result.current.mutate(9);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.revokeToken).toHaveBeenCalledWith(5, 1, 9);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: MACHINE_IDENTITY_KEYS.tokens(5, 1) });
    });
});

describe('useClassifyMachineToken', () => {
    it('classifies a token and invalidates that machine’s tokens', async () => {
        mock.classifyToken.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useClassifyMachineToken(5, 1), { wrapper });

        act(() => {
            result.current.mutate({ tokenId: 9, classification: 'restricted' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.classifyToken).toHaveBeenCalledWith(5, 1, 9, 'restricted');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: MACHINE_IDENTITY_KEYS.tokens(5, 1) });
    });
});
