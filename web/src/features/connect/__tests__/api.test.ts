import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/connect', () => ({
    connectApi: {
        listConnectors: vi.fn(),
        readSecret: vi.fn(),
        listRefGrants: vi.fn(),
        createRefGrant: vi.fn(),
        deleteRefGrant: vi.fn(),
    },
}));

import { connectApi } from '../../../services/connect';
import { useConnectors, useReadFederatedSecret, useRefGrants, useCreateRefGrant, useDeleteRefGrant } from '../api';

const mock = connectApi as unknown as {
    listConnectors: ReturnType<typeof vi.fn>;
    readSecret: ReturnType<typeof vi.fn>;
    listRefGrants: ReturnType<typeof vi.fn>;
    createRefGrant: ReturnType<typeof vi.fn>;
    deleteRefGrant: ReturnType<typeof vi.fn>;
};

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => vi.clearAllMocks());

describe('useConnectors', () => {
    it('fetches the connector list', async () => {
        mock.listConnectors.mockResolvedValueOnce(['vault', 'aws-sm']);
        const { wrapper } = createWrapper();
        const { result } = renderHook(() => useConnectors(), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual(['vault', 'aws-sm']);
    });
});

describe('useReadFederatedSecret', () => {
    it('reads a secret via the connector/ref pair on mutate', async () => {
        const secret = { connector: 'vault', ref: 'db/password', value: 'hunter2' };
        mock.readSecret.mockResolvedValueOnce(secret);
        const { wrapper } = createWrapper();
        const { result } = renderHook(() => useReadFederatedSecret(), { wrapper });

        act(() => {
            result.current.mutate({ connector: 'vault', ref: 'db/password' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.readSecret).toHaveBeenCalledWith('vault', 'db/password');
        expect(result.current.data).toEqual(secret);
    });

    // G28: the response carries decrypted plaintext. Without a short gcTime
    // override, react-query's MutationCache would retain it for the default 5
    // minutes after the last observer unmounts.
    it('does not retain the decrypted plaintext in the MutationCache once the component unmounts', async () => {
        const secret = { connector: 'vault', ref: 'db/password', value: 'hunter2-plaintext' };
        mock.readSecret.mockResolvedValueOnce(secret);
        const { wrapper, queryClient } = createWrapper();
        const { result, unmount } = renderHook(() => useReadFederatedSecret(), { wrapper });

        act(() => {
            result.current.mutate({ connector: 'vault', ref: 'db/password' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        // The mutation cache holds the plaintext response while there's still an
        // observer — that alone is expected/necessary for the active request.
        expect(queryClient.getMutationCache().getAll()).toHaveLength(1);
        expect(queryClient.getMutationCache().getAll()[0]?.state.data).toEqual(secret);

        // Once the component unmounts (no explicit close/dismiss beyond that),
        // the short gcTime evicts the plaintext instead of it lingering for the
        // default 5 minutes.
        unmount();
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });
});

describe('useRefGrants', () => {
    it('fetches the ref grants list', async () => {
        const grants = [{ id: 1, role_id: 2, connector: 'vault', ref_prefix: 'db/' }];
        mock.listRefGrants.mockResolvedValueOnce(grants);
        const { wrapper } = createWrapper();
        const { result } = renderHook(() => useRefGrants(), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual(grants);
    });
});

describe('useCreateRefGrant', () => {
    it('creates a grant and invalidates the ref-grants query', async () => {
        const grant = { id: 5, role_id: 2, connector: 'vault', ref_prefix: 'db/*' };
        mock.createRefGrant.mockResolvedValueOnce(grant);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useCreateRefGrant(), { wrapper });

        act(() => {
            result.current.mutate({ roleId: 2, connector: 'vault', refPrefix: 'db/*' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.createRefGrant).toHaveBeenCalledWith(2, 'vault', 'db/*');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['connect-ref-grants'] });
    });
});

describe('useDeleteRefGrant', () => {
    it('deletes a grant and invalidates the ref-grants query', async () => {
        mock.deleteRefGrant.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useDeleteRefGrant(), { wrapper });

        act(() => {
            result.current.mutate(5);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.deleteRefGrant).toHaveBeenCalledWith(5);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['connect-ref-grants'] });
    });
});
