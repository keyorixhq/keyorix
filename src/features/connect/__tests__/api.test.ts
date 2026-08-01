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
