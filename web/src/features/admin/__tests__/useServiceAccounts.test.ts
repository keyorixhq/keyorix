import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import {
    useServiceAccounts,
    useCreateServiceAccount,
    useUpdateServiceAccount,
    useDeactivateServiceAccount,
    useServiceAccountTokens,
    useCreateToken,
    useRevokeToken,
} from '../useServiceAccounts';
import type { ServiceAccount, APIToken } from '../../../types/serviceAccounts';

const mocks = vi.hoisted(() => ({
    listServiceAccounts: vi.fn(),
    createServiceAccount: vi.fn(),
    updateServiceAccount: vi.fn(),
    deactivateServiceAccount: vi.fn(),
    listTokens: vi.fn(),
    createToken: vi.fn(),
    revokeToken: vi.fn(),
}));

vi.mock('../../../services/serviceAccounts', () => ({
    serviceAccountsApi: {
        listServiceAccounts: mocks.listServiceAccounts,
        createServiceAccount: mocks.createServiceAccount,
        updateServiceAccount: mocks.updateServiceAccount,
        deactivateServiceAccount: mocks.deactivateServiceAccount,
        listTokens: mocks.listTokens,
        createToken: mocks.createToken,
        revokeToken: mocks.revokeToken,
    },
}));

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client: queryClient }, children);
    };
    return { wrapper, queryClient };
}

const serviceAccountsFixture: ServiceAccount[] = [
    {
        id: 1,
        name: 'ci-bot',
        description: 'CI pipeline account',
        client_id: 'client-abc',
        scopes: 'read,write',
        is_active: true,
        created_at: '2026-01-01T00:00:00Z',
    },
];

const tokensFixture: APIToken[] = [
    {
        id: 10,
        client_id: 1,
        scope: 'read',
        expires_at: null,
        created_at: '2026-01-01T00:00:00Z',
        revoked: false,
    },
];

beforeEach(() => {
    vi.clearAllMocks();
});

// ── useServiceAccounts ───────────────────────────────────────────────────────

describe('useServiceAccounts', () => {
    it('starts loading and transitions to success with the service account list', async () => {
        mocks.listServiceAccounts.mockResolvedValueOnce(serviceAccountsFixture);

        const { result } = renderHook(() => useServiceAccounts(), { wrapper: createWrapper().wrapper });

        expect(result.current.isLoading).toBe(true);

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.data).toEqual(serviceAccountsFixture);
        expect(mocks.listServiceAccounts).toHaveBeenCalledTimes(1);
        expect(mocks.listServiceAccounts).toHaveBeenCalledWith();
    });

    it('uses the ["service-accounts"] query key', async () => {
        mocks.listServiceAccounts.mockResolvedValueOnce(serviceAccountsFixture);
        const { wrapper, queryClient } = createWrapper();

        const { result } = renderHook(() => useServiceAccounts(), { wrapper });
        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(queryClient.getQueryData(['service-accounts'])).toEqual(serviceAccountsFixture);
    });

    it('surfaces a rejected request as an error', async () => {
        mocks.listServiceAccounts.mockRejectedValueOnce(new Error('list failed'));

        const { result } = renderHook(() => useServiceAccounts(), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isError).toBe(true));
        expect((result.current.error as Error).message).toBe('list failed');
    });
});

// ── useCreateServiceAccount ──────────────────────────────────────────────────

describe('useCreateServiceAccount', () => {
    const payload = { name: 'new-bot', description: 'desc', scopes: 'read' };

    it('calls createServiceAccount with the body and resolves with the created account', async () => {
        const created = { service_account: { ...serviceAccountsFixture[0], id: 2 }, client_secret: 'secret-value' };
        mocks.createServiceAccount.mockResolvedValueOnce(created);

        const { result } = renderHook(() => useCreateServiceAccount(), { wrapper: createWrapper().wrapper });

        let mutationResult: unknown;
        await act(async () => {
            mutationResult = await result.current.mutateAsync(payload);
        });

        // mutationFn is `serviceAccountsApi.createServiceAccount` referenced directly (not
        // wrapped in an arrow function), so React Query invokes it with an internal context
        // object as a second argument — assert only the first (payload) argument.
        expect(mocks.createServiceAccount.mock.calls[0][0]).toEqual(payload);
        expect(mutationResult).toEqual(created);
    });

    it('invalidates the service-accounts query cache on success', async () => {
        mocks.createServiceAccount.mockResolvedValueOnce({ service_account: serviceAccountsFixture[0] });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');

        const { result } = renderHook(() => useCreateServiceAccount(), { wrapper });

        await act(async () => {
            await result.current.mutateAsync(payload);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['service-accounts'] });
    });

    it('rejects and surfaces the mutation error when the request fails', async () => {
        mocks.createServiceAccount.mockRejectedValueOnce(new Error('create failed'));

        const { result } = renderHook(() => useCreateServiceAccount(), { wrapper: createWrapper().wrapper });

        await expect(result.current.mutateAsync(payload)).rejects.toThrow('create failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useUpdateServiceAccount ──────────────────────────────────────────────────

describe('useUpdateServiceAccount', () => {
    it('calls updateServiceAccount with the id and body', async () => {
        const updated = { ...serviceAccountsFixture[0], name: 'renamed-bot' };
        mocks.updateServiceAccount.mockResolvedValueOnce(updated);

        const { result } = renderHook(() => useUpdateServiceAccount(), { wrapper: createWrapper().wrapper });

        let mutationResult: unknown;
        await act(async () => {
            mutationResult = await result.current.mutateAsync({ id: 1, body: { name: 'renamed-bot' } });
        });

        expect(mocks.updateServiceAccount).toHaveBeenCalledWith(1, { name: 'renamed-bot' });
        expect(mutationResult).toEqual(updated);
    });

    it('invalidates the service-accounts query cache on success', async () => {
        mocks.updateServiceAccount.mockResolvedValueOnce(serviceAccountsFixture[0]);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');

        const { result } = renderHook(() => useUpdateServiceAccount(), { wrapper });

        await act(async () => {
            await result.current.mutateAsync({ id: 1, body: { description: 'updated' } });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['service-accounts'] });
    });

    it('rejects and surfaces the mutation error when the request fails', async () => {
        mocks.updateServiceAccount.mockRejectedValueOnce(new Error('update failed'));

        const { result } = renderHook(() => useUpdateServiceAccount(), { wrapper: createWrapper().wrapper });

        await expect(result.current.mutateAsync({ id: 1, body: { name: 'x' } })).rejects.toThrow('update failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useDeactivateServiceAccount ──────────────────────────────────────────────

describe('useDeactivateServiceAccount', () => {
    it('calls deactivateServiceAccount with the id', async () => {
        mocks.deactivateServiceAccount.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useDeactivateServiceAccount(), { wrapper: createWrapper().wrapper });

        await act(async () => {
            await result.current.mutateAsync(1);
        });

        expect(mocks.deactivateServiceAccount).toHaveBeenCalledWith(1);
    });

    it('invalidates the service-accounts query cache on success', async () => {
        mocks.deactivateServiceAccount.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');

        const { result } = renderHook(() => useDeactivateServiceAccount(), { wrapper });

        await act(async () => {
            await result.current.mutateAsync(1);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['service-accounts'] });
    });

    it('rejects and surfaces the mutation error when the request fails', async () => {
        mocks.deactivateServiceAccount.mockRejectedValueOnce(new Error('deactivate failed'));

        const { result } = renderHook(() => useDeactivateServiceAccount(), { wrapper: createWrapper().wrapper });

        await expect(result.current.mutateAsync(1)).rejects.toThrow('deactivate failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useServiceAccountTokens ──────────────────────────────────────────────────

describe('useServiceAccountTokens', () => {
    it('starts loading and transitions to success with the token list', async () => {
        mocks.listTokens.mockResolvedValueOnce(tokensFixture);

        const { result } = renderHook(() => useServiceAccountTokens(1), { wrapper: createWrapper().wrapper });

        expect(result.current.isLoading).toBe(true);

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.data).toEqual(tokensFixture);
        expect(mocks.listTokens).toHaveBeenCalledWith(1);
    });

    it('uses the ["service-account-tokens", id] query key', async () => {
        mocks.listTokens.mockResolvedValueOnce(tokensFixture);
        const { wrapper, queryClient } = createWrapper();

        const { result } = renderHook(() => useServiceAccountTokens(1), { wrapper });
        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(queryClient.getQueryData(['service-account-tokens', 1])).toEqual(tokensFixture);
    });

    it('does not call listTokens and stays disabled when serviceAccountId is null', async () => {
        const { result } = renderHook(() => useServiceAccountTokens(null), { wrapper: createWrapper().wrapper });

        // Give React Query a tick to settle; a disabled query never transitions to fetching.
        await waitFor(() => expect(result.current.fetchStatus).toBe('idle'));

        expect(result.current.isLoading).toBe(false);
        expect(mocks.listTokens).not.toHaveBeenCalled();
    });

    it('surfaces a rejected request as an error', async () => {
        mocks.listTokens.mockRejectedValueOnce(new Error('tokens failed'));

        const { result } = renderHook(() => useServiceAccountTokens(1), { wrapper: createWrapper().wrapper });

        await waitFor(() => expect(result.current.isError).toBe(true));
        expect((result.current.error as Error).message).toBe('tokens failed');
    });
});

// ── useCreateToken ───────────────────────────────────────────────────────────

describe('useCreateToken', () => {
    const body = { description: 'ci token', expires_at: '2027-01-01T00:00:00Z' };

    it('calls createToken with the service account id and body', async () => {
        const created = { token: tokensFixture[0], access_token: 'plain-token-value' };
        mocks.createToken.mockResolvedValueOnce(created);

        const { result } = renderHook(() => useCreateToken(), { wrapper: createWrapper().wrapper });

        let mutationResult: unknown;
        await act(async () => {
            mutationResult = await result.current.mutateAsync({ serviceAccountId: 1, body });
        });

        expect(mocks.createToken).toHaveBeenCalledWith(1, body);
        expect(mutationResult).toEqual(created);
    });

    it('invalidates only the tokens query for that specific service account id on success', async () => {
        mocks.createToken.mockResolvedValueOnce({ token: tokensFixture[0], access_token: 'x' });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');

        const { result } = renderHook(() => useCreateToken(), { wrapper });

        await act(async () => {
            await result.current.mutateAsync({ serviceAccountId: 7, body });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['service-account-tokens', 7] });
    });

    it('rejects and surfaces the mutation error when the request fails', async () => {
        mocks.createToken.mockRejectedValueOnce(new Error('create token failed'));

        const { result } = renderHook(() => useCreateToken(), { wrapper: createWrapper().wrapper });

        await expect(result.current.mutateAsync({ serviceAccountId: 1, body })).rejects.toThrow('create token failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useRevokeToken ───────────────────────────────────────────────────────────

describe('useRevokeToken', () => {
    it('calls revokeToken with the token id', async () => {
        mocks.revokeToken.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useRevokeToken(), { wrapper: createWrapper().wrapper });

        await act(async () => {
            await result.current.mutateAsync({ tokenId: 10 });
        });

        expect(mocks.revokeToken).toHaveBeenCalledWith(10);
    });

    it('invalidates the entire service-account-tokens prefix (not just one service account) on success', async () => {
        // NOTE: unlike useCreateToken, the mutation variables only carry `tokenId`, not the
        // owning `serviceAccountId`, so the hook cannot narrow invalidation to a single
        // service account's token list. It invalidates the whole ['service-account-tokens']
        // key prefix instead, which is broader than strictly necessary but functionally
        // correct (React Query treats a partial key as a prefix match). Documenting this
        // as observed behavior, not a bug — APITokensPage relies on exactly this broad
        // invalidation since it fans a single revoke out across per-account token queries
        // sharing the same key prefix.
        mocks.revokeToken.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');

        const { result } = renderHook(() => useRevokeToken(), { wrapper });

        await act(async () => {
            await result.current.mutateAsync({ tokenId: 10 });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['service-account-tokens'] });
    });

    it('rejects and surfaces the mutation error when the request fails', async () => {
        mocks.revokeToken.mockRejectedValueOnce(new Error('revoke failed'));

        const { result } = renderHook(() => useRevokeToken(), { wrapper: createWrapper().wrapper });

        await expect(result.current.mutateAsync({ tokenId: 10 })).rejects.toThrow('revoke failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});
