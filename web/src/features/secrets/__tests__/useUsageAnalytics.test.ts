import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { SecretUsageStat, UnusedSecretStat } from '../../../types';

// vi.hoisted() runs before the vi.mock() factory so the stubs are in scope there.
const { mockMostAccessed, mockUnused } = vi.hoisted(() => ({
    mockMostAccessed: vi.fn(),
    mockUnused: vi.fn(),
}));

vi.mock('../../../services/secrets', () => ({
    secretsApi: {
        mostAccessed: mockMostAccessed,
        unused: mockUnused,
    },
}));

import { useMostAccessedSecrets, useUnusedSecrets } from '../useUsageAnalytics';

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client: queryClient }, children);
    };
}

const mostAccessedFixture: SecretUsageStat[] = [
    { secret_id: 1, secret_name: 'db-password', environment_id: 10, read_count: 42, last_read: '2026-07-29T12:00:00Z' },
    { secret_id: 2, secret_name: 'api-key', environment_id: 10, read_count: 17, last_read: '2026-07-28T09:30:00Z' },
];

const unusedFixture: UnusedSecretStat[] = [
    { secret_id: 3, secret_name: 'legacy-token', environment_id: 11, last_read: null },
    { secret_id: 4, secret_name: 'old-cert', environment_id: 11, last_read: '2025-01-01T00:00:00Z' },
];

describe('useMostAccessedSecrets', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('starts in a loading state with an empty secrets array', async () => {
        let resolvePromise: (value: SecretUsageStat[]) => void = () => {};
        mockMostAccessed.mockReturnValue(
            new Promise<SecretUsageStat[]>((resolve) => {
                resolvePromise = resolve;
            })
        );

        const { result } = renderHook(() => useMostAccessedSecrets(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        expect(result.current.secrets).toEqual([]);

        resolvePromise(mostAccessedFixture);
        await waitFor(() => expect(result.current.isLoading).toBe(false));
    });

    it('resolves with the fixture data and the correct query key / service args', async () => {
        mockMostAccessed.mockResolvedValue(mostAccessedFixture);

        const params = { days: 30, limit: 10, projectId: 5 };
        const { result } = renderHook(() => useMostAccessedSecrets(params), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.secrets).toEqual(mostAccessedFixture);
        expect(result.current.error).toBeNull();
        expect(mockMostAccessed).toHaveBeenCalledExactlyOnceWith(params);
    });

    it('calls the service with undefined params when none are supplied', async () => {
        mockMostAccessed.mockResolvedValue(mostAccessedFixture);

        const { result } = renderHook(() => useMostAccessedSecrets(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(mockMostAccessed).toHaveBeenCalledExactlyOnceWith(undefined);
    });

    it('defaults secrets to an empty array when the query rejects', async () => {
        const apiError = new Error('most-accessed request failed');
        mockMostAccessed.mockRejectedValue(apiError);

        const { result } = renderHook(() => useMostAccessedSecrets({ days: 7 }), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.secrets).toEqual([]);
        expect(result.current.error).toBe(apiError);
    });

    it('refetches with a new query key and new service args when params change', async () => {
        mockMostAccessed.mockResolvedValueOnce([mostAccessedFixture[0]]).mockResolvedValueOnce(mostAccessedFixture);

        const { result, rerender } = renderHook(({ days }) => useMostAccessedSecrets({ days }), {
            wrapper: createWrapper(),
            initialProps: { days: 30 },
        });

        await waitFor(() => expect(result.current.isLoading).toBe(false));
        expect(result.current.secrets).toEqual([mostAccessedFixture[0]]);
        expect(mockMostAccessed).toHaveBeenCalledExactlyOnceWith({ days: 30 });

        rerender({ days: 90 });

        await waitFor(() => expect(result.current.secrets).toEqual(mostAccessedFixture));
        expect(mockMostAccessed).toHaveBeenCalledTimes(2);
        expect(mockMostAccessed).toHaveBeenNthCalledWith(2, { days: 90 });
    });
});

describe('useUnusedSecrets', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('starts in a loading state with an empty secrets array', async () => {
        let resolvePromise: (value: UnusedSecretStat[]) => void = () => {};
        mockUnused.mockReturnValue(
            new Promise<UnusedSecretStat[]>((resolve) => {
                resolvePromise = resolve;
            })
        );

        const { result } = renderHook(() => useUnusedSecrets(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        expect(result.current.secrets).toEqual([]);

        resolvePromise(unusedFixture);
        await waitFor(() => expect(result.current.isLoading).toBe(false));
    });

    it('resolves with the fixture data and the correct service args', async () => {
        mockUnused.mockResolvedValue(unusedFixture);

        const params = { days: 90, projectId: 12 };
        const { result } = renderHook(() => useUnusedSecrets(params), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.secrets).toEqual(unusedFixture);
        expect(result.current.error).toBeNull();
        expect(mockUnused).toHaveBeenCalledExactlyOnceWith(params);
    });

    it('defaults secrets to an empty array when the query rejects', async () => {
        const apiError = new Error('unused request failed');
        mockUnused.mockRejectedValue(apiError);

        const { result } = renderHook(() => useUnusedSecrets({ days: 60 }), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.secrets).toEqual([]);
        expect(result.current.error).toBe(apiError);
    });

    it('refetches with new service args when params change', async () => {
        mockUnused.mockResolvedValueOnce([unusedFixture[0]]).mockResolvedValueOnce(unusedFixture);

        const { result, rerender } = renderHook(({ days }) => useUnusedSecrets({ days }), {
            wrapper: createWrapper(),
            initialProps: { days: 30 },
        });

        await waitFor(() => expect(result.current.isLoading).toBe(false));
        expect(result.current.secrets).toEqual([unusedFixture[0]]);

        rerender({ days: 90 });

        await waitFor(() => expect(result.current.secrets).toEqual(unusedFixture));
        expect(mockUnused).toHaveBeenCalledTimes(2);
        expect(mockUnused).toHaveBeenNthCalledWith(2, { days: 90 });
    });
});
