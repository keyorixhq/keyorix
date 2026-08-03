import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import {
    useNotificationChannels,
    useCreateNotificationChannel,
    useUpdateNotificationChannel,
    useDeleteNotificationChannel,
    useRetryPolicy,
    useSetRetryPolicy,
} from '../useNotificationChannels';

const { notificationChannelsApiMock } = vi.hoisted(() => ({
    notificationChannelsApiMock: {
        list: vi.fn(),
        get: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        getRetryPolicy: vi.fn(),
        setRetryPolicy: vi.fn(),
    },
}));

vi.mock('../../../services/notificationChannels', () => ({ notificationChannelsApi: notificationChannelsApiMock }));

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client: queryClient }, children);
    };
}

function createSpyableWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
    const Wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { Wrapper, invalidateSpy };
}

beforeEach(() => {
    vi.clearAllMocks();
});

const channel = {
    id: 1,
    name: 'platform-alerts',
    type: 'webhook',
    enabled: true,
    url: 'https://hooks.example.com/platform',
    events: 'secret.rotated',
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
};

// ── useNotificationChannels ───────────────────────────────────────────────

describe('useNotificationChannels', () => {
    it('starts loading and transitions to success, using the ["notification-channels"] key', async () => {
        notificationChannelsApiMock.list.mockResolvedValueOnce([channel]);

        const { result } = renderHook(() => useNotificationChannels(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.data).toEqual([channel]);
        expect(notificationChannelsApiMock.list).toHaveBeenCalledTimes(1);
    });

    it('serves a second mount from cache without a fresh call (shared query key)', async () => {
        notificationChannelsApiMock.list.mockResolvedValue([]);
        const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
        const wrapper = ({ children }: { children: React.ReactNode }) =>
            React.createElement(QueryClientProvider, { client: queryClient }, children);

        const first = renderHook(() => useNotificationChannels(), { wrapper });
        await waitFor(() => expect(first.result.current.isLoading).toBe(false));

        const second = renderHook(() => useNotificationChannels(), { wrapper });
        await waitFor(() => expect(second.result.current.isLoading).toBe(false));

        expect(notificationChannelsApiMock.list).toHaveBeenCalledTimes(1);
    });
});

// ── useCreateNotificationChannel ──────────────────────────────────────────

describe('useCreateNotificationChannel', () => {
    const body = { name: 'platform-alerts', type: 'webhook', events: 'secret.rotated' };

    it('calls notificationChannelsApi.create with the body', async () => {
        notificationChannelsApiMock.create.mockResolvedValueOnce(channel);

        const { result } = renderHook(() => useCreateNotificationChannel(), { wrapper: createWrapper() });

        let mutationResult: unknown;
        await act(async () => {
            mutationResult = await result.current.mutateAsync(body);
        });

        expect(notificationChannelsApiMock.create).toHaveBeenCalledWith(body);
        expect(mutationResult).toEqual(channel);
    });

    it('invalidates the ["notification-channels"] query cache on success', async () => {
        notificationChannelsApiMock.create.mockResolvedValueOnce(channel);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useCreateNotificationChannel(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync(body);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['notification-channels'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        notificationChannelsApiMock.create.mockRejectedValueOnce(new Error('create failed'));

        const { result } = renderHook(() => useCreateNotificationChannel(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync(body)).rejects.toThrow('create failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useUpdateNotificationChannel ──────────────────────────────────────────

describe('useUpdateNotificationChannel', () => {
    const body = { name: 'platform-alerts-v2', type: 'webhook', events: 'secret.rotated' };

    it('calls notificationChannelsApi.update with id and body', async () => {
        notificationChannelsApiMock.update.mockResolvedValueOnce({ ...channel, name: 'platform-alerts-v2' });

        const { result } = renderHook(() => useUpdateNotificationChannel(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ id: 1, body });
        });

        expect(notificationChannelsApiMock.update).toHaveBeenCalledWith(1, body);
    });

    it('invalidates the ["notification-channels"] query cache on success', async () => {
        notificationChannelsApiMock.update.mockResolvedValueOnce(channel);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useUpdateNotificationChannel(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync({ id: 1, body });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['notification-channels'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        notificationChannelsApiMock.update.mockRejectedValueOnce(new Error('update failed'));

        const { result } = renderHook(() => useUpdateNotificationChannel(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ id: 1, body })).rejects.toThrow('update failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useDeleteNotificationChannel ──────────────────────────────────────────

describe('useDeleteNotificationChannel', () => {
    it('calls notificationChannelsApi.delete with the id', async () => {
        notificationChannelsApiMock.delete.mockResolvedValueOnce(undefined);

        const { result } = renderHook(() => useDeleteNotificationChannel(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync(1);
        });

        expect(notificationChannelsApiMock.delete).toHaveBeenCalledWith(1);
    });

    it('invalidates the ["notification-channels"] query cache on success', async () => {
        notificationChannelsApiMock.delete.mockResolvedValueOnce(undefined);
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useDeleteNotificationChannel(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync(1);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['notification-channels'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        notificationChannelsApiMock.delete.mockRejectedValueOnce(new Error('delete failed'));

        const { result } = renderHook(() => useDeleteNotificationChannel(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync(1)).rejects.toThrow('delete failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useRetryPolicy ─────────────────────────────────────────────────────────

describe('useRetryPolicy', () => {
    it('fetches the retry policy when channelId is non-null', async () => {
        const policy = { channel_id: 1, max_retries: 3, retry_backoff_ms: 1000 };
        notificationChannelsApiMock.getRetryPolicy.mockResolvedValueOnce(policy);

        const { result } = renderHook(() => useRetryPolicy(1), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(notificationChannelsApiMock.getRetryPolicy).toHaveBeenCalledWith(1);
        expect(result.current.data).toEqual(policy);
    });

    it('stays disabled and never calls the service when channelId is null', () => {
        const { result } = renderHook(() => useRetryPolicy(null), { wrapper: createWrapper() });

        expect(result.current.fetchStatus).toBe('idle');
        expect(notificationChannelsApiMock.getRetryPolicy).not.toHaveBeenCalled();
    });
});

// ── useSetRetryPolicy ──────────────────────────────────────────────────────

describe('useSetRetryPolicy', () => {
    const body = { max_retries: 5, retry_backoff_ms: 2000 };

    it('calls notificationChannelsApi.setRetryPolicy with id and body', async () => {
        notificationChannelsApiMock.setRetryPolicy.mockResolvedValueOnce({ channel_id: 1, ...body });

        const { result } = renderHook(() => useSetRetryPolicy(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ id: 1, body });
        });

        expect(notificationChannelsApiMock.setRetryPolicy).toHaveBeenCalledWith(1, body);
    });

    it('invalidates ["notification-channels",id,"retry-policy"] scoped to the mutated channel on success', async () => {
        notificationChannelsApiMock.setRetryPolicy.mockResolvedValueOnce({ channel_id: 1, ...body });
        const { Wrapper, invalidateSpy } = createSpyableWrapper();

        const { result } = renderHook(() => useSetRetryPolicy(), { wrapper: Wrapper });

        await act(async () => {
            await result.current.mutateAsync({ id: 1, body });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['notification-channels', 1, 'retry-policy'] });
    });

    it('surfaces a rejected mutation as an error', async () => {
        notificationChannelsApiMock.setRetryPolicy.mockRejectedValueOnce(new Error('set-retry-policy failed'));

        const { result } = renderHook(() => useSetRetryPolicy(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ id: 1, body })).rejects.toThrow('set-retry-policy failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});
