import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/secrets', () => ({
    secretsApi: {
        list: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        rotate: vi.fn(),
    },
}));

import { secretsApi } from '../../../services/secrets';
import { queryKeys } from '../../../lib/queryClient';
import { useProjectSecrets } from '../useProjectSecrets';

const mock = secretsApi as unknown as {
    list: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
    rotate: ReturnType<typeof vi.fn>;
};

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

const emptyPage = { data: [], total: 0, page: 1, pageSize: 20, totalPages: 1 };

beforeEach(() => {
    vi.clearAllMocks();
    mock.list.mockResolvedValue(emptyPage);
});

afterEach(() => {
    // Safety net: if a fake-timers test fails before it restores real timers, a
    // leaked fake clock freezes waitFor's internal polling in every test that runs
    // after it.
    vi.useRealTimers();
});

// ── query: enablement + param composition ──────────────────────────────────────

describe('useProjectSecrets query', () => {
    it('does not fetch when projectId is 0 (not > 0)', async () => {
        renderHook(() => useProjectSecrets({ projectId: 0, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });
        await act(async () => {});
        expect(mock.list).not.toHaveBeenCalled();
    });

    it('fetches with only page/pageSize/project_id when there is no search, filter, or environment', async () => {
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });
        await waitFor(() => expect(result.current.isLoading).toBe(false));
        expect(mock.list).toHaveBeenCalledWith({ page: 1, pageSize: 20, project_id: 5 });
    });

    it('includes environment_id only when environmentId is truthy', async () => {
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: 3 }), {
            wrapper: createWrapper().wrapper,
        });
        await waitFor(() => expect(result.current.isLoading).toBe(false));
        expect(mock.list).toHaveBeenCalledWith({ page: 1, pageSize: 20, project_id: 5, environment_id: 3 });
    });

    it('includes type only when typeFilter is not "all"', async () => {
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });
        await waitFor(() => expect(mock.list).toHaveBeenCalledTimes(1));

        act(() => {
            result.current.setTypeFilter('password');
        });
        await waitFor(() => expect(mock.list).toHaveBeenCalledTimes(2));

        expect(mock.list).toHaveBeenLastCalledWith({ page: 1, pageSize: 20, type: 'password', project_id: 5 });
    });

    it('composes the query key from projectId, environmentId, debouncedSearch, typeFilter, page, and pageSize', async () => {
        const { wrapper, queryClient } = createWrapper();
        renderHook(() => useProjectSecrets({ projectId: 5, environmentId: 3 }), { wrapper });
        await waitFor(() => expect(mock.list).toHaveBeenCalled());

        const state = queryClient.getQueryState(['project-secrets', 5, 3, '', 'all', 1, 20]);
        expect(state).toBeDefined();
        expect(state?.status).toBe('success');
    });
});

// ── debounced search ─────────────────────────────────────────────────────────

describe('useProjectSecrets debounced search', () => {
    it('debounces search input, applies it to the query, and resets page to 1', async () => {
        vi.useFakeTimers();
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });

        // Let the initial (unfiltered) query settle.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });
        expect(mock.list).toHaveBeenCalledTimes(1);

        // Move off page 1 so the debounce's page-reset behavior is observable.
        act(() => {
            result.current.handlePageChange(3);
        });
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });
        expect(result.current.pagination.page).toBe(3);

        act(() => {
            result.current.setSearch('db');
        });
        // Debounce hasn't elapsed yet — no fetch with the new search term.
        expect(mock.list).not.toHaveBeenLastCalledWith(expect.objectContaining({ search: 'db' }));

        // advanceTimersByTimeAsync (not advanceTimersByTime + waitFor) so the debounce's
        // setTimeout and the subsequent react-query fetch's promise chain both flush —
        // waitFor's own internal polling uses real timers, which are frozen once fake
        // timers are active, so it would otherwise hang forever.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(300);
        });
        // One more flush: the debounce firing triggers a state update that starts the
        // query on the *next* render, so the fetch itself resolves a tick after 300ms.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });

        expect(result.current.pagination.page).toBe(1);
        expect(mock.list).toHaveBeenLastCalledWith({ page: 1, pageSize: 20, search: 'db', project_id: 5 });

        vi.useRealTimers();
    });
});

// ── pagination derived object ───────────────────────────────────────────────

describe('useProjectSecrets pagination', () => {
    it('defaults total/totalPages when data is undefined', () => {
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });
        // Assert synchronously, before the mocked promise has a chance to resolve.
        expect(result.current.pagination).toEqual({ page: 1, pageSize: 20, total: 0, totalPages: 1 });
    });

    it('passes through total/totalPages once data resolves', async () => {
        mock.list.mockResolvedValueOnce({ data: [{ id: 1 }], total: 45, page: 1, pageSize: 20, totalPages: 3 });
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });
        await waitFor(() => expect(result.current.pagination.total).toBe(45));
        expect(result.current.pagination).toEqual({ page: 1, pageSize: 20, total: 45, totalPages: 3 });
    });
});

// ── handlePageChange / handlePageSizeChange ─────────────────────────────────

describe('useProjectSecrets handlePageChange / handlePageSizeChange', () => {
    it('updates the page', () => {
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });
        act(() => {
            result.current.handlePageChange(4);
        });
        expect(result.current.pagination.page).toBe(4);
    });

    it('updates page size and resets page to 1', () => {
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });
        act(() => {
            result.current.handlePageChange(4);
        });
        act(() => {
            result.current.handlePageSizeChange(50);
        });
        expect(result.current.pagination.pageSize).toBe(50);
        expect(result.current.pagination.page).toBe(1);
    });
});

// ── modal state ──────────────────────────────────────────────────────────────

describe('useProjectSecrets openModal / closeModal', () => {
    it('sets activeModal and modalData, then clears both on close', () => {
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });

        act(() => {
            result.current.openModal('edit', { id: 7, name: 'x' });
        });
        expect(result.current.activeModal).toBe('edit');
        expect(result.current.modalData).toEqual({ id: 7, name: 'x' });

        act(() => {
            result.current.closeModal();
        });
        expect(result.current.activeModal).toBeNull();
        expect(result.current.modalData).toBeNull();
    });

    it('defaults modalData to null when opening without data', () => {
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });
        act(() => {
            result.current.openModal('delete');
        });
        expect(result.current.activeModal).toBe('delete');
        expect(result.current.modalData).toBeNull();
    });
});

// ── mutations ────────────────────────────────────────────────────────────────

describe('useProjectSecrets createMutation', () => {
    it('creates a secret, then closes the modal and invalidates both caches', async () => {
        mock.create.mockResolvedValueOnce({ id: 1 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), { wrapper });

        act(() => {
            result.current.openModal('create');
        });
        expect(result.current.activeModal).toBe('create');

        act(() => {
            result.current.createMutation.mutate({ name: 'x', type: 'text', value: 'v' });
        });
        await waitFor(() => expect(result.current.createMutation.isSuccess).toBe(true));

        expect(mock.create).toHaveBeenCalledWith({ name: 'x', type: 'text', value: 'v' });
        expect(result.current.activeModal).toBeNull();
        expect(result.current.modalData).toBeNull();
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['project-secrets', 5] });
    });
});

describe('useProjectSecrets editMutation', () => {
    it('includes value in the update payload when the trimmed value is non-empty', async () => {
        mock.update.mockResolvedValueOnce({ id: 2 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), { wrapper });

        act(() => {
            result.current.editMutation.mutate({ id: 2, name: 'renamed', type: 'text', value: 'secret-value' });
        });
        await waitFor(() => expect(result.current.editMutation.isSuccess).toBe(true));

        expect(mock.update).toHaveBeenCalledWith(2, { name: 'renamed', type: 'text', value: 'secret-value' });
        expect(result.current.activeModal).toBeNull();
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['project-secrets', 5] });
    });

    // Documents the exact branch in useProjectSecrets.ts: `if (value.trim()) updateData.value = value;`
    it('omits value from the update payload when it is empty or whitespace-only', async () => {
        mock.update.mockResolvedValueOnce({ id: 2 });
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), {
            wrapper: createWrapper().wrapper,
        });

        act(() => {
            result.current.editMutation.mutate({ id: 2, name: 'renamed', type: 'text', value: '   ' });
        });
        await waitFor(() => expect(result.current.editMutation.isSuccess).toBe(true));

        expect(mock.update).toHaveBeenCalledWith(2, { name: 'renamed', type: 'text' });
    });
});

describe('useProjectSecrets deleteMutation', () => {
    it('deletes a secret, then closes the modal and invalidates both caches', async () => {
        mock.delete.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), { wrapper });

        act(() => {
            result.current.openModal('delete', { id: 9 });
        });

        act(() => {
            result.current.deleteMutation.mutate(9);
        });
        await waitFor(() => expect(result.current.deleteMutation.isSuccess).toBe(true));

        expect(mock.delete).toHaveBeenCalledWith(9);
        expect(result.current.activeModal).toBeNull();
        expect(result.current.modalData).toBeNull();
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['project-secrets', 5] });
    });
});

describe('useProjectSecrets rotateMutation', () => {
    it('rotates a secret, then closes the modal and invalidates both caches', async () => {
        mock.rotate.mockResolvedValueOnce({ id: 3 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useProjectSecrets({ projectId: 5, environmentId: null }), { wrapper });

        act(() => {
            result.current.openModal('rotate', { id: 3 });
        });

        act(() => {
            result.current.rotateMutation.mutate({ id: 3, newValue: 'new-secret-value' });
        });
        await waitFor(() => expect(result.current.rotateMutation.isSuccess).toBe(true));

        expect(mock.rotate).toHaveBeenCalledWith(3, 'new-secret-value');
        expect(result.current.activeModal).toBeNull();
        expect(result.current.modalData).toBeNull();
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['project-secrets', 5] });
    });
});
