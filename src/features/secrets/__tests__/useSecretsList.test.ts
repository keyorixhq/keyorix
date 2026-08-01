import React from 'react';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useSecretsList } from '../useSecretsList';
import { useUIStore } from '../../../store/uiStore';
import { queryKeys } from '../../../lib/queryClient';

const mocks = vi.hoisted(() => ({
    secretsList: vi.fn(),
    secretsCreate: vi.fn(),
    secretsUpdate: vi.fn(),
    secretsDelete: vi.fn(),
    secretsRotate: vi.fn(),
    environmentsList: vi.fn(),
}));

vi.mock('../../../services/secrets', () => ({
    secretsApi: {
        list: mocks.secretsList,
        create: mocks.secretsCreate,
        update: mocks.secretsUpdate,
        delete: mocks.secretsDelete,
        rotate: mocks.secretsRotate,
    },
}));

vi.mock('../../../services/environments', () => ({
    environmentsApi: {
        list: mocks.environmentsList,
    },
}));

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client: queryClient }, children);
    };
    return { wrapper, queryClient };
}

// name/type/lastModified/Expiration are deliberately chosen so that sorting by
// "modified", "name" and "expiry" each produce a different order.
const secretsFixture = [
    {
        id: 1,
        name: 'Zulu',
        type: 'password',
        lastModified: '2024-03-01T00:00:00Z',
        Expiration: '2025-06-01T00:00:00Z',
    },
    { id: 2, name: 'alpha', type: 'text', lastModified: '2024-01-01T00:00:00Z', Expiration: null },
    {
        id: 3,
        name: 'Mike',
        type: 'api_key',
        lastModified: '2024-02-01T00:00:00Z',
        Expiration: '2025-01-01T00:00:00Z',
    },
];

const defaultListResponse = { data: secretsFixture, total: 3, page: 1, pageSize: 20, totalPages: 1 };

const environmentsFixture = [
    { id: 1, name: 'production' },
    { id: 2, name: 'staging' },
];

describe('useSecretsList', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mocks.secretsList.mockResolvedValue(defaultListResponse);
        mocks.environmentsList.mockResolvedValue(environmentsFixture);
        mocks.secretsCreate.mockResolvedValue({ id: 99 });
        mocks.secretsUpdate.mockResolvedValue({ id: 1 });
        mocks.secretsDelete.mockResolvedValue(undefined);
        mocks.secretsRotate.mockResolvedValue({ ok: true });
        // The UI store is a real Zustand singleton (persist+devtools); reset it so
        // modal state from a previous test doesn't leak in.
        useUIStore.setState({ activeModal: null, modalData: null });
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe('main query', () => {
        it('starts loading, then resolves with the secrets list and derived pagination totals', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });

            expect(result.current.isLoading).toBe(true);
            expect(result.current.pagination).toEqual({ page: 1, pageSize: 20, total: 0, totalPages: 0 });

            await waitFor(() => expect(result.current.isLoading).toBe(false));

            expect(result.current.data).toEqual(defaultListResponse);
            expect(result.current.error).toBeNull();
            // Effect syncs total/totalPages from the resolved response.
            expect(result.current.pagination.total).toBe(3);
            expect(result.current.pagination.totalPages).toBe(1);
            expect(mocks.secretsList).toHaveBeenCalledWith({ page: 1, pageSize: 20 });
        });

        it('uses the queryKeys.secrets.list factory as its query key', async () => {
            const { wrapper, queryClient } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            const expectedKey = queryKeys.secrets.list({
                search: '',
                type: 'all',
                classification: '',
                environment: '',
                tags: [],
                page: 1,
                pageSize: 20,
                sortBy: 'modified_desc',
            });
            expect(queryClient.getQueryData(expectedKey)).toEqual(defaultListResponse);
        });

        it('loads environments and exposes them', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });

            await waitFor(() => expect(result.current.environments).toEqual(environmentsFixture));
        });
    });

    describe('sorting', () => {
        it('defaults to modified_desc (newest first)', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            expect(result.current.secrets.map((s) => s.name)).toEqual(['Zulu', 'Mike', 'alpha']);
        });

        it('sorts by name ascending, case-insensitively', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.setSortBy('name_asc'));

            expect(result.current.secrets.map((s) => s.name)).toEqual(['alpha', 'Mike', 'Zulu']);
        });

        it('sorts by expiry ascending with nulls last', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.setSortBy('expiry_asc'));

            // Mike expires 2025-01-01, Zulu 2025-06-01, alpha has no Expiration.
            expect(result.current.secrets.map((s) => s.name)).toEqual(['Mike', 'Zulu', 'alpha']);
        });

        it('BUG: expiry_desc does not keep nulls last despite the "nulls sort last regardless of direction" comment', async () => {
            // compareSecrets negates compareExpiry's result for descending sorts
            // (`sortDirection === 'asc' ? cmp : -cmp`), which also flips the sign
            // compareExpiry uses to push null-Expiration entries to the end. The
            // net effect: nulls sort LAST for asc (as documented) but FIRST for
            // desc (contradicting the "regardless of direction" comment on
            // compareExpiry in useSecretsList.ts). Documenting via test, not
            // fixing, per this coverage sweep's scope.
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.setSortBy('expiry_desc'));

            // If nulls truly sorted last regardless of direction, this would be
            // ['Zulu', 'Mike', 'alpha']. It is not.
            expect(result.current.secrets.map((s) => s.name)).toEqual(['alpha', 'Zulu', 'Mike']);
        });

        it('falls back to a no-op comparator (stable/original order) for an unrecognized sort field', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.setSortBy('unknown_asc'));

            expect(result.current.secrets.map((s) => s.name)).toEqual(secretsFixture.map((s) => s.name));
        });
    });

    describe('filters', () => {
        it('updates the query params when type/classification/tags filters change, and resets to page 1', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.handlePageChange(3));
            await waitFor(() => expect(result.current.pagination.page).toBe(3));

            act(() => result.current.handleFilterChange('type', 'password'));
            await waitFor(() =>
                expect(mocks.secretsList).toHaveBeenLastCalledWith({ page: 1, pageSize: 20, type: 'password' })
            );
            expect(result.current.pagination.page).toBe(1);

            act(() => result.current.handleFilterChange('classification', 'confidential'));
            await waitFor(() =>
                expect(mocks.secretsList).toHaveBeenLastCalledWith({
                    page: 1,
                    pageSize: 20,
                    type: 'password',
                    classification: 'confidential',
                })
            );

            act(() => result.current.handleFilterChange('tags', ['prod', 'db']));
            await waitFor(() =>
                expect(mocks.secretsList).toHaveBeenLastCalledWith({
                    page: 1,
                    pageSize: 20,
                    type: 'password',
                    classification: 'confidential',
                    tags: ['prod', 'db'],
                })
            );
        });

        it('maps an environment filter to environment_id via the loaded environments list', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.environments).toEqual(environmentsFixture));
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.handleFilterChange('environment', 'staging'));

            await waitFor(() =>
                expect(mocks.secretsList).toHaveBeenLastCalledWith({ page: 1, pageSize: 20, environment_id: 2 })
            );
        });

        it('handleClearFilters resets filters, search/tag inputs, and pagination page', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => {
                result.current.handleFilterChange('type', 'password');
                result.current.setSearchInput('abc');
                result.current.setTagInput('tag');
                result.current.handlePageChange(2);
            });

            act(() => result.current.handleClearFilters());

            expect(result.current.filters).toEqual({
                search: '',
                type: 'all',
                classification: '',
                environment: '',
                tags: [],
            });
            expect(result.current.searchInput).toBe('');
            expect(result.current.tagInput).toBe('');
            expect(result.current.pagination.page).toBe(1);
        });

        it('computes hasActiveFilters from the current filters', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            expect(result.current.hasActiveFilters).toBe(false);

            act(() => result.current.handleFilterChange('classification', 'restricted'));
            expect(result.current.hasActiveFilters).toBe(true);

            act(() => result.current.handleClearFilters());
            expect(result.current.hasActiveFilters).toBe(false);
        });
    });

    describe('tags', () => {
        it('handleAddTag trims, dedupes, and clears tagInput; handleRemoveTag removes by value', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.handleAddTag('  prod  '));
            expect(result.current.filters.tags).toEqual(['prod']);
            expect(result.current.tagInput).toBe('');

            // Duplicate (already-trimmed) tag is not added again.
            act(() => result.current.handleAddTag('prod'));
            expect(result.current.filters.tags).toEqual(['prod']);

            // Whitespace-only tag is ignored.
            act(() => result.current.handleAddTag('   '));
            expect(result.current.filters.tags).toEqual(['prod']);

            act(() => result.current.handleAddTag('db'));
            expect(result.current.filters.tags).toEqual(['prod', 'db']);

            act(() => result.current.handleRemoveTag('prod'));
            expect(result.current.filters.tags).toEqual(['db']);
        });

        it('handleTagInputKeyPress adds the tag on Enter and prevents default; ignores other keys', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.setTagInput('staging'));
            const preventDefault = vi.fn();
            act(() =>
                result.current.handleTagInputKeyPress({
                    key: 'Enter',
                    preventDefault,
                } as unknown as React.KeyboardEvent)
            );

            expect(preventDefault).toHaveBeenCalledTimes(1);
            expect(result.current.filters.tags).toEqual(['staging']);

            act(() => result.current.setTagInput('ignored'));
            const preventDefault2 = vi.fn();
            act(() =>
                result.current.handleTagInputKeyPress({
                    key: 'Tab',
                    preventDefault: preventDefault2,
                } as unknown as React.KeyboardEvent)
            );
            expect(preventDefault2).not.toHaveBeenCalled();
            expect(result.current.filters.tags).toEqual(['staging']);
        });
    });

    describe('pagination', () => {
        it('handlePageChange sets the page and refetches with it', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.handlePageChange(2));

            await waitFor(() => expect(mocks.secretsList).toHaveBeenLastCalledWith({ page: 2, pageSize: 20 }));
            expect(result.current.pagination.page).toBe(2);
        });

        it('handlePageSizeChange sets pageSize and resets to page 1', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.handlePageChange(3));
            act(() => result.current.handlePageSizeChange(50));

            await waitFor(() => expect(mocks.secretsList).toHaveBeenLastCalledWith({ page: 1, pageSize: 50 }));
            expect(result.current.pagination.page).toBe(1);
            expect(result.current.pagination.pageSize).toBe(50);
        });
    });

    describe('debounced search', () => {
        beforeEach(() => vi.useFakeTimers());

        it('debounces searchInput into filters.search (and resets page) after 300ms', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });

            await act(async () => {
                await vi.advanceTimersByTimeAsync(0);
            });

            act(() => result.current.handlePageChange(4));
            expect(result.current.pagination.page).toBe(4);

            act(() => result.current.setSearchInput('db-password'));
            expect(result.current.filters.search).toBe('');

            await act(async () => {
                await vi.advanceTimersByTimeAsync(300);
            });

            expect(result.current.filters.search).toBe('db-password');
            expect(result.current.pagination.page).toBe(1);

            await act(async () => {
                await vi.advanceTimersByTimeAsync(0);
            });
            expect(mocks.secretsList).toHaveBeenLastCalledWith({
                page: 1,
                pageSize: 20,
                search: 'db-password',
            });
        });
    });

    describe('mutations', () => {
        it('createMutation calls secretsApi.create, closes the modal, and invalidates secrets.all', async () => {
            const { wrapper, queryClient } = createWrapper();
            const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
            useUIStore.setState({ activeModal: 'create-secret', modalData: null });

            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            const formData = { name: 'new-secret', value: 'v', type: 'text' } as any;
            act(() => result.current.createMutation.mutate(formData));

            await waitFor(() => expect(result.current.createMutation.isSuccess).toBe(true));

            expect(mocks.secretsCreate).toHaveBeenCalledWith(formData);
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
            expect(result.current.activeModal).toBeNull();
        });

        it('editMutation includes value only when non-blank (buildEditUpdateData)', async () => {
            const { wrapper, queryClient } = createWrapper();
            const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
            useUIStore.setState({ activeModal: 'edit-secret', modalData: { id: 1 } });

            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.editMutation.mutate({ id: 1, name: 'renamed', type: 'password', value: '   ' }));
            await waitFor(() => expect(result.current.editMutation.isSuccess).toBe(true));
            expect(mocks.secretsUpdate).toHaveBeenLastCalledWith(1, { name: 'renamed', type: 'password' });

            act(() =>
                result.current.editMutation.mutate({ id: 1, name: 'renamed', type: 'password', value: 'newval' })
            );
            await waitFor(() => expect(mocks.secretsUpdate).toHaveBeenCalledTimes(2));
            expect(mocks.secretsUpdate).toHaveBeenLastCalledWith(1, {
                name: 'renamed',
                type: 'password',
                value: 'newval',
            });

            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
            expect(result.current.activeModal).toBeNull();
        });

        it('deleteMutation calls secretsApi.delete, closes the modal, and invalidates secrets.all', async () => {
            const { wrapper, queryClient } = createWrapper();
            const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
            useUIStore.setState({ activeModal: 'delete-secret', modalData: { id: 7 } });

            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.deleteMutation.mutate(7));
            await waitFor(() => expect(result.current.deleteMutation.isSuccess).toBe(true));

            expect(mocks.secretsDelete).toHaveBeenCalledWith(7);
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
            expect(result.current.activeModal).toBeNull();
        });

        it('rotateMutation calls secretsApi.rotate, closes the modal, and invalidates secrets.all', async () => {
            const { wrapper, queryClient } = createWrapper();
            const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
            useUIStore.setState({ activeModal: 'rotate-secret', modalData: { id: 3 } });

            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.rotateMutation.mutate({ id: 3, newValue: 'fresh-value' }));
            await waitFor(() => expect(result.current.rotateMutation.isSuccess).toBe(true));

            expect(mocks.secretsRotate).toHaveBeenCalledWith(3, 'fresh-value');
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
            expect(result.current.activeModal).toBeNull();
        });

        it('bulkDeleteMutation deletes each id, clears selection/bulk mode, closes the modal, and invalidates', async () => {
            const { wrapper, queryClient } = createWrapper();
            const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
            useUIStore.setState({ activeModal: 'bulk-delete', modalData: null });

            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => {
                result.current.toggleSelectedItem(1);
                result.current.toggleSelectedItem(2);
                result.current.setBulkActionMode(true);
            });
            expect(result.current.selectedItems).toEqual(new Set([1, 2]));
            expect(result.current.bulkActionMode).toBe(true);

            act(() => result.current.bulkDeleteMutation.mutate([1, 2]));
            await waitFor(() => expect(result.current.bulkDeleteMutation.isSuccess).toBe(true));

            expect(mocks.secretsDelete).toHaveBeenCalledWith(1);
            expect(mocks.secretsDelete).toHaveBeenCalledWith(2);
            expect(result.current.selectedItems).toEqual(new Set());
            expect(result.current.bulkActionMode).toBe(false);
            expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: queryKeys.secrets.all });
            expect(result.current.activeModal).toBeNull();
        });
    });

    describe('bulk selection helpers', () => {
        it('toggleSelectedItem adds/removes ids; clearSelectedItems empties the set', async () => {
            const { wrapper } = createWrapper();
            const { result } = renderHook(() => useSecretsList(), { wrapper });
            await waitFor(() => expect(result.current.isLoading).toBe(false));

            act(() => result.current.toggleSelectedItem(5));
            expect(result.current.selectedItems).toEqual(new Set([5]));

            act(() => result.current.toggleSelectedItem(5));
            expect(result.current.selectedItems).toEqual(new Set());

            act(() => {
                result.current.toggleSelectedItem(1);
                result.current.toggleSelectedItem(2);
            });
            expect(result.current.selectedItems).toEqual(new Set([1, 2]));

            act(() => result.current.clearSelectedItems());
            expect(result.current.selectedItems).toEqual(new Set());
        });
    });
});
