import { describe, it, expect, vi, afterEach } from 'vitest';

// Mock the three services queryClient.ts imports for its prefetchQueries
// helpers, so prefetching doesn't make real network calls.
vi.mock('../../services/secrets', () => ({
    secretsApi: { get: vi.fn() },
}));
vi.mock('../../services/users', () => ({
    usersApi: { search: vi.fn() },
}));
vi.mock('../../services/groups', () => ({
    groupsApi: { search: vi.fn() },
}));

import { queryClient, queryKeys, invalidateQueries, prefetchQueries } from '../queryClient';
import { secretsApi } from '../../services/secrets';
import { usersApi } from '../../services/users';
import { groupsApi } from '../../services/groups';

describe('defaultOptions.queries.retry', () => {
    const retry = queryClient.getDefaultOptions().queries?.retry as (failureCount: number, error: unknown) => boolean;

    it('does not retry on a 4xx client error', () => {
        expect(retry(0, { response: { status: 404 } })).toBe(false);
        expect(retry(0, { response: { status: 400 } })).toBe(false);
        expect(retry(0, { response: { status: 499 } })).toBe(false);
    });

    it('retries a non-4xx error (e.g. 5xx or no response) up to 3 attempts', () => {
        expect(retry(0, { response: { status: 500 } })).toBe(true);
        expect(retry(2, { response: { status: 500 } })).toBe(true);
        expect(retry(3, { response: { status: 500 } })).toBe(false);
    });

    it('retries when the error has no response at all (network failure)', () => {
        expect(retry(0, new Error('network down'))).toBe(true);
        expect(retry(0, undefined)).toBe(true);
    });

    it('does not retry at the 500 boundary (5xx is not in the 400-499 range, so it still retries)', () => {
        // 500 itself is >= 500 so the 4xx short-circuit is false; confirms the
        // upper bound of the "don't retry" range is exclusive.
        expect(retry(0, { response: { status: 500 } })).toBe(true);
    });
});

describe('defaultOptions.queries.retryDelay', () => {
    const retryDelay = queryClient.getDefaultOptions().queries?.retryDelay as (attemptIndex: number) => number;

    it('backs off exponentially', () => {
        expect(retryDelay(0)).toBe(1000);
        expect(retryDelay(1)).toBe(2000);
        expect(retryDelay(2)).toBe(4000);
    });

    it('caps the delay at 30 seconds', () => {
        expect(retryDelay(10)).toBe(30000);
    });
});

describe('defaultOptions.mutations', () => {
    it('retries mutations once with a fixed 1s delay', () => {
        const mutationDefaults = queryClient.getDefaultOptions().mutations;
        expect(mutationDefaults?.retry).toBe(1);
        expect(mutationDefaults?.retryDelay).toBe(1000);
    });
});

describe('queryKeys factory', () => {
    it('builds secrets keys', () => {
        expect(queryKeys.secrets.all).toEqual(['secrets']);
        expect(queryKeys.secrets.lists()).toEqual(['secrets', 'list']);
        expect(queryKeys.secrets.list({ page: 1 })).toEqual(['secrets', 'list', { page: 1 }]);
        expect(queryKeys.secrets.details()).toEqual(['secrets', 'detail']);
        expect(queryKeys.secrets.detail(5)).toEqual(['secrets', 'detail', 5]);
        expect(queryKeys.secrets.versions(5)).toEqual(['secrets', 'detail', 5, 'versions']);
    });

    it('builds sharing keys', () => {
        expect(queryKeys.sharing.all).toEqual(['sharing']);
        expect(queryKeys.sharing.lists()).toEqual(['sharing', 'list']);
        expect(queryKeys.sharing.list()).toEqual(['sharing', 'list', undefined]);
        expect(queryKeys.sharing.details()).toEqual(['sharing', 'detail']);
        expect(queryKeys.sharing.detail(7)).toEqual(['sharing', 'detail', 7]);
    });

    it('builds users keys, including search', () => {
        expect(queryKeys.users.all).toEqual(['users']);
        expect(queryKeys.users.lists()).toEqual(['users', 'list']);
        expect(queryKeys.users.details()).toEqual(['users', 'detail']);
        expect(queryKeys.users.detail(3)).toEqual(['users', 'detail', 3]);
        expect(queryKeys.users.search('ali')).toEqual(['users', 'search', 'ali']);
    });

    it('builds groups keys, including search', () => {
        expect(queryKeys.groups.all).toEqual(['groups']);
        expect(queryKeys.groups.lists()).toEqual(['groups', 'list']);
        expect(queryKeys.groups.details()).toEqual(['groups', 'detail']);
        expect(queryKeys.groups.detail(9)).toEqual(['groups', 'detail', 9]);
        expect(queryKeys.groups.search('eng')).toEqual(['groups', 'search', 'eng']);
    });

    it('builds dashboard and admin keys', () => {
        expect(queryKeys.dashboard.all).toEqual(['dashboard']);
        expect(queryKeys.dashboard.stats()).toEqual(['dashboard', 'stats']);
        expect(queryKeys.dashboard.activity({ range: '7d' })).toEqual(['dashboard', 'activity', { range: '7d' }]);
        expect(queryKeys.admin.all).toEqual(['admin']);
        expect(queryKeys.admin.stats()).toEqual(['admin', 'stats']);
        expect(queryKeys.admin.roles()).toEqual(['admin', 'roles']);
    });
});

describe('invalidateQueries helpers', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('invalidates secrets caches with the matching queryKey', () => {
        const spy = vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue(undefined);

        invalidateQueries.secrets.all();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.secrets.all });

        invalidateQueries.secrets.lists();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.secrets.lists() });

        invalidateQueries.secrets.detail(5);
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.secrets.detail(5) });
    });

    it('invalidates sharing caches with the matching queryKey', () => {
        const spy = vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue(undefined);

        invalidateQueries.sharing.all();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.sharing.all });

        invalidateQueries.sharing.lists();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.sharing.lists() });

        invalidateQueries.sharing.detail(7);
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.sharing.detail(7) });
    });

    it('invalidates users caches, including the ad-hoc search-prefix key', () => {
        const spy = vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue(undefined);

        invalidateQueries.users.all();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.users.all });

        invalidateQueries.users.search();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: [...queryKeys.users.all, 'search'] });
    });

    it('invalidates groups caches, including the ad-hoc search-prefix key', () => {
        const spy = vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue(undefined);

        invalidateQueries.groups.all();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.groups.all });

        invalidateQueries.groups.search();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: [...queryKeys.groups.all, 'search'] });
    });

    it('invalidates dashboard caches with the matching queryKey', () => {
        const spy = vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue(undefined);

        invalidateQueries.dashboard.all();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.dashboard.all });

        invalidateQueries.dashboard.stats();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.dashboard.stats() });
    });

    it('invalidates the admin cache with the matching queryKey', () => {
        const spy = vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue(undefined);

        invalidateQueries.admin.all();
        expect(spy).toHaveBeenLastCalledWith({ queryKey: queryKeys.admin.all });
    });
});

describe('prefetchQueries helpers', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        queryClient.clear();
    });

    it('secretDetail prefetches by id via secretsApi.get', async () => {
        vi.mocked(secretsApi.get).mockResolvedValueOnce({ id: 5, name: 'db-password' } as never);

        await prefetchQueries.secretDetail(5);

        expect(secretsApi.get).toHaveBeenCalledWith(5);
        expect(queryClient.getQueryData(queryKeys.secrets.detail(5))).toEqual({ id: 5, name: 'db-password' });
    });

    it('userSearch skips prefetching for a too-short query (under 2 chars)', async () => {
        const result = await prefetchQueries.userSearch('a');

        expect(result).toBeUndefined();
        expect(usersApi.search).not.toHaveBeenCalled();
    });

    it('userSearch prefetches once the query reaches 2 characters', async () => {
        vi.mocked(usersApi.search).mockResolvedValueOnce([{ id: 1, name: 'ali' }] as never);

        await prefetchQueries.userSearch('al');

        expect(usersApi.search).toHaveBeenCalledWith('al');
        expect(queryClient.getQueryData(queryKeys.users.search('al'))).toEqual([{ id: 1, name: 'ali' }]);
    });

    it('groupSearch skips prefetching for a too-short query (under 2 chars)', async () => {
        const result = await prefetchQueries.groupSearch('e');

        expect(result).toBeUndefined();
        expect(groupsApi.search).not.toHaveBeenCalled();
    });

    it('groupSearch prefetches once the query reaches 2 characters', async () => {
        vi.mocked(groupsApi.search).mockResolvedValueOnce([{ id: 2, name: 'eng' }] as never);

        await prefetchQueries.groupSearch('en');

        expect(groupsApi.search).toHaveBeenCalledWith('en');
        expect(queryClient.getQueryData(queryKeys.groups.search('en'))).toEqual([{ id: 2, name: 'eng' }]);
    });
});
