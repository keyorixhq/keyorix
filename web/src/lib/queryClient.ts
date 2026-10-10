import { QueryClient, DefaultOptions } from '@tanstack/react-query';
import { secretsApi } from '../services/secrets';
import { usersApi } from '../services/users';
import { groupsApi } from '../services/groups';

// queryClientDefaultOptions is exported so a test can build a throwaway QueryClient that
// provably carries the SAME policy the app runs with, instead of hand-copying it.
// #2738's reproduction depends on the mutation retry policy below, and a test that
// re-declared it locally would have gone green against a broken app.
export const queryClientDefaultOptions: DefaultOptions = {
    queries: {
        // Stale time: 5 minutes
        staleTime: 5 * 60 * 1000,
        // Cache time: 10 minutes
        gcTime: 10 * 60 * 1000,
        // Retry failed requests 3 times with exponential backoff
        retry: (failureCount, error: any) => {
            // Don't retry on 4xx errors (client errors)
            if (error?.response?.status >= 400 && error?.response?.status < 500) {
                return false;
            }
            // Retry up to 3 times for other errors
            return failureCount < 3;
        },
        retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
        // Refetch on window focus for important data
        refetchOnWindowFocus: true,
        // Refetch on reconnect
        refetchOnReconnect: true,
        // Don't refetch on mount if data is fresh
        refetchOnMount: true,
    },
    mutations: {
        // #2738: never retry a mutation the server has already reached a verdict on.
        // A 4xx is an answer, not a transient failure, and re-sending it has two
        // concrete costs:
        //
        //  1. It re-sends a non-idempotent POST. For the MFA re-auth endpoints
        //     (/auth/mfa/disable, /auth/mfa/activate, /auth/mfa/recovery-codes/
        //     regenerate -- all gated by internal/core's requireReauth, which calls
        //     recordFailedLogin on every rejection) ONE user click burned TWO
        //     per-account lockout slots, silently halving how many attempts an
        //     operator gets before the account locks.
        //  2. A retry is PAUSED whenever react-query's onlineManager reports
        //     offline (the default networkMode: 'online'), and a paused mutation's
        //     promise never settles: isPending stays true forever, no onError ever
        //     fires, and no request is ever sent. That is exactly the permanently
        //     stuck Disable-2FA dialog of #2738 -- spinner up, no error text, no
        //     further request, and (because the mutation object outlives the
        //     dialog) not cleared by closing and reopening it.
        //
        // Mirrors the queries policy above, which has always excluded 4xx.
        retry: (failureCount, error: any) => {
            if (error?.response?.status >= 400 && error?.response?.status < 500) {
                return false;
            }
            return failureCount < 1;
        },
        retryDelay: 1000,
    },
};

// Create query client with custom configuration
export const queryClient = new QueryClient({
    defaultOptions: queryClientDefaultOptions,
});

// Sensitive-data convention (G28 — secret plaintext lingers client-side with no
// auto-clear): any query or mutation whose response carries decrypted secret
// plaintext (a secret value, a one-time dynamic-secret/machine-token credential,
// a federated Connect read, an MFA recovery code, a personal access token, ...)
// MUST override `gcTime: SENSITIVE_GC_TIME` in its `useQuery`/`useMutation` call.
// Without it, react-query keeps the plaintext response in the QueryCache /
// MutationCache for the default gcTime above (10 min for queries, 5 min for
// mutations) after the last observer unmounts — long after the UI has hidden or
// re-masked the value. `0` evicts it as soon as the last observer goes away.
//
// This is intentionally opt-in per call site (not a global default): most
// queries/mutations return non-sensitive data, and lowering gcTime for all of
// them would hurt normal caching for no security benefit.
export const SENSITIVE_GC_TIME = 0;

// Query keys factory for consistent key management
export const queryKeys = {
    // Authentication
    auth: {
        profile: ['auth', 'profile'] as const,
    },

    // Secrets
    secrets: {
        all: ['secrets'] as const,
        lists: () => [...queryKeys.secrets.all, 'list'] as const,
        list: (params?: any) => [...queryKeys.secrets.lists(), params] as const,
        details: () => [...queryKeys.secrets.all, 'detail'] as const,
        detail: (id: number) => [...queryKeys.secrets.details(), id] as const,
        versions: (id: number) => [...queryKeys.secrets.detail(id), 'versions'] as const,
        value: (id: number) => [...queryKeys.secrets.detail(id), 'value'] as const,
    },

    // Sharing
    sharing: {
        all: ['sharing'] as const,
        lists: () => [...queryKeys.sharing.all, 'list'] as const,
        list: (params?: any) => [...queryKeys.sharing.lists(), params] as const,
        details: () => [...queryKeys.sharing.all, 'detail'] as const,
        detail: (id: number) => [...queryKeys.sharing.details(), id] as const,
    },

    // Users
    users: {
        all: ['users'] as const,
        lists: () => [...queryKeys.users.all, 'list'] as const,
        list: (params?: any) => [...queryKeys.users.lists(), params] as const,
        details: () => [...queryKeys.users.all, 'detail'] as const,
        detail: (id: number) => [...queryKeys.users.details(), id] as const,
        search: (query: string) => [...queryKeys.users.all, 'search', query] as const,
    },

    // Groups
    groups: {
        all: ['groups'] as const,
        lists: () => [...queryKeys.groups.all, 'list'] as const,
        list: (params?: any) => [...queryKeys.groups.lists(), params] as const,
        details: () => [...queryKeys.groups.all, 'detail'] as const,
        detail: (id: number) => [...queryKeys.groups.details(), id] as const,
        search: (query: string) => [...queryKeys.groups.all, 'search', query] as const,
    },

    // Dashboard
    dashboard: {
        all: ['dashboard'] as const,
        stats: () => [...queryKeys.dashboard.all, 'stats'] as const,
        activity: (params?: any) => [...queryKeys.dashboard.all, 'activity', params] as const,
    },

    // Admin
    admin: {
        all: ['admin'] as const,
        stats: () => [...queryKeys.admin.all, 'stats'] as const,
        users: (params?: any) => [...queryKeys.admin.all, 'users', params] as const,
        roles: () => [...queryKeys.admin.all, 'roles'] as const,
        audit: (params?: any) => [...queryKeys.admin.all, 'audit', params] as const,
    },
};

// Cache invalidation helpers
export const invalidateQueries = {
    secrets: {
        all: () => queryClient.invalidateQueries({ queryKey: queryKeys.secrets.all }),
        lists: () => queryClient.invalidateQueries({ queryKey: queryKeys.secrets.lists() }),
        detail: (id: number) => queryClient.invalidateQueries({ queryKey: queryKeys.secrets.detail(id) }),
    },
    sharing: {
        all: () => queryClient.invalidateQueries({ queryKey: queryKeys.sharing.all }),
        lists: () => queryClient.invalidateQueries({ queryKey: queryKeys.sharing.lists() }),
        detail: (id: number) => queryClient.invalidateQueries({ queryKey: queryKeys.sharing.detail(id) }),
    },
    users: {
        all: () => queryClient.invalidateQueries({ queryKey: queryKeys.users.all }),
        search: () => queryClient.invalidateQueries({ queryKey: [...queryKeys.users.all, 'search'] }),
    },
    groups: {
        all: () => queryClient.invalidateQueries({ queryKey: queryKeys.groups.all }),
        search: () => queryClient.invalidateQueries({ queryKey: [...queryKeys.groups.all, 'search'] }),
    },
    dashboard: {
        all: () => queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all }),
        stats: () => queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.stats() }),
    },
    admin: {
        all: () => queryClient.invalidateQueries({ queryKey: queryKeys.admin.all }),
    },
};

// Prefetch helpers for better UX
export const prefetchQueries = {
    secretDetail: (id: number) => {
        return queryClient.prefetchQuery({
            queryKey: queryKeys.secrets.detail(id),
            queryFn: () => secretsApi.get(id),
            staleTime: 2 * 60 * 1000,
        });
    },

    userSearch: (query: string) => {
        if (query.length < 2) return;
        return queryClient.prefetchQuery({
            queryKey: queryKeys.users.search(query),
            queryFn: () => usersApi.search(query),
            staleTime: 30 * 1000,
        });
    },

    groupSearch: (query: string) => {
        if (query.length < 2) return;
        return queryClient.prefetchQuery({
            queryKey: queryKeys.groups.search(query),
            queryFn: () => groupsApi.search(query),
            staleTime: 30 * 1000,
        });
    },
};
