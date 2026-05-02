import { QueryClient, DefaultOptions } from '@tanstack/react-query';

// Default query options
const defaultOptions: DefaultOptions = {
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
        // Retry mutations once
        retry: 1,
        retryDelay: 1000,
    },
};

// Create query client with custom configuration
export const queryClient = new QueryClient({
    defaultOptions,
});

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
            queryFn: () => import('../services/api').then(({ apiService }) => apiService.secrets.get(id)),
            staleTime: 2 * 60 * 1000, // 2 minutes
        });
    },

    userSearch: (query: string) => {
        if (query.length < 2) return;
        return queryClient.prefetchQuery({
            queryKey: queryKeys.users.search(query),
            queryFn: () => import('../services/api').then(({ apiService }) => apiService.users.search(query)),
            staleTime: 30 * 1000, // 30 seconds
        });
    },

    groupSearch: (query: string) => {
        if (query.length < 2) return;
        return queryClient.prefetchQuery({
            queryKey: queryKeys.groups.search(query),
            queryFn: () => import('../services/api').then(({ apiService }) => apiService.groups.search(query)),
            staleTime: 30 * 1000, // 30 seconds
        });
    },
};