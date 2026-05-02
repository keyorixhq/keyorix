import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../services/api';
import { queryKeys, invalidateQueries } from '../lib/queryClient';
import { Secret, SecretFormData, SecretFilters, PaginatedResponse } from '../types';

// Hook for fetching secrets list
export const useSecrets = (params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    type?: string;
    namespace?: string;
    zone?: string;
    environment?: string;
    tags?: string[];
}) => {
    return useQuery({
        queryKey: queryKeys.secrets.list(params),
        queryFn: () => apiService.secrets.list(params),
        keepPreviousData: true,
    });
};

// Hook for fetching a single secret
export const useSecret = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.secrets.detail(id),
        queryFn: () => apiService.secrets.get(id),
        enabled,
    });
};

// Hook for fetching secret versions
export const useSecretVersions = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.secrets.versions(id),
        queryFn: () => apiService.secrets.getVersions(id),
        enabled,
    });
};

// Hook for creating a secret
export const useCreateSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (data: SecretFormData) => apiService.secrets.create(data),
        onSuccess: (newSecret) => {
            // Invalidate and refetch secrets list
            invalidateQueries.secrets.all();

            // Add the new secret to the cache
            queryClient.setQueryData(
                queryKeys.secrets.detail(newSecret.id),
                newSecret
            );
        },
    });
};

// Hook for updating a secret
export const useUpdateSecret = (id: number) => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (data: Partial<SecretFormData>) => apiService.secrets.update(id, data),
        onSuccess: (updatedSecret) => {
            // Update the secret in cache
            queryClient.setQueryData(
                queryKeys.secrets.detail(id),
                updatedSecret
            );

            // Invalidate secrets list to reflect changes
            invalidateQueries.secrets.lists();
        },
    });
};

// Hook for deleting a secret
export const useDeleteSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (id: number) => apiService.secrets.delete(id),
        onSuccess: (_, deletedId) => {
            // Remove from cache
            queryClient.removeQueries({
                queryKey: queryKeys.secrets.detail(deletedId)
            });

            // Invalidate secrets list
            invalidateQueries.secrets.all();
        },
    });
};

// Hook for bulk operations
export const useBulkDeleteSecrets = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (secretIds: number[]) => {
            // Delete secrets in parallel
            await Promise.all(
                secretIds.map(id => apiService.secrets.delete(id))
            );
            return secretIds;
        },
        onSuccess: (deletedIds) => {
            // Remove from cache
            deletedIds.forEach(id => {
                queryClient.removeQueries({
                    queryKey: queryKeys.secrets.detail(id)
                });
            });

            // Invalidate secrets list
            invalidateQueries.secrets.all();
        },
    });
};

// Hook for duplicating a secret
export const useDuplicateSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async ({ originalId, newData }: { originalId: number; newData: Partial<SecretFormData> }) => {
            // First get the original secret
            const original = await apiService.secrets.get(originalId);

            // Create new secret with modified data
            const duplicateData: SecretFormData = {
                name: newData.name || `${original.name}-copy`,
                value: original.value,
                type: newData.type || original.type,
                namespace: newData.namespace || original.namespace,
                zone: newData.zone || original.zone,
                environment: newData.environment || original.environment,
                metadata: { ...original.metadata, ...newData.metadata },
                tags: newData.tags || original.tags,
            };

            return apiService.secrets.create(duplicateData);
        },
        onSuccess: (newSecret) => {
            // Add to cache
            queryClient.setQueryData(
                queryKeys.secrets.detail(newSecret.id),
                newSecret
            );

            // Invalidate secrets list
            invalidateQueries.secrets.all();
        },
    });
};

// Hook for searching secrets with debouncing
export const useSearchSecrets = (query: string, delay = 300) => {
    const [debouncedQuery, setDebouncedQuery] = React.useState(query);

    React.useEffect(() => {
        const timer = setTimeout(() => {
            setDebouncedQuery(query);
        }, delay);

        return () => clearTimeout(timer);
    }, [query, delay]);

    return useQuery({
        queryKey: queryKeys.secrets.list({ search: debouncedQuery }),
        queryFn: () => apiService.secrets.list({ search: debouncedQuery }),
        enabled: debouncedQuery.length >= 2, // Only search if query is at least 2 characters
        keepPreviousData: true,
    });
};

// Hook for getting secret statistics
export const useSecretStats = () => {
    return useQuery({
        queryKey: ['secrets', 'stats'],
        queryFn: async () => {
            const response = await apiService.secrets.list({ pageSize: 1 });
            return {
                total: response.total,
                // Could add more stats here
            };
        },
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
};

// Hook for prefetching secret details
export const usePrefetchSecret = () => {
    const queryClient = useQueryClient();

    return React.useCallback((id: number) => {
        queryClient.prefetchQuery({
            queryKey: queryKeys.secrets.detail(id),
            queryFn: () => apiService.secrets.get(id),
            staleTime: 2 * 60 * 1000, // 2 minutes
        });
    }, [queryClient]);
};

// Hook for optimistic updates
export const useOptimisticSecretUpdate = (id: number) => {
    const queryClient = useQueryClient();

    return React.useCallback((updatedData: Partial<Secret>) => {
        queryClient.setQueryData(
            queryKeys.secrets.detail(id),
            (oldData: Secret | undefined) => {
                if (!oldData) return oldData;
                return { ...oldData, ...updatedData };
            }
        );
    }, [queryClient, id]);
};