import React from 'react';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { secretsApi } from '../../services/secrets';
import { queryKeys, invalidateQueries } from '../../lib/queryClient';
import { Secret, SecretFormData } from '../../types';

export const useSecrets = (params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    type?: string;
    environment?: string;
    tags?: string[];
}) => {
    return useQuery({
        queryKey: queryKeys.secrets.list(params),
        queryFn: () => secretsApi.list(params),
        placeholderData: keepPreviousData,
    });
};

export const useSecret = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.secrets.detail(id),
        queryFn: () => secretsApi.get(id),
        enabled,
    });
};

export const useSecretVersions = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.secrets.versions(id),
        queryFn: () => secretsApi.getVersions(id),
        enabled,
    });
};

export const useCreateSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (data: SecretFormData) => secretsApi.create(data),
        onSuccess: (newSecret) => {
            invalidateQueries.secrets.all();
            queryClient.setQueryData(queryKeys.secrets.detail(newSecret.id), newSecret);
        },
    });
};

export const useUpdateSecret = (id: number) => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (data: Partial<SecretFormData>) => secretsApi.update(id, data),
        onSuccess: (updatedSecret) => {
            queryClient.setQueryData(queryKeys.secrets.detail(id), updatedSecret);
            invalidateQueries.secrets.lists();
        },
    });
};

export const useDeleteSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (id: number) => secretsApi.delete(id),
        onSuccess: (_, deletedId) => {
            queryClient.removeQueries({ queryKey: queryKeys.secrets.detail(deletedId) });
            invalidateQueries.secrets.all();
        },
    });
};

export const useBulkDeleteSecrets = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (secretIds: number[]) => {
            await Promise.all(secretIds.map(id => secretsApi.delete(id)));
            return secretIds;
        },
        onSuccess: (deletedIds) => {
            deletedIds.forEach(id => {
                queryClient.removeQueries({ queryKey: queryKeys.secrets.detail(id) });
            });
            invalidateQueries.secrets.all();
        },
    });
};

export const useDuplicateSecret = () => {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async ({ originalId, newData }: { originalId: number; newData: Partial<SecretFormData> }) => {
            const original = await secretsApi.get(originalId);
            const duplicateData: SecretFormData = {
                name: newData.name || `${original.name}-copy`,
                value: '',
                type: newData.type || original.type,
                environment: newData.environment || original.environment,
                metadata: { ...original.metadata, ...newData.metadata },
                tags: newData.tags || original.tags,
            };
            return secretsApi.create(duplicateData);
        },
        onSuccess: (newSecret) => {
            queryClient.setQueryData(queryKeys.secrets.detail(newSecret.id), newSecret);
            invalidateQueries.secrets.all();
        },
    });
};

export const useSearchSecrets = (query: string, delay = 300) => {
    const [debouncedQuery, setDebouncedQuery] = React.useState(query);

    React.useEffect(() => {
        const timer = setTimeout(() => { setDebouncedQuery(query); }, delay);
        return () => clearTimeout(timer);
    }, [query, delay]);

    return useQuery({
        queryKey: queryKeys.secrets.list({ search: debouncedQuery }),
        queryFn: () => secretsApi.list({ search: debouncedQuery }),
        enabled: debouncedQuery.length >= 2,
        placeholderData: keepPreviousData,
    });
};

export const useSecretStats = () => {
    return useQuery({
        queryKey: ['secrets', 'stats'],
        queryFn: async () => {
            const response = await secretsApi.list({ pageSize: 1 });
            return { total: response.total };
        },
        staleTime: 5 * 60 * 1000,
    });
};

export const usePrefetchSecret = () => {
    const queryClient = useQueryClient();

    return React.useCallback((id: number) => {
        queryClient.prefetchQuery({
            queryKey: queryKeys.secrets.detail(id),
            queryFn: () => secretsApi.get(id),
            staleTime: 2 * 60 * 1000,
        });
    }, [queryClient]);
};

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
