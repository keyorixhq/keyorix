import { useQuery } from '@tanstack/react-query';
import { secretsApi } from '../../services/secrets';

export function useMostAccessedSecrets(params?: { days?: number; limit?: number; projectId?: number }) {
    const { data, isLoading, error } = useQuery({
        queryKey: ['secrets', 'usage', 'most-accessed', params],
        queryFn: () => secretsApi.mostAccessed(params),
        staleTime: 2 * 60 * 1000,
    });
    return { secrets: data ?? [], isLoading, error };
}

export function useUnusedSecrets(params?: { days?: number; projectId?: number }) {
    const { data, isLoading, error } = useQuery({
        queryKey: ['secrets', 'usage', 'unused', params],
        queryFn: () => secretsApi.unused(params),
        staleTime: 2 * 60 * 1000,
    });
    return { secrets: data ?? [], isLoading, error };
}
