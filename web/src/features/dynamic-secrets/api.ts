import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { dynamicSecretsApi, CreateDynamicConfigPayload } from '../../services/dynamicSecrets';

// ADR-035 query keys. Configs are scoped per (project, environment); leases per config.
export const DYNAMIC_SECRET_KEYS = {
    all: ['dynamic-secrets'] as const,
    list: (projectId: number, environmentId?: number) =>
        [...DYNAMIC_SECRET_KEYS.all, 'list', projectId, environmentId ?? 0] as const,
    leases: (configId: number) => [...DYNAMIC_SECRET_KEYS.all, 'leases', configId] as const,
};

export function useDynamicConfigs(projectId: number, environmentId?: number) {
    return useQuery({
        queryKey: DYNAMIC_SECRET_KEYS.list(projectId, environmentId),
        queryFn: () => dynamicSecretsApi.list(projectId, environmentId),
        enabled: !!projectId,
        staleTime: 30_000,
        retry: false, // a 403 for users without secrets.read shouldn't thrash
    });
}

export function useDynamicLeases(configId: number, enabled = true) {
    return useQuery({
        queryKey: DYNAMIC_SECRET_KEYS.leases(configId),
        queryFn: () => dynamicSecretsApi.listLeases(configId),
        enabled: enabled && !!configId,
        staleTime: 10_000,
    });
}

export function useCreateDynamicConfig() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (payload: CreateDynamicConfigPayload) => dynamicSecretsApi.create(payload),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: DYNAMIC_SECRET_KEYS.all }),
    });
}

export function useClassifyDynamicConfig() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, classification }: { id: number; classification: string }) =>
            dynamicSecretsApi.classify(id, classification),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: DYNAMIC_SECRET_KEYS.all }),
    });
}

export function useIssueLease(configId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (ttlSeconds?: number) => dynamicSecretsApi.issue(configId, ttlSeconds),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: DYNAMIC_SECRET_KEYS.leases(configId) }),
    });
}

export function useRevokeLease(configId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (leaseId: string) => dynamicSecretsApi.revokeLease(leaseId),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: DYNAMIC_SECRET_KEYS.leases(configId) }),
    });
}

export function useRevokeAllLeases(configId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: () => dynamicSecretsApi.revokeAll(configId),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: DYNAMIC_SECRET_KEYS.leases(configId) }),
    });
}
