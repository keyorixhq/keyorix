import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { dynamicSecretsApi, CreateDynamicConfigPayload } from '../../services/dynamicSecrets';
import { SENSITIVE_GC_TIME } from '../../lib/queryClient';

// ADR-035 query keys. Configs are scoped per (project, environment); leases per config.
export const DYNAMIC_SECRET_KEYS = {
    all: ['dynamic-secrets'] as const,
    list: (projectId: number, environmentId?: number) =>
        [...DYNAMIC_SECRET_KEYS.all, 'list', projectId, environmentId ?? 0] as const,
    leases: (configId: number) => [...DYNAMIC_SECRET_KEYS.all, 'leases', configId] as const,
    // Keys carry ids only: never a DSN (the admin-DSN update is a mutation, not a query).
    refusedAdminDsn: (projectId: number) => [...DYNAMIC_SECRET_KEYS.all, 'refused-admin-dsn', projectId] as const,
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

// The project's configs whose stored admin DSN names a refused option. The server needs
// dynamic-secret admin authority for it (403 otherwise), so callers pass `enabled` only for
// roles that can manage configs, and a 403 is not retried.
export function useRefusedAdminDsn(projectId: number, enabled = true) {
    return useQuery({
        queryKey: DYNAMIC_SECRET_KEYS.refusedAdminDsn(projectId),
        queryFn: () => dynamicSecretsApi.listRefusedAdminDsn(projectId),
        enabled: enabled && !!projectId,
        staleTime: 30_000,
        retry: false,
    });
}

// Replaces a config's admin DSN. The DSN is a secret: it is only ever the mutation variable
// (never a query key or a cached response), a failure surfaces as an AdminDsnUpdateError with
// the DSN scrubbed, and gcTime 0 drops the mutation (and its variables) as soon as the form
// unmounts. Success invalidates every dynamic-secrets query, which refreshes both the
// configs list and the refused-DSN report.
export function useUpdateDynamicConfigAdminDSN() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, adminDsn }: { id: number; adminDsn: string }) =>
            dynamicSecretsApi.updateAdminDsn(id, adminDsn),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: DYNAMIC_SECRET_KEYS.all }),
        // 'forbidden' covers a config that is gone as well as a missing authority (they read
        // the same, INV-WEB-06): refresh the lists so a deleted config stops being offered.
        onError: (error) => {
            if ((error as { kind?: string }).kind === 'forbidden') {
                void queryClient.invalidateQueries({ queryKey: DYNAMIC_SECRET_KEYS.all });
            }
        },
        gcTime: SENSITIVE_GC_TIME,
    });
}

export function useIssueLease(configId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (ttlSeconds?: number) => dynamicSecretsApi.issue(configId, ttlSeconds),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: DYNAMIC_SECRET_KEYS.leases(configId) }),
        // G28: the response is a one-time credential (often a password) — don't
        // let react-query's MutationCache retain it for the default 5 minutes
        // after unmount.
        gcTime: SENSITIVE_GC_TIME,
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
