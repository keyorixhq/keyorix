import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { machineIdentitiesApi, MachineAction, MachineIdentityType } from '../../services/machineIdentities';
import { SENSITIVE_GC_TIME } from '../../lib/queryClient';

// ADR-023 query keys, namespaced per project.
export const MACHINE_IDENTITY_KEYS = {
    all: ['machine-identities'] as const,
    list: (projectId: number) => [...MACHINE_IDENTITY_KEYS.all, 'list', projectId] as const,
    tokens: (projectId: number, machineId: number) =>
        [...MACHINE_IDENTITY_KEYS.all, 'tokens', projectId, machineId] as const,
};

export function useMachineIdentities(projectId: number) {
    return useQuery({
        queryKey: MACHINE_IDENTITY_KEYS.list(projectId),
        queryFn: () => machineIdentitiesApi.list(projectId),
        enabled: !!projectId,
        staleTime: 30_000,
        retry: false, // a 403 for users without users.read shouldn't thrash
    });
}

export function useCreateMachineIdentity(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({
            name,
            identityType,
            description,
        }: {
            name: string;
            identityType: MachineIdentityType;
            description?: string;
        }) => machineIdentitiesApi.create(projectId, name, identityType, description),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: MACHINE_IDENTITY_KEYS.list(projectId) }),
    });
}

export function useTransitionMachineIdentity(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ machineId, action }: { machineId: number; action: MachineAction }) =>
            machineIdentitiesApi.transition(projectId, machineId, action),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: MACHINE_IDENTITY_KEYS.list(projectId) }),
    });
}

export function useClassifyMachineIdentity(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ machineId, classification }: { machineId: number; classification: string }) =>
            machineIdentitiesApi.classify(projectId, machineId, classification),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: MACHINE_IDENTITY_KEYS.list(projectId) }),
    });
}

export function useMachineTokens(projectId: number, machineId: number, enabled = true) {
    return useQuery({
        queryKey: MACHINE_IDENTITY_KEYS.tokens(projectId, machineId),
        queryFn: () => machineIdentitiesApi.listTokens(projectId, machineId),
        enabled: enabled && !!projectId && !!machineId,
        staleTime: 15_000,
    });
}

export function useIssueMachineToken(projectId: number, machineId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (opts: { name: string; expiresInDays?: number; classification?: string }) =>
            machineIdentitiesApi.issueToken(projectId, machineId, opts),
        onSuccess: () =>
            queryClient.invalidateQueries({ queryKey: MACHINE_IDENTITY_KEYS.tokens(projectId, machineId) }),
        // G28: the response is a one-time bearer token — don't let react-query's
        // MutationCache retain it for the default 5 minutes after unmount.
        gcTime: SENSITIVE_GC_TIME,
    });
}

export function useRevokeMachineToken(projectId: number, machineId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (tokenId: number) => machineIdentitiesApi.revokeToken(projectId, machineId, tokenId),
        onSuccess: () =>
            queryClient.invalidateQueries({ queryKey: MACHINE_IDENTITY_KEYS.tokens(projectId, machineId) }),
    });
}

export function useClassifyMachineToken(projectId: number, machineId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ tokenId, classification }: { tokenId: number; classification: string }) =>
            machineIdentitiesApi.classifyToken(projectId, machineId, tokenId, classification),
        onSuccess: () =>
            queryClient.invalidateQueries({ queryKey: MACHINE_IDENTITY_KEYS.tokens(projectId, machineId) }),
    });
}
