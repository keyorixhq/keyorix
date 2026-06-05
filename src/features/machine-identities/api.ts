import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
    machineIdentitiesApi,
    MachineAction,
    MachineIdentityType,
} from '../../services/machineIdentities';

// ADR-023 query keys, namespaced per project.
export const MACHINE_IDENTITY_KEYS = {
    all: ['machine-identities'] as const,
    list: (projectId: number) => [...MACHINE_IDENTITY_KEYS.all, 'list', projectId] as const,
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
        onSuccess: () =>
            queryClient.invalidateQueries({ queryKey: MACHINE_IDENTITY_KEYS.list(projectId) }),
    });
}

export function useTransitionMachineIdentity(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ machineId, action }: { machineId: number; action: MachineAction }) =>
            machineIdentitiesApi.transition(projectId, machineId, action),
        onSuccess: () =>
            queryClient.invalidateQueries({ queryKey: MACHINE_IDENTITY_KEYS.list(projectId) }),
    });
}
