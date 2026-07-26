import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { connectApi } from '../../services/connect';

// Keyorix Connect data hooks (ADR-043). Listing connectors is a cached query;
// reading a federated secret is a mutation (an explicit, audited action — not
// prefetched/cached, so a value is fetched only on demand and never stored).

const REF_GRANTS_KEY = ['connect-ref-grants'] as const;

export const useConnectors = () =>
    useQuery({
        queryKey: ['connect-connectors'],
        queryFn: () => connectApi.listConnectors(),
        staleTime: 60 * 1000,
    });

export const useReadFederatedSecret = () =>
    useMutation({
        mutationFn: ({ connector, ref }: { connector: string; ref: string }) => connectApi.readSecret(connector, ref),
    });

// Per-reference RBAC grants (ADR-045). The list is gated server-side by roles.read;
// create/delete by roles.write — a 403 for users without those surfaces as an error
// rather than thrashing retries.
export const useRefGrants = () =>
    useQuery({
        queryKey: REF_GRANTS_KEY,
        queryFn: () => connectApi.listRefGrants(),
        staleTime: 30 * 1000,
        retry: false,
    });

export const useCreateRefGrant = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ roleId, connector, refPrefix }: { roleId: number; connector: string; refPrefix: string }) =>
            connectApi.createRefGrant(roleId, connector, refPrefix),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: REF_GRANTS_KEY }),
    });
};

export const useDeleteRefGrant = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => connectApi.deleteRefGrant(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: REF_GRANTS_KEY }),
    });
};
