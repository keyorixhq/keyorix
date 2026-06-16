import { useQuery, useMutation } from '@tanstack/react-query';
import { connectApi } from '../../services/connect';

// Keyorix Connect data hooks (ADR-043). Listing connectors is a cached query;
// reading a federated secret is a mutation (an explicit, audited action — not
// prefetched/cached, so a value is fetched only on demand and never stored).

export const useConnectors = () =>
    useQuery({
        queryKey: ['connect-connectors'],
        queryFn: () => connectApi.listConnectors(),
        staleTime: 60 * 1000,
    });

export const useReadFederatedSecret = () =>
    useMutation({
        mutationFn: ({ connector, ref }: { connector: string; ref: string }) =>
            connectApi.readSecret(connector, ref),
    });
