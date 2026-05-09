import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { serviceAccountsApi } from '../../services/serviceAccounts';

const SA_KEY = 'service-accounts';
const TOKEN_KEY = 'service-account-tokens';

export const useServiceAccounts = () =>
    useQuery({
        queryKey: [SA_KEY],
        queryFn: () => serviceAccountsApi.listServiceAccounts(),
        staleTime: 2 * 60 * 1000,
    });

export const useCreateServiceAccount = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: serviceAccountsApi.createServiceAccount,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [SA_KEY] }),
    });
};

export const useUpdateServiceAccount = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({
            id,
            body,
        }: {
            id: number;
            body: { name?: string; description?: string; scopes?: string };
        }) => serviceAccountsApi.updateServiceAccount(id, body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [SA_KEY] }),
    });
};

export const useDeactivateServiceAccount = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => serviceAccountsApi.deactivateServiceAccount(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [SA_KEY] }),
    });
};

export const useServiceAccountTokens = (serviceAccountId: number | null) =>
    useQuery({
        queryKey: [TOKEN_KEY, serviceAccountId],
        queryFn: () => serviceAccountsApi.listTokens(serviceAccountId!),
        enabled: serviceAccountId !== null,
        staleTime: 60 * 1000,
    });

export const useCreateToken = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({
            serviceAccountId,
            body,
        }: {
            serviceAccountId: number;
            body: { description?: string; expires_at?: string };
        }) => serviceAccountsApi.createToken(serviceAccountId, body),
        onSuccess: (_data, { serviceAccountId }) => {
            queryClient.invalidateQueries({ queryKey: [TOKEN_KEY, serviceAccountId] });
        },
    });
};

export const useRevokeToken = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ tokenId }: { tokenId: number }) =>
            serviceAccountsApi.revokeToken(tokenId),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: [TOKEN_KEY] });
        },
    });
};
