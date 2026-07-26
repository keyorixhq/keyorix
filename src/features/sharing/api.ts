import { useQuery, useMutation, keepPreviousData } from '@tanstack/react-query';
import { sharingApi } from '../../services/sharing';
import { usersApi } from '../../services/users';
import { queryKeys, invalidateQueries } from '../../lib/queryClient';
import { ShareFormData } from '../../types';

export const useShares = (params?: {
    page?: number;
    pageSize?: number;
    secretId?: number;
    recipientType?: 'user' | 'group';
}) => {
    return useQuery({
        queryKey: queryKeys.sharing.list(params),
        queryFn: () => sharingApi.list(params),
        placeholderData: keepPreviousData,
    });
};

export const useDeleteShare = () => {
    return useMutation({
        mutationFn: (shareId: number) => sharingApi.delete(shareId),
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};

export const useBulkDeleteShares = () => {
    return useMutation({
        mutationFn: async (shareIds: number[]) => {
            await Promise.all(shareIds.map((id) => sharingApi.delete(id)));
            return shareIds;
        },
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};

// useUpdateShare changes a share's permission and/or its time-bound expiry.
export const useUpdateShare = () => {
    return useMutation({
        mutationFn: ({
            id,
            permission,
            expiresAt,
            clearExpiry,
        }: {
            id: number;
            permission: 'read' | 'write';
            expiresAt?: string;
            clearExpiry?: boolean;
        }) =>
            sharingApi.update(id, {
                permission,
                ...(expiresAt ? { expiresAt } : {}),
                ...(clearExpiry ? { clearExpiry } : {}),
            }),
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};

export const useCreateShare = () => {
    return useMutation({
        mutationFn: (data: ShareFormData & { secretId: number }) => sharingApi.create(data),
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};

// Plain async function — called imperatively inside form submit handlers.
// Lives here so components don't import directly from services/.
export const searchRecipients = (query: string) => usersApi.search(query);

// Composite mutation: search user by username then create share in one step.
export const useShareSecret = (secretId: number) => {
    return useMutation({
        mutationFn: async ({
            username,
            permission,
            expiresAt,
        }: {
            username: string;
            permission: 'read' | 'write';
            expiresAt?: string;
        }) => {
            const results = await usersApi.search(username.trim());
            const match = results.find((r) => r.name.toLowerCase() === username.trim().toLowerCase());
            if (!match) throw new Error(`User "${username}" not found.`);
            return sharingApi.create({
                secretId,
                recipientType: match.type,
                recipientId: match.id,
                permission,
                ...(expiresAt ? { expiresAt } : {}),
            });
        },
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });
};
