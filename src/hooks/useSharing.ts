import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../services/api';
import { queryKeys, invalidateQueries } from '../lib/queryClient';
import { ShareRecord, ShareFormData, PaginatedResponse, Recipient } from '../types';
import { useNotificationStore } from '../store/notificationStore';

// Query hooks for sharing
export const useShares = (params?: {
    page?: number;
    pageSize?: number;
    secretId?: number;
    recipientType?: 'user' | 'group';
}) => {
    return useQuery({
        queryKey: queryKeys.sharing.list(params),
        queryFn: () => apiService.sharing.list(params),
        enabled: true,
        staleTime: 2 * 60 * 1000, // 2 minutes
    });
};

export const useShare = (id: number, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.sharing.detail(id),
        queryFn: () => apiService.sharing.get(id),
        enabled: enabled && id > 0,
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
};

// User and group search hooks
export const useUserSearch = (query: string, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.users.search(query),
        queryFn: () => apiService.users.search(query),
        enabled: enabled && query.length >= 2,
        staleTime: 30 * 1000, // 30 seconds
        gcTime: 2 * 60 * 1000, // 2 minutes
    });
};

export const useGroupSearch = (query: string, enabled = true) => {
    return useQuery({
        queryKey: queryKeys.groups.search(query),
        queryFn: () => apiService.groups.search(query),
        enabled: enabled && query.length >= 2,
        staleTime: 30 * 1000, // 30 seconds
        gcTime: 2 * 60 * 1000, // 2 minutes
    });
};

// Combined recipient search hook
export const useRecipientSearch = (query: string, enabled = true) => {
    const userQuery = useUserSearch(query, enabled);
    const groupQuery = useGroupSearch(query, enabled);

    return {
        data: [
            ...(userQuery.data || []),
            ...(groupQuery.data || []),
        ] as Recipient[],
        isLoading: userQuery.isLoading || groupQuery.isLoading,
        error: userQuery.error || groupQuery.error,
        refetch: () => {
            userQuery.refetch();
            groupQuery.refetch();
        },
    };
};

// Mutation hooks for sharing
export const useCreateShare = () => {
    const queryClient = useQueryClient();
    const { addNotification } = useNotificationStore();

    return useMutation({
        mutationFn: (data: ShareFormData & { secretId: number }) =>
            apiService.sharing.create(data),
        onSuccess: (newShare) => {
            // Invalidate sharing lists
            invalidateQueries.sharing.lists();

            // Invalidate secrets to update share indicators
            invalidateQueries.secrets.detail(newShare.secretId);
            invalidateQueries.secrets.lists();

            // Add to cache
            queryClient.setQueryData(
                queryKeys.sharing.detail(newShare.id),
                newShare
            );

            addNotification({
                type: 'success',
                title: 'Secret Shared',
                message: `Secret has been shared with ${newShare.recipientName} successfully.`,
            });
        },
        onError: (error: any) => {
            addNotification({
                type: 'error',
                title: 'Failed to Share Secret',
                message: error.message || 'An error occurred while sharing the secret.',
            });
        },
    });
};

export const useUpdateShare = () => {
    const queryClient = useQueryClient();
    const { addNotification } = useNotificationStore();

    return useMutation({
        mutationFn: ({ id, data }: { id: number; data: Partial<ShareFormData> }) =>
            apiService.sharing.update(id, data),
        onMutate: async ({ id, data }) => {
            // Cancel any outgoing refetches
            await queryClient.cancelQueries({ queryKey: queryKeys.sharing.detail(id) });

            // Snapshot the previous value
            const previousShare = queryClient.getQueryData<ShareRecord>(queryKeys.sharing.detail(id));

            // Optimistically update the cache
            if (previousShare) {
                queryClient.setQueryData(queryKeys.sharing.detail(id), {
                    ...previousShare,
                    ...data,
                });
            }

            return { previousShare };
        },
        onSuccess: (updatedShare) => {
            // Update the cache with the server response
            queryClient.setQueryData(
                queryKeys.sharing.detail(updatedShare.id),
                updatedShare
            );

            // Invalidate lists to ensure consistency
            invalidateQueries.sharing.lists();

            addNotification({
                type: 'success',
                title: 'Share Updated',
                message: `Share permissions for ${updatedShare.recipientName} have been updated.`,
            });
        },
        onError: (error: any, { id }, context) => {
            // Rollback optimistic update
            if (context?.previousShare) {
                queryClient.setQueryData(queryKeys.sharing.detail(id), context.previousShare);
            }

            addNotification({
                type: 'error',
                title: 'Failed to Update Share',
                message: error.message || 'An error occurred while updating the share.',
            });
        },
    });
};

export const useDeleteShare = () => {
    const queryClient = useQueryClient();
    const { addNotification } = useNotificationStore();

    return useMutation({
        mutationFn: (id: number) => apiService.sharing.delete(id),
        onMutate: async (id) => {
            // Cancel any outgoing refetches
            await queryClient.cancelQueries({ queryKey: queryKeys.sharing.detail(id) });

            // Get the share info for the notification
            const share = queryClient.getQueryData<ShareRecord>(queryKeys.sharing.detail(id));

            // Optimistically remove from lists
            queryClient.setQueriesData(
                { queryKey: queryKeys.sharing.lists() },
                (old: PaginatedResponse<ShareRecord> | undefined) => {
                    if (!old) return old;
                    return {
                        ...old,
                        data: old.data.filter(s => s.id !== id),
                        total: old.total - 1,
                    };
                }
            );

            return { share };
        },
        onSuccess: (_, id, context) => {
            // Remove from cache
            queryClient.removeQueries({ queryKey: queryKeys.sharing.detail(id) });

            // Invalidate lists and related secrets
            invalidateQueries.sharing.lists();
            if (context?.share?.secretId) {
                invalidateQueries.secrets.detail(context.share.secretId);
                invalidateQueries.secrets.lists();
            }

            addNotification({
                type: 'success',
                title: 'Share Revoked',
                message: `Share with ${context?.share?.recipientName || 'recipient'} has been revoked.`,
            });
        },
        onError: (error: any) => {
            // Invalidate to refetch correct data
            invalidateQueries.sharing.all();

            addNotification({
                type: 'error',
                title: 'Failed to Revoke Share',
                message: error.message || 'An error occurred while revoking the share.',
            });
        },
    });
};

export const useSelfRemoveShare = () => {
    const queryClient = useQueryClient();
    const { addNotification } = useNotificationStore();

    return useMutation({
        mutationFn: (id: number) => apiService.sharing.selfRemove(id),
        onMutate: async (id) => {
            // Get the share info for the notification
            const share = queryClient.getQueryData<ShareRecord>(queryKeys.sharing.detail(id));

            // Optimistically remove from lists
            queryClient.setQueriesData(
                { queryKey: queryKeys.sharing.lists() },
                (old: PaginatedResponse<ShareRecord> | undefined) => {
                    if (!old) return old;
                    return {
                        ...old,
                        data: old.data.filter(s => s.id !== id),
                        total: old.total - 1,
                    };
                }
            );

            return { share };
        },
        onSuccess: (_, id, context) => {
            // Remove from cache
            queryClient.removeQueries({ queryKey: queryKeys.sharing.detail(id) });

            // Invalidate lists and related secrets
            invalidateQueries.sharing.lists();
            if (context?.share?.secretId) {
                invalidateQueries.secrets.detail(context.share.secretId);
                invalidateQueries.secrets.lists();
            }

            addNotification({
                type: 'success',
                title: 'Removed from Share',
                message: 'You have successfully removed yourself from this shared secret.',
            });
        },
        onError: (error: any) => {
            // Invalidate to refetch correct data
            invalidateQueries.sharing.all();

            addNotification({
                type: 'error',
                title: 'Failed to Remove from Share',
                message: error.message || 'An error occurred while removing yourself from the share.',
            });
        },
    });
};

// Bulk operations
export const useBulkDeleteShares = () => {
    const queryClient = useQueryClient();
    const { addNotification } = useNotificationStore();

    return useMutation({
        mutationFn: async (ids: number[]) => {
            // Delete shares in parallel
            await Promise.all(ids.map(id => apiService.sharing.delete(id)));
            return ids;
        },
        onSuccess: (deletedIds) => {
            // Remove from cache
            deletedIds.forEach(id => {
                queryClient.removeQueries({ queryKey: queryKeys.sharing.detail(id) });
            });

            // Invalidate lists and secrets
            invalidateQueries.sharing.lists();
            invalidateQueries.secrets.lists();

            addNotification({
                type: 'success',
                title: 'Shares Revoked',
                message: `${deletedIds.length} share(s) have been revoked successfully.`,
            });
        },
        onError: (error: any) => {
            addNotification({
                type: 'error',
                title: 'Failed to Revoke Shares',
                message: error.message || 'An error occurred while revoking the shares.',
            });
        },
    });
};