import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    ShareIcon,
    UserIcon,
    UserGroupIcon,
    PencilIcon,
    TrashIcon,
    EyeIcon,
    MagnifyingGlassIcon,
    FunnelIcon,
    ClockIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { queryKeys, invalidateQueries } from '../../lib/queryClient';
import { useUIStore } from '../../store/uiStore';
import { usePreferencesStore } from '../../store/preferencesStore';
import { ShareRecord, PaginationState } from '../../types';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Dropdown } from '../../components/ui/Dropdown';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';

const ITEMS_PER_PAGE = 20;

const RECIPIENT_TYPE_OPTIONS = [
    { value: 'all', label: 'All Types' },
    { value: 'user', label: 'Users' },
    { value: 'group', label: 'Groups' },
];

const PERMISSION_OPTIONS = [
    { value: 'all', label: 'All Permissions' },
    { value: 'read', label: 'Read Only' },
    { value: 'write', label: 'Read & Write' },
];

export const SharingManagementPage: React.FC = () => {
    const { openModal, selectedItems, toggleSelectedItem, clearSelectedItems, bulkActionMode, setBulkActionMode } = useUIStore();
    const { getFormattedDate, getFormattedTime } = usePreferencesStore();
    const queryClient = useQueryClient();

    // State for filters and pagination
    const [filters, setFilters] = useState({
        search: '',
        recipientType: 'all',
        permission: 'all',
        secretId: undefined as number | undefined,
    });

    const [pagination, setPagination] = useState<PaginationState>({
        page: 1,
        pageSize: ITEMS_PER_PAGE,
        total: 0,
        totalPages: 0,
    });

    // Fetch shares with filters and pagination
    const { data, isLoading, error, refetch } = useQuery({
        queryKey: queryKeys.sharing.list({
            ...filters,
            page: pagination.page,
            pageSize: pagination.pageSize
        }),
        queryFn: () => apiService.sharing.list({
            page: pagination.page,
            pageSize: pagination.pageSize,
            secretId: filters.secretId,
            recipientType: filters.recipientType !== 'all' ? filters.recipientType as 'user' | 'group' : undefined,
        }),
        keepPreviousData: true,
    });

    // Update pagination when data changes
    React.useEffect(() => {
        if (data) {
            setPagination(prev => ({
                ...prev,
                total: data.total,
                totalPages: data.totalPages,
            }));
        }
    }, [data]);

    // Delete share mutation
    const deleteMutation = useMutation({
        mutationFn: (shareId: number) => apiService.sharing.delete(shareId),
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });

    // Bulk delete mutation
    const bulkDeleteMutation = useMutation({
        mutationFn: async (shareIds: number[]) => {
            await Promise.all(shareIds.map(id => apiService.sharing.delete(id)));
            return shareIds;
        },
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
            clearSelectedItems();
            setBulkActionMode(false);
        },
    });

    // Self-remove mutation
    const selfRemoveMutation = useMutation({
        mutationFn: (shareId: number) => apiService.sharing.selfRemove(shareId),
        onSuccess: () => {
            invalidateQueries.sharing.all();
            invalidateQueries.secrets.all();
        },
    });

    // Handle filter changes
    const handleFilterChange = (key: string, value: any) => {
        setFilters(prev => ({ ...prev, [key]: value }));
        setPagination(prev => ({ ...prev, page: 1 })); // Reset to first page
    };

    // Handle search with debouncing
    const [searchInput, setSearchInput] = useState(filters.search);
    React.useEffect(() => {
        const timer = setTimeout(() => {
            handleFilterChange('search', searchInput);
        }, 300);
        return () => clearTimeout(timer);
    }, [searchInput]);

    // Handle pagination
    const handlePageChange = (page: number) => {
        setPagination(prev => ({ ...prev, page }));
    };

    // Handle individual share actions
    const handleViewSecret = (share: ShareRecord) => {
        openModal('view-secret', { secretId: share.secretId });
    };

    const handleEditShare = (share: ShareRecord) => {
        openModal('edit-share', { share });
    };

    const handleDeleteShare = (share: ShareRecord) => {
        openModal('confirm-delete', {
            title: 'Delete Share',
            message: `Are you sure you want to revoke access for "${share.recipientName}"?`,
            onConfirm: () => deleteMutation.mutate(share.id),
        });
    };

    const handleSelfRemove = (share: ShareRecord) => {
        openModal('confirm-delete', {
            title: 'Remove Yourself',
            message: `Are you sure you want to remove your access to this secret?`,
            onConfirm: () => selfRemoveMutation.mutate(share.id),
        });
    };

    // Handle bulk actions
    const handleBulkDelete = () => {
        if (selectedItems.size === 0) return;

        openModal('confirm-delete', {
            title: 'Delete Multiple Shares',
            message: `Are you sure you want to revoke ${selectedItems.size} share(s)?`,
            onConfirm: () => bulkDeleteMutation.mutate(Array.from(selectedItems) as number[]),
        });
    };

    // Filter shares based on search
    const filteredShares = React.useMemo(() => {
        if (!data?.data) return [];

        let result = [...data.data];

        // Apply client-side search filter
        if (filters.search) {
            const searchLower = filters.search.toLowerCase();
            result = result.filter(share =>
                share.recipientName.toLowerCase().includes(searchLower) ||
                share.createdBy.toLowerCase().includes(searchLower)
            );
        }

        // Apply permission filter
        if (filters.permission !== 'all') {
            result = result.filter(share => share.permission === filters.permission);
        }

        return result;
    }, [data?.data, filters.search, filters.permission]);

    if (error) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load shares"
                    message="There was an error loading the sharing information. Please try again."
                    action={
                        <Button variant="outline" size="sm" onClick={() => refetch()}>
                            Retry
                        </Button>
                    }
                />
            </div>
        );
    }

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">
                        Sharing Management
                    </h1>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                        Manage secret sharing permissions and access
                    </p>
                </div>
                <div className="flex items-center space-x-3">
                    {bulkActionMode && (
                        <div className="flex items-center space-x-2">
                            <span className="text-sm text-gray-500 dark:text-gray-400">
                                {selectedItems.size} selected
                            </span>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={handleBulkDelete}
                                disabled={selectedItems.size === 0}
                                className="text-red-600 hover:text-red-700"
                            >
                                <TrashIcon className="h-4 w-4 mr-1" />
                                Revoke
                            </Button>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                    setBulkActionMode(false);
                                    clearSelectedItems();
                                }}
                            >
                                Cancel
                            </Button>
                        </div>
                    )}
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setBulkActionMode(!bulkActionMode)}
                    >
                        Select
                    </Button>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {/* Search */}
                    <div className="lg:col-span-2">
                        <Input
                            type="text"
                            placeholder="Search recipients or creators..."
                            value={searchInput}
                            onChange={(e) => setSearchInput(e.target.value)}
                            icon={MagnifyingGlassIcon}
                        />
                    </div>

                    {/* Recipient Type Filter */}
                    <div>
                        <Dropdown
                            value={filters.recipientType}
                            onChange={(value) => handleFilterChange('recipientType', value)}
                            options={RECIPIENT_TYPE_OPTIONS}
                            placeholder="Recipient Type"
                        />
                    </div>

                    {/* Permission Filter */}
                    <div>
                        <Dropdown
                            value={filters.permission}
                            onChange={(value) => handleFilterChange('permission', value)}
                            options={PERMISSION_OPTIONS}
                            placeholder="Permission"
                        />
                    </div>
                </div>

                {/* Active Filters */}
                {(filters.search || filters.recipientType !== 'all' || filters.permission !== 'all') && (
                    <div className="mt-4 flex items-center space-x-2">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Active filters:</span>
                        {filters.search && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                Search: {filters.search}
                            </span>
                        )}
                        {filters.recipientType !== 'all' && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                                Type: {filters.recipientType}
                            </span>
                        )}
                        {filters.permission !== 'all' && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
                                Permission: {filters.permission}
                            </span>
                        )}
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                                setFilters({
                                    search: '',
                                    recipientType: 'all',
                                    permission: 'all',
                                    secretId: undefined,
                                });
                                setSearchInput('');
                            }}
                            className="text-xs"
                        >
                            Clear all
                        </Button>
                    </div>
                )}
            </div>

            {/* Shares List */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                {isLoading ? (
                    <div className="p-8">
                        <Loading />
                    </div>
                ) : filteredShares.length === 0 ? (
                    <div className="p-8 text-center">
                        <div className="text-gray-400 dark:text-gray-500 mb-4">
                            <ShareIcon className="h-12 w-12 mx-auto" />
                        </div>
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                            No shares found
                        </h3>
                        <p className="text-gray-500 dark:text-gray-400">
                            {filters.search || filters.recipientType !== 'all' || filters.permission !== 'all'
                                ? 'Try adjusting your filters.'
                                : 'No secrets have been shared yet.'}
                        </p>
                    </div>
                ) : (
                    <div className="overflow-hidden">
                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-900">
                                <tr>
                                    {bulkActionMode && (
                                        <th className="px-6 py-3 text-left">
                                            <input
                                                type="checkbox"
                                                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                                checked={filteredShares.length > 0 && filteredShares.every(s => selectedItems.has(s.id))}
                                                onChange={(e) => {
                                                    if (e.target.checked) {
                                                        filteredShares.forEach(s => toggleSelectedItem(s.id));
                                                    } else {
                                                        clearSelectedItems();
                                                    }
                                                }}
                                            />
                                        </th>
                                    )}
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Secret
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Recipient
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Permission
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Shared By
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Created
                                    </th>
                                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                {filteredShares.map((share) => (
                                    <tr key={share.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                                        {bulkActionMode && (
                                            <td className="px-6 py-4">
                                                <input
                                                    type="checkbox"
                                                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                                    checked={selectedItems.has(share.id)}
                                                    onChange={() => toggleSelectedItem(share.id)}
                                                />
                                            </td>
                                        )}
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <div className="text-sm font-medium text-gray-900 dark:text-white">
                                                Secret #{share.secretId}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <div className="flex items-center">
                                                <div className="flex-shrink-0 mr-3">
                                                    {share.recipientType === 'user' ? (
                                                        <UserIcon className="h-5 w-5 text-gray-400" />
                                                    ) : (
                                                        <UserGroupIcon className="h-5 w-5 text-gray-400" />
                                                    )}
                                                </div>
                                                <div>
                                                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                                                        {share.recipientName}
                                                    </div>
                                                    <div className="text-xs text-gray-500 dark:text-gray-400">
                                                        {share.recipientType}
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${share.permission === 'write'
                                                    ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                                                    : 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                                                }`}>
                                                {share.permission === 'write' ? 'Read & Write' : 'Read Only'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                            {share.createdBy}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                            <div>
                                                <div>{getFormattedDate(share.createdAt)}</div>
                                                <div className="text-xs">{getFormattedTime(share.createdAt)}</div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                            <div className="flex items-center justify-end space-x-2">
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleViewSecret(share)}
                                                    title="View secret"
                                                >
                                                    <EyeIcon className="h-4 w-4" />
                                                </Button>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleEditShare(share)}
                                                    title="Edit permissions"
                                                >
                                                    <PencilIcon className="h-4 w-4" />
                                                </Button>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleDeleteShare(share)}
                                                    title="Revoke access"
                                                    className="text-red-600 hover:text-red-700"
                                                >
                                                    <TrashIcon className="h-4 w-4" />
                                                </Button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>

                        {/* Pagination */}
                        {pagination.totalPages > 1 && (
                            <div className="bg-white dark:bg-gray-800 px-4 py-3 border-t border-gray-200 dark:border-gray-700 sm:px-6">
                                <div className="flex items-center justify-between">
                                    <div className="flex-1 flex justify-between sm:hidden">
                                        <Button
                                            variant="outline"
                                            onClick={() => handlePageChange(pagination.page - 1)}
                                            disabled={pagination.page === 1}
                                        >
                                            Previous
                                        </Button>
                                        <Button
                                            variant="outline"
                                            onClick={() => handlePageChange(pagination.page + 1)}
                                            disabled={pagination.page === pagination.totalPages}
                                        >
                                            Next
                                        </Button>
                                    </div>
                                    <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                                        <div>
                                            <p className="text-sm text-gray-700 dark:text-gray-300">
                                                Showing{' '}
                                                <span className="font-medium">
                                                    {(pagination.page - 1) * pagination.pageSize + 1}
                                                </span>{' '}
                                                to{' '}
                                                <span className="font-medium">
                                                    {Math.min(pagination.page * pagination.pageSize, pagination.total)}
                                                </span>{' '}
                                                of{' '}
                                                <span className="font-medium">{pagination.total}</span> results
                                            </p>
                                        </div>
                                        <div>
                                            <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                                                <Button
                                                    variant="outline"
                                                    onClick={() => handlePageChange(pagination.page - 1)}
                                                    disabled={pagination.page === 1}
                                                    className="rounded-l-md"
                                                >
                                                    Previous
                                                </Button>
                                                {Array.from({ length: Math.min(5, pagination.totalPages) }, (_, i) => {
                                                    const page = i + 1;
                                                    return (
                                                        <Button
                                                            key={page}
                                                            variant={pagination.page === page ? 'primary' : 'outline'}
                                                            onClick={() => handlePageChange(page)}
                                                            className="rounded-none"
                                                        >
                                                            {page}
                                                        </Button>
                                                    );
                                                })}
                                                <Button
                                                    variant="outline"
                                                    onClick={() => handlePageChange(pagination.page + 1)}
                                                    disabled={pagination.page === pagination.totalPages}
                                                    className="rounded-r-md"
                                                >
                                                    Next
                                                </Button>
                                            </nav>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};