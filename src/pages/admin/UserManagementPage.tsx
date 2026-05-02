import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    UserIcon,
    PlusIcon,
    PencilIcon,
    TrashIcon,
    ShieldCheckIcon,
    MagnifyingGlassIcon,
    FunnelIcon,
    EyeIcon,
    UserPlusIcon,
    ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { queryKeys, invalidateQueries } from '../../lib/queryClient';
import { useUIStore } from '../../store/uiStore';
import { useTranslation } from '../../lib/i18n';
import { useLocaleFormat } from '../../lib/i18n';
import { User, PaginationState } from '../../types';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Dropdown } from '../../components/ui/Dropdown';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';

const ITEMS_PER_PAGE = 20;

const USER_ROLES = [
    { value: 'all', label: 'All Roles' },
    { value: 'admin', label: 'Administrator' },
    { value: 'user', label: 'User' },
    { value: 'viewer', label: 'Viewer' },
];

const USER_STATUS = [
    { value: 'all', label: 'All Status' },
    { value: 'active', label: 'Active' },
    { value: 'inactive', label: 'Inactive' },
    { value: 'suspended', label: 'Suspended' },
];

interface ExtendedUser extends User {
    status: 'active' | 'inactive' | 'suspended';
    secretCount: number;
    shareCount: number;
    lastActivity: string;
}

export const UserManagementPage: React.FC = () => {
    const { t } = useTranslation();
    const { formatDateTime } = useLocaleFormat();
    const { openModal, selectedItems, toggleSelectedItem, clearSelectedItems, bulkActionMode, setBulkActionMode } = useUIStore();
    const queryClient = useQueryClient();

    // State for filters and pagination
    const [filters, setFilters] = useState({
        search: '',
        role: 'all',
        status: 'all',
    });

    const [pagination, setPagination] = useState<PaginationState>({
        page: 1,
        pageSize: ITEMS_PER_PAGE,
        total: 0,
        totalPages: 0,
    });

    // Fetch users with filters and pagination
    const { data, isLoading, error, refetch } = useQuery({
        queryKey: queryKeys.admin.users({ ...filters, page: pagination.page, pageSize: pagination.pageSize }),
        queryFn: async () => {
            // Mock user data - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 800));

            const mockUsers: ExtendedUser[] = [
                {
                    id: 1,
                    username: 'john.doe',
                    email: 'john.doe@company.com',
                    role: 'admin',
                    permissions: ['read', 'write', 'admin'],
                    preferences: {
                        language: 'en',
                        timezone: 'UTC',
                        theme: 'system',
                        notifications: {
                            email: true,
                            browser: true,
                            sharing: true,
                            security: true,
                        },
                    },
                    lastLogin: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
                    status: 'active',
                    secretCount: 45,
                    shareCount: 12,
                    lastActivity: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
                },
                {
                    id: 2,
                    username: 'jane.smith',
                    email: 'jane.smith@company.com',
                    role: 'user',
                    permissions: ['read', 'write'],
                    preferences: {
                        language: 'en',
                        timezone: 'America/New_York',
                        theme: 'light',
                        notifications: {
                            email: true,
                            browser: false,
                            sharing: true,
                            security: true,
                        },
                    },
                    lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
                    status: 'active',
                    secretCount: 23,
                    shareCount: 8,
                    lastActivity: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
                },
                {
                    id: 3,
                    username: 'bob.wilson',
                    email: 'bob.wilson@company.com',
                    role: 'viewer',
                    permissions: ['read'],
                    preferences: {
                        language: 'en',
                        timezone: 'Europe/London',
                        theme: 'dark',
                        notifications: {
                            email: false,
                            browser: true,
                            sharing: false,
                            security: true,
                        },
                    },
                    lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString(),
                    status: 'inactive',
                    secretCount: 5,
                    shareCount: 2,
                    lastActivity: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2).toISOString(),
                },
                {
                    id: 4,
                    username: 'alice.johnson',
                    email: 'alice.johnson@company.com',
                    role: 'user',
                    permissions: ['read', 'write'],
                    preferences: {
                        language: 'fr',
                        timezone: 'Europe/Paris',
                        theme: 'system',
                        notifications: {
                            email: true,
                            browser: true,
                            sharing: true,
                            security: true,
                        },
                    },
                    lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
                    status: 'suspended',
                    secretCount: 12,
                    shareCount: 3,
                    lastActivity: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(),
                },
            ];

            // Apply filters
            let filteredUsers = mockUsers;

            if (filters.search) {
                const searchLower = filters.search.toLowerCase();
                filteredUsers = filteredUsers.filter(user =>
                    user.username.toLowerCase().includes(searchLower) ||
                    user.email.toLowerCase().includes(searchLower)
                );
            }

            if (filters.role !== 'all') {
                filteredUsers = filteredUsers.filter(user => user.role === filters.role);
            }

            if (filters.status !== 'all') {
                filteredUsers = filteredUsers.filter(user => user.status === filters.status);
            }

            return {
                data: filteredUsers,
                total: filteredUsers.length,
                page: pagination.page,
                pageSize: pagination.pageSize,
                totalPages: Math.ceil(filteredUsers.length / pagination.pageSize),
            };
        },
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

    // Delete user mutation
    const deleteUserMutation = useMutation({
        mutationFn: (userId: number) => {
            // Mock deletion - in real app this would call the API
            return Promise.resolve();
        },
        onSuccess: () => {
            invalidateQueries.admin.all();
        },
    });

    // Bulk operations
    const bulkDeleteMutation = useMutation({
        mutationFn: async (userIds: number[]) => {
            // Mock bulk deletion
            await Promise.all(userIds.map(id => Promise.resolve()));
            return userIds;
        },
        onSuccess: () => {
            invalidateQueries.admin.all();
            clearSelectedItems();
            setBulkActionMode(false);
        },
    });

    // Handle filter changes
    const handleFilterChange = (key: string, value: string) => {
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

    // Handle individual user actions
    const handleViewUser = (user: ExtendedUser) => {
        openModal('view-user', { user });
    };

    const handleEditUser = (user: ExtendedUser) => {
        openModal('edit-user', { user });
    };

    const handleDeleteUser = (user: ExtendedUser) => {
        openModal('confirm-delete', {
            title: 'Delete User',
            message: `Are you sure you want to delete user "${user.username}"? This action cannot be undone.`,
            onConfirm: () => deleteUserMutation.mutate(user.id),
        });
    };

    const handleSuspendUser = (user: ExtendedUser) => {
        openModal('confirm-action', {
            title: 'Suspend User',
            message: `Are you sure you want to suspend user "${user.username}"?`,
            onConfirm: () => {
                // Mock suspend action
                console.log('Suspend user:', user.id);
            },
        });
    };

    // Handle bulk actions
    const handleBulkDelete = () => {
        if (selectedItems.size === 0) return;

        openModal('confirm-delete', {
            title: 'Delete Multiple Users',
            message: `Are you sure you want to delete ${selectedItems.size} user(s)? This action cannot be undone.`,
            onConfirm: () => bulkDeleteMutation.mutate(Array.from(selectedItems) as number[]),
        });
    };

    const handleCreateUser = () => {
        openModal('create-user');
    };

    const getStatusColor = (status: ExtendedUser['status']) => {
        switch (status) {
            case 'active':
                return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
            case 'inactive':
                return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';
            case 'suspended':
                return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
            default:
                return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';
        }
    };

    const getRoleColor = (role: string) => {
        switch (role) {
            case 'admin':
                return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200';
            case 'user':
                return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
            case 'viewer':
                return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
            default:
                return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';
        }
    };

    if (error) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load users"
                    message="There was an error loading the user data. Please try again."
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
                        User Management
                    </h1>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                        Manage user accounts, roles, and permissions
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
                                Delete
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
                    <Button
                        onClick={handleCreateUser}
                    >
                        <UserPlusIcon className="h-4 w-4 mr-2" />
                        Add User
                    </Button>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Search */}
                    <div>
                        <Input
                            type="text"
                            placeholder="Search users..."
                            value={searchInput}
                            onChange={(e) => setSearchInput(e.target.value)}
                            icon={MagnifyingGlassIcon}
                        />
                    </div>

                    {/* Role Filter */}
                    <div>
                        <Dropdown
                            value={filters.role}
                            onChange={(value) => handleFilterChange('role', value)}
                            options={USER_ROLES}
                            placeholder="Filter by role"
                        />
                    </div>

                    {/* Status Filter */}
                    <div>
                        <Dropdown
                            value={filters.status}
                            onChange={(value) => handleFilterChange('status', value)}
                            options={USER_STATUS}
                            placeholder="Filter by status"
                            icon={FunnelIcon}
                        />
                    </div>
                </div>

                {/* Active Filters */}
                {(filters.search || filters.role !== 'all' || filters.status !== 'all') && (
                    <div className="mt-4 flex items-center space-x-2">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Active filters:</span>
                        {filters.search && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                Search: {filters.search}
                            </span>
                        )}
                        {filters.role !== 'all' && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                                Role: {filters.role}
                            </span>
                        )}
                        {filters.status !== 'all' && (
                            <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
                                Status: {filters.status}
                            </span>
                        )}
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                                setFilters({
                                    search: '',
                                    role: 'all',
                                    status: 'all',
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

            {/* Users Table */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                {isLoading ? (
                    <div className="p-8">
                        <Loading />
                    </div>
                ) : !data?.data || data.data.length === 0 ? (
                    <div className="p-8 text-center">
                        <div className="text-gray-400 dark:text-gray-500 mb-4">
                            <UserIcon className="h-12 w-12 mx-auto" />
                        </div>
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                            No users found
                        </h3>
                        <p className="text-gray-500 dark:text-gray-400 mb-4">
                            {filters.search || filters.role !== 'all' || filters.status !== 'all'
                                ? 'Try adjusting your filters.'
                                : 'Get started by adding your first user.'}
                        </p>
                        {!filters.search && filters.role === 'all' && filters.status === 'all' && (
                            <Button onClick={handleCreateUser}>
                                <UserPlusIcon className="h-4 w-4 mr-2" />
                                Add User
                            </Button>
                        )}
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
                                                checked={data.data.length > 0 && data.data.every(u => selectedItems.has(u.id))}
                                                onChange={(e) => {
                                                    if (e.target.checked) {
                                                        data.data.forEach(u => toggleSelectedItem(u.id));
                                                    } else {
                                                        clearSelectedItems();
                                                    }
                                                }}
                                            />
                                        </th>
                                    )}
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        User
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Role
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Status
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Activity
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Last Login
                                    </th>
                                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                {data.data.map((user) => (
                                    <tr key={user.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                                        {bulkActionMode && (
                                            <td className="px-6 py-4">
                                                <input
                                                    type="checkbox"
                                                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                                    checked={selectedItems.has(user.id)}
                                                    onChange={() => toggleSelectedItem(user.id)}
                                                />
                                            </td>
                                        )}
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <div className="flex items-center">
                                                <div className="flex-shrink-0 h-10 w-10">
                                                    <div className="h-10 w-10 rounded-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center">
                                                        <UserIcon className="h-6 w-6 text-gray-500 dark:text-gray-400" />
                                                    </div>
                                                </div>
                                                <div className="ml-4">
                                                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                                                        {user.username}
                                                    </div>
                                                    <div className="text-sm text-gray-500 dark:text-gray-400">
                                                        {user.email}
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRoleColor(user.role)}`}>
                                                {user.role}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(user.status)}`}>
                                                {user.status}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                            <div>
                                                <div>{user.secretCount} secrets</div>
                                                <div className="text-xs">{user.shareCount} shares</div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                            {formatDateTime(user.lastLogin)}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                            <div className="flex items-center justify-end space-x-2">
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleViewUser(user)}
                                                    title="View user"
                                                >
                                                    <EyeIcon className="h-4 w-4" />
                                                </Button>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleEditUser(user)}
                                                    title="Edit user"
                                                >
                                                    <PencilIcon className="h-4 w-4" />
                                                </Button>
                                                {user.status === 'active' && (
                                                    <Button
                                                        variant="ghost"
                                                        size="sm"
                                                        onClick={() => handleSuspendUser(user)}
                                                        title="Suspend user"
                                                        className="text-yellow-600 hover:text-yellow-700"
                                                    >
                                                        <ExclamationTriangleIcon className="h-4 w-4" />
                                                    </Button>
                                                )}
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => handleDeleteUser(user)}
                                                    title="Delete user"
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