import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    ShieldCheckIcon,
    PlusIcon,
    PencilIcon,
    TrashIcon,
    UserGroupIcon,
    CheckIcon,
    XMarkIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { queryKeys, invalidateQueries } from '../../lib/queryClient';
import { useForm } from '../../store/formStore';
import { useTranslation } from '../../lib/i18n';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Modal } from '../ui/Modal';
import { Alert } from '../ui/Alert';
import { Loading } from '../ui/Loading';

interface Role {
    id: number;
    name: string;
    description: string;
    permissions: string[];
    userCount: number;
    isSystem: boolean;
    createdAt: string;
    updatedAt: string;
}

interface Permission {
    id: string;
    name: string;
    description: string;
    category: string;
    isSystem: boolean;
}

interface RolePermissionManagerProps {
    isOpen: boolean;
    onClose: () => void;
}

const FORM_ID = 'role-form';

export const RolePermissionManager: React.FC<RolePermissionManagerProps> = ({
    isOpen,
    onClose
}) => {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const form = useForm(FORM_ID);

    const [selectedRole, setSelectedRole] = useState<Role | null>(null);
    const [isCreating, setIsCreating] = useState(false);

    // Fetch roles
    const { data: roles, isLoading: rolesLoading } = useQuery({
        queryKey: queryKeys.admin.roles(),
        queryFn: async (): Promise<Role[]> => {
            // Mock roles data - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 800));

            return [
                {
                    id: 1,
                    name: 'Administrator',
                    description: 'Full system access with all permissions',
                    permissions: [
                        'secrets.read',
                        'secrets.write',
                        'secrets.delete',
                        'secrets.share',
                        'users.read',
                        'users.write',
                        'users.delete',
                        'admin.system',
                        'admin.audit',
                        'admin.roles',
                    ],
                    userCount: 3,
                    isSystem: true,
                    createdAt: '2024-01-01T00:00:00Z',
                    updatedAt: '2024-01-01T00:00:00Z',
                },
                {
                    id: 2,
                    name: 'User',
                    description: 'Standard user with secret management permissions',
                    permissions: [
                        'secrets.read',
                        'secrets.write',
                        'secrets.share',
                    ],
                    userCount: 45,
                    isSystem: true,
                    createdAt: '2024-01-01T00:00:00Z',
                    updatedAt: '2024-01-01T00:00:00Z',
                },
                {
                    id: 3,
                    name: 'Viewer',
                    description: 'Read-only access to secrets',
                    permissions: [
                        'secrets.read',
                    ],
                    userCount: 12,
                    isSystem: true,
                    createdAt: '2024-01-01T00:00:00Z',
                    updatedAt: '2024-01-01T00:00:00Z',
                },
                {
                    id: 4,
                    name: 'DevOps',
                    description: 'Custom role for DevOps team with specific permissions',
                    permissions: [
                        'secrets.read',
                        'secrets.write',
                        'secrets.share',
                        'admin.audit',
                    ],
                    userCount: 8,
                    isSystem: false,
                    createdAt: '2024-02-15T10:30:00Z',
                    updatedAt: '2024-02-20T14:45:00Z',
                },
            ];
        },
        enabled: isOpen,
    });

    // Fetch available permissions
    const { data: permissions } = useQuery({
        queryKey: ['admin', 'permissions'],
        queryFn: async (): Promise<Permission[]> => {
            // Mock permissions data - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 500));

            return [
                {
                    id: 'secrets.read',
                    name: 'Read Secrets',
                    description: 'View and access secret values',
                    category: 'Secrets',
                    isSystem: true,
                },
                {
                    id: 'secrets.write',
                    name: 'Write Secrets',
                    description: 'Create and modify secrets',
                    category: 'Secrets',
                    isSystem: true,
                },
                {
                    id: 'secrets.delete',
                    name: 'Delete Secrets',
                    description: 'Delete secrets permanently',
                    category: 'Secrets',
                    isSystem: true,
                },
                {
                    id: 'secrets.share',
                    name: 'Share Secrets',
                    description: 'Share secrets with other users and groups',
                    category: 'Secrets',
                    isSystem: true,
                },
                {
                    id: 'users.read',
                    name: 'View Users',
                    description: 'View user accounts and profiles',
                    category: 'Users',
                    isSystem: true,
                },
                {
                    id: 'users.write',
                    name: 'Manage Users',
                    description: 'Create and modify user accounts',
                    category: 'Users',
                    isSystem: true,
                },
                {
                    id: 'users.delete',
                    name: 'Delete Users',
                    description: 'Delete user accounts permanently',
                    category: 'Users',
                    isSystem: true,
                },
                {
                    id: 'admin.system',
                    name: 'System Administration',
                    description: 'Access system settings and configuration',
                    category: 'Administration',
                    isSystem: true,
                },
                {
                    id: 'admin.audit',
                    name: 'Audit Logs',
                    description: 'View and export audit logs',
                    category: 'Administration',
                    isSystem: true,
                },
                {
                    id: 'admin.roles',
                    name: 'Role Management',
                    description: 'Create and manage user roles and permissions',
                    category: 'Administration',
                    isSystem: true,
                },
            ];
        },
        enabled: isOpen,
    });

    // Create/Update role mutation
    const saveRoleMutation = useMutation({
        mutationFn: async (data: { name: string; description: string; permissions: string[] }) => {
            // Mock save - in real app this would call the API
            await new Promise(resolve => setTimeout(resolve, 1000));

            if (selectedRole) {
                return { ...selectedRole, ...data, updatedAt: new Date().toISOString() };
            } else {
                return {
                    id: Date.now(),
                    ...data,
                    userCount: 0,
                    isSystem: false,
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString(),
                };
            }
        },
        onSuccess: () => {
            invalidateQueries.admin.all();
            handleCloseForm();
        },
    });

    // Delete role mutation
    const deleteRoleMutation = useMutation({
        mutationFn: async (roleId: number) => {
            // Mock delete - in real app this would call the API
            await new Promise(resolve => setTimeout(resolve, 500));
            return roleId;
        },
        onSuccess: () => {
            invalidateQueries.admin.all();
        },
    });

    // Initialize form when role is selected
    React.useEffect(() => {
        if (selectedRole || isCreating) {
            form.initialize({
                name: selectedRole?.name || '',
                description: selectedRole?.description || '',
                permissions: selectedRole?.permissions || [],
            });
        }
    }, [selectedRole, isCreating, form]);

    const handleCreateRole = () => {
        setSelectedRole(null);
        setIsCreating(true);
    };

    const handleEditRole = (role: Role) => {
        setSelectedRole(role);
        setIsCreating(false);
    };

    const handleDeleteRole = (role: Role) => {
        if (role.isSystem) {
            alert('System roles cannot be deleted');
            return;
        }

        if (role.userCount > 0) {
            alert(`Cannot delete role "${role.name}" because it is assigned to ${role.userCount} user(s)`);
            return;
        }

        if (confirm(`Are you sure you want to delete the role "${role.name}"?`)) {
            deleteRoleMutation.mutate(role.id);
        }
    };

    const handleCloseForm = () => {
        setSelectedRole(null);
        setIsCreating(false);
        form.destroy();
    };

    const handleSaveRole = async (e: React.FormEvent) => {
        e.preventDefault();

        const values = form.getValues();

        // Validate form
        const errors: Record<string, string> = {};
        if (!values.name?.trim()) {
            errors.name = 'Role name is required';
        }
        if (!values.description?.trim()) {
            errors.description = 'Role description is required';
        }
        if (!values.permissions || values.permissions.length === 0) {
            errors.permissions = 'At least one permission is required';
        }

        if (Object.keys(errors).length > 0) {
            form.setErrors(errors);
            return;
        }

        form.setSubmitting(true);
        try {
            await saveRoleMutation.mutateAsync({
                name: values.name,
                description: values.description,
                permissions: values.permissions,
            });
        } catch (error) {
            // Error handling
        } finally {
            form.setSubmitting(false);
        }
    };

    const handlePermissionToggle = (permissionId: string) => {
        const values = form.getValues();
        const currentPermissions = values.permissions || [];

        if (currentPermissions.includes(permissionId)) {
            form.setValues({
                permissions: currentPermissions.filter(p => p !== permissionId)
            });
        } else {
            form.setValues({
                permissions: [...currentPermissions, permissionId]
            });
        }
    };

    // Group permissions by category
    const permissionsByCategory = React.useMemo(() => {
        if (!permissions) return {};

        return permissions.reduce((acc, permission) => {
            if (!acc[permission.category]) {
                acc[permission.category] = [];
            }
            acc[permission.category].push(permission);
            return acc;
        }, {} as Record<string, Permission[]>);
    }, [permissions]);

    const values = form.getValues();
    const errors = form.getErrors();
    const isSubmitting = form.isSubmitting();

    return (
        <Modal
            isOpen={isOpen}
            onClose={onClose}
            title="Role & Permission Management"
            size="xl"
        >
            <div className="flex h-96">
                {/* Roles List */}
                <div className="w-1/3 border-r border-gray-200 dark:border-gray-700 pr-4">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                            Roles
                        </h3>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={handleCreateRole}
                        >
                            <PlusIcon className="h-4 w-4 mr-1" />
                            New
                        </Button>
                    </div>

                    {rolesLoading ? (
                        <Loading />
                    ) : (
                        <div className="space-y-2 max-h-80 overflow-y-auto">
                            {roles?.map((role) => (
                                <div
                                    key={role.id}
                                    className={`p-3 rounded-lg border cursor-pointer transition-colors ${selectedRole?.id === role.id
                                            ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                                            : 'border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700'
                                        }`}
                                    onClick={() => handleEditRole(role)}
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex-1">
                                            <div className="flex items-center space-x-2">
                                                <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                                                    {role.name}
                                                </h4>
                                                {role.isSystem && (
                                                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                                                        System
                                                    </span>
                                                )}
                                            </div>
                                            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                                {role.userCount} users
                                            </p>
                                        </div>
                                        {!role.isSystem && (
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    handleDeleteRole(role);
                                                }}
                                                className="text-red-600 hover:text-red-700"
                                            >
                                                <TrashIcon className="h-4 w-4" />
                                            </Button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Role Form */}
                <div className="flex-1 pl-4">
                    {selectedRole || isCreating ? (
                        <form onSubmit={handleSaveRole} className="space-y-4">
                            <div className="flex items-center justify-between">
                                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                    {isCreating ? 'Create Role' : 'Edit Role'}
                                </h3>
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    onClick={handleCloseForm}
                                >
                                    <XMarkIcon className="h-4 w-4" />
                                </Button>
                            </div>

                            {saveRoleMutation.error && (
                                <Alert
                                    type="error"
                                    title="Failed to save role"
                                    message="There was an error saving the role. Please try again."
                                />
                            )}

                            <div className="space-y-4">
                                <div>
                                    <Input
                                        label="Role Name"
                                        type="text"
                                        value={values.name || ''}
                                        onChange={(e) => form.setValues({ name: e.target.value })}
                                        error={errors.name}
                                        disabled={selectedRole?.isSystem}
                                        required
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                        Description
                                    </label>
                                    <textarea
                                        value={values.description || ''}
                                        onChange={(e) => form.setValues({ description: e.target.value })}
                                        disabled={selectedRole?.isSystem}
                                        className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
                                        rows={2}
                                        required
                                    />
                                    {errors.description && (
                                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">
                                            {errors.description}
                                        </p>
                                    )}
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                        Permissions
                                    </label>
                                    {errors.permissions && (
                                        <p className="mb-2 text-sm text-red-600 dark:text-red-400">
                                            {errors.permissions}
                                        </p>
                                    )}
                                    <div className="max-h-48 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-md p-3">
                                        {Object.entries(permissionsByCategory).map(([category, categoryPermissions]) => (
                                            <div key={category} className="mb-4 last:mb-0">
                                                <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                                                    {category}
                                                </h4>
                                                <div className="space-y-2">
                                                    {categoryPermissions.map((permission) => (
                                                        <label
                                                            key={permission.id}
                                                            className="flex items-start space-x-3 cursor-pointer"
                                                        >
                                                            <input
                                                                type="checkbox"
                                                                checked={(values.permissions || []).includes(permission.id)}
                                                                onChange={() => handlePermissionToggle(permission.id)}
                                                                disabled={selectedRole?.isSystem}
                                                                className="mt-0.5 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                                                            />
                                                            <div className="flex-1">
                                                                <div className="text-sm font-medium text-gray-900 dark:text-white">
                                                                    {permission.name}
                                                                </div>
                                                                <div className="text-xs text-gray-500 dark:text-gray-400">
                                                                    {permission.description}
                                                                </div>
                                                            </div>
                                                        </label>
                                                    ))}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            {!selectedRole?.isSystem && (
                                <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                                    <Button
                                        type="button"
                                        variant="outline"
                                        onClick={handleCloseForm}
                                        disabled={isSubmitting}
                                    >
                                        Cancel
                                    </Button>
                                    <Button
                                        type="submit"
                                        disabled={isSubmitting}
                                    >
                                        {isSubmitting && <Loading size="sm" className="mr-2" />}
                                        {isCreating ? 'Create Role' : 'Update Role'}
                                    </Button>
                                </div>
                            )}
                        </form>
                    ) : (
                        <div className="flex items-center justify-center h-full">
                            <div className="text-center">
                                <ShieldCheckIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                                <p className="text-gray-500 dark:text-gray-400">
                                    Select a role to edit or create a new one
                                </p>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </Modal>
    );
};