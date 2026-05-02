import React, { useEffect } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
    UserIcon,
    UserGroupIcon,
    PencilIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { queryKeys, invalidateQueries } from '../../lib/queryClient';
import { useForm } from '../../store/formStore';
import { ShareRecord, ShareFormData } from '../../types';
import { Button } from '../ui/Button';
import { Dropdown } from '../ui/Dropdown';
import { Modal } from '../ui/Modal';
import { Alert } from '../ui/Alert';
import { Loading } from '../ui/Loading';

interface EditShareModalProps {
    share: ShareRecord;
    isOpen: boolean;
    onClose: () => void;
    onSuccess?: () => void;
}

const PERMISSION_OPTIONS = [
    { value: 'read', label: 'Read Only', description: 'Can view the secret value' },
    { value: 'write', label: 'Read & Write', description: 'Can view and modify the secret' },
];

const FORM_ID = 'edit-share-form';

export const EditShareModal: React.FC<EditShareModalProps> = ({
    share,
    isOpen,
    onClose,
    onSuccess
}) => {
    const queryClient = useQueryClient();
    const form = useForm(FORM_ID);

    // Initialize form
    useEffect(() => {
        if (isOpen && share) {
            form.initialize({
                permission: share.permission,
            });
        } else {
            form.destroy();
        }
    }, [isOpen, share, form]);

    // Update mutation
    const updateMutation = useMutation({
        mutationFn: (data: Partial<ShareFormData>) =>
            apiService.sharing.update(share.id, data),
        onSuccess: (updatedShare) => {
            // Update the share in cache
            queryClient.setQueryData(
                queryKeys.sharing.detail(share.id),
                updatedShare
            );

            // Invalidate shares list to reflect changes
            invalidateQueries.sharing.lists();

            // Invalidate the secret details
            invalidateQueries.secrets.detail(share.secretId);

            onSuccess?.();
            onClose();
        },
    });

    // Handle form submission
    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        const values = form.getValues();

        // Check if anything changed
        if (values.permission === share.permission) {
            onClose();
            return;
        }

        form.setSubmitting(true);

        try {
            await updateMutation.mutateAsync({
                permission: values.permission,
            });
        } catch (error) {
            // Error handling is done by the mutation
        } finally {
            form.setSubmitting(false);
        }
    };

    const values = form.getValues();
    const isSubmitting = form.isSubmitting();
    const hasChanges = values.permission !== share.permission;

    return (
        <Modal
            isOpen={isOpen}
            onClose={onClose}
            title="Edit Share Permissions"
            size="md"
        >
            <form onSubmit={handleSubmit} className="space-y-6">
                {/* Error Alert */}
                {updateMutation.error && (
                    <Alert
                        type="error"
                        title="Failed to update share"
                        message={updateMutation.error instanceof Error ? updateMutation.error.message : 'An unexpected error occurred'}
                    />
                )}

                {/* Share Info */}
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                    <div className="flex items-center space-x-3">
                        <div className="flex-shrink-0">
                            {share.recipientType === 'user' ? (
                                <UserIcon className="h-8 w-8 text-blue-600 dark:text-blue-400" />
                            ) : (
                                <UserGroupIcon className="h-8 w-8 text-green-600 dark:text-green-400" />
                            )}
                        </div>
                        <div className="flex-1">
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                {share.recipientName}
                            </h3>
                            <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                                {share.recipientType}
                            </p>
                        </div>
                        <div className="flex-shrink-0">
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                Secret #{share.secretId}
                            </span>
                        </div>
                    </div>
                </div>

                {/* Permission Selection */}
                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Permission Level
                    </label>
                    <Dropdown
                        value={values.permission || share.permission}
                        onChange={(value) => form.setValues({ permission: value })}
                        options={PERMISSION_OPTIONS}
                    />
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                        {PERMISSION_OPTIONS.find(p => p.value === values.permission)?.description}
                    </p>
                </div>

                {/* Current vs New Permission Comparison */}
                {hasChanges && (
                    <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
                        <h4 className="text-sm font-medium text-blue-900 dark:text-blue-100 mb-2">
                            Permission Change
                        </h4>
                        <div className="flex items-center space-x-4 text-sm">
                            <div>
                                <span className="text-gray-500 dark:text-gray-400">Current:</span>
                                <span className="ml-1 font-medium text-gray-900 dark:text-white">
                                    {PERMISSION_OPTIONS.find(p => p.value === share.permission)?.label}
                                </span>
                            </div>
                            <div className="text-gray-400">→</div>
                            <div>
                                <span className="text-gray-500 dark:text-gray-400">New:</span>
                                <span className="ml-1 font-medium text-blue-900 dark:text-blue-100">
                                    {PERMISSION_OPTIONS.find(p => p.value === values.permission)?.label}
                                </span>
                            </div>
                        </div>
                    </div>
                )}

                {/* Share Details */}
                <div className="text-sm text-gray-500 dark:text-gray-400 space-y-1">
                    <div>
                        <span className="font-medium">Shared by:</span> {share.createdBy}
                    </div>
                    <div>
                        <span className="font-medium">Created:</span> {new Date(share.createdAt).toLocaleDateString()}
                    </div>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-end space-x-3 pt-6 border-t border-gray-200 dark:border-gray-700">
                    <Button
                        type="button"
                        variant="outline"
                        onClick={onClose}
                        disabled={isSubmitting}
                    >
                        Cancel
                    </Button>
                    <Button
                        type="submit"
                        disabled={isSubmitting || !hasChanges}
                    >
                        {isSubmitting && <Loading size="sm" className="mr-2" />}
                        <PencilIcon className="h-4 w-4 mr-2" />
                        Update Permissions
                    </Button>
                </div>
            </form>
        </Modal>
    );
};