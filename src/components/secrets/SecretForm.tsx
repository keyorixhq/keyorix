import React, { useState, useEffect } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
    EyeIcon,
    EyeSlashIcon,
    DocumentDuplicateIcon,
    PlusIcon,
    XMarkIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { queryKeys, invalidateQueries } from '../../lib/queryClient';
import { useForm } from '../../store/formStore';
import { Secret, SecretFormData, SecretType } from '../../types';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Textarea } from '../ui/Textarea';
import { Dropdown } from '../ui/Dropdown';
import { Alert } from '../ui/Alert';
import { Loading } from '../ui/Loading';

interface SecretFormProps {
    secret?: Secret;
    onSuccess?: (secret: Secret) => void;
    onCancel?: () => void;
}

const SECRET_TYPES: { value: SecretType; label: string; description: string }[] = [
    { value: 'text', label: 'Text', description: 'Plain text value' },
    { value: 'password', label: 'Password', description: 'Sensitive password or passphrase' },
    { value: 'api_key', label: 'API Key', description: 'API key or token' },
    { value: 'certificate', label: 'Certificate', description: 'SSL certificate or private key' },
    { value: 'json', label: 'JSON', description: 'Structured JSON data' },
];

const FORM_ID = 'secret-form';

export const SecretForm: React.FC<SecretFormProps> = ({ secret, onSuccess, onCancel }) => {
    const queryClient = useQueryClient();
    const isEditing = !!secret;

    // Form state
    const form = useForm(FORM_ID);
    const [showValue, setShowValue] = useState(false);
    const [newTag, setNewTag] = useState('');
    const [newMetadataKey, setNewMetadataKey] = useState('');
    const [newMetadataValue, setNewMetadataValue] = useState('');

    // Initialize form
    useEffect(() => {
        const initialValues: SecretFormData = secret ? {
            name: secret.name,
            value: '', // Don't pre-fill value for security
            type: secret.type,
            namespace: secret.namespace,
            zone: secret.zone,
            environment: secret.environment,
            metadata: secret.metadata,
            tags: secret.tags,
        } : {
            name: '',
            value: '',
            type: 'text',
            namespace: 'default',
            zone: 'default',
            environment: 'production',
            metadata: {},
            tags: [],
        };

        form.initialize(initialValues);

        return () => {
            form.destroy();
        };
    }, [secret, form]);

    // Mutations
    const createMutation = useMutation({
        mutationFn: (data: SecretFormData) => apiService.secrets.create(data),
        onSuccess: (newSecret) => {
            invalidateQueries.secrets.all();
            onSuccess?.(newSecret);
        },
    });

    const updateMutation = useMutation({
        mutationFn: (data: Partial<SecretFormData>) =>
            apiService.secrets.update(secret!.id, data),
        onSuccess: (updatedSecret) => {
            invalidateQueries.secrets.all();
            invalidateQueries.secrets.detail(secret!.id);
            onSuccess?.(updatedSecret);
        },
    });

    const mutation = isEditing ? updateMutation : createMutation;

    // Form validation
    const validateForm = () => {
        const values = form.getValues();
        const errors: Record<string, string> = {};

        if (!values.name?.trim()) {
            errors.name = 'Name is required';
        } else if (values.name.length < 3) {
            errors.name = 'Name must be at least 3 characters';
        } else if (!/^[a-zA-Z0-9_-]+$/.test(values.name)) {
            errors.name = 'Name can only contain letters, numbers, hyphens, and underscores';
        }

        if (!values.value?.trim()) {
            errors.value = 'Value is required';
        }

        if (!values.type) {
            errors.type = 'Type is required';
        }

        if (!values.namespace?.trim()) {
            errors.namespace = 'Namespace is required';
        }

        if (!values.zone?.trim()) {
            errors.zone = 'Zone is required';
        }

        if (!values.environment?.trim()) {
            errors.environment = 'Environment is required';
        }

        // Validate JSON if type is json
        if (values.type === 'json' && values.value) {
            try {
                JSON.parse(values.value);
            } catch {
                errors.value = 'Invalid JSON format';
            }
        }

        form.setErrors(errors);
        return Object.keys(errors).length === 0;
    };

    // Handle form submission
    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) {
            form.touchAll();
            return;
        }

        const values = form.getValues();
        form.setSubmitting(true);

        try {
            await mutation.mutateAsync(values);
        } catch (error) {
            // Error handling is done by the mutation
        } finally {
            form.setSubmitting(false);
        }
    };

    // Handle tag management
    const handleAddTag = () => {
        if (!newTag.trim()) return;

        const values = form.getValues();
        const currentTags = values.tags || [];

        if (!currentTags.includes(newTag.trim())) {
            form.setValues({ tags: [...currentTags, newTag.trim()] });
        }

        setNewTag('');
    };

    const handleRemoveTag = (tagToRemove: string) => {
        const values = form.getValues();
        const currentTags = values.tags || [];
        form.setValues({ tags: currentTags.filter(tag => tag !== tagToRemove) });
    };

    // Handle metadata management
    const handleAddMetadata = () => {
        if (!newMetadataKey.trim() || !newMetadataValue.trim()) return;

        const values = form.getValues();
        const currentMetadata = values.metadata || {};

        form.setValues({
            metadata: {
                ...currentMetadata,
                [newMetadataKey.trim()]: newMetadataValue.trim()
            }
        });

        setNewMetadataKey('');
        setNewMetadataValue('');
    };

    const handleRemoveMetadata = (keyToRemove: string) => {
        const values = form.getValues();
        const currentMetadata = values.metadata || {};
        const { [keyToRemove]: removed, ...rest } = currentMetadata;
        form.setValues({ metadata: rest });
    };

    // Copy to clipboard
    const handleCopyValue = async () => {
        const values = form.getValues();
        if (values.value) {
            try {
                await navigator.clipboard.writeText(values.value);
                // Could show a toast notification here
            } catch (error) {
                console.error('Failed to copy to clipboard:', error);
            }
        }
    };

    const values = form.getValues();
    const errors = form.getErrors();
    const isSubmitting = form.isSubmitting();

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            {/* Error Alert */}
            {mutation.error && (
                <Alert
                    type="error"
                    title="Failed to save secret"
                    message={mutation.error instanceof Error ? mutation.error.message : 'An unexpected error occurred'}
                />
            )}

            {/* Basic Information */}
            <div className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Basic Information
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <Input
                            label="Name"
                            type="text"
                            value={values.name || ''}
                            onChange={(e) => form.setValues({ name: e.target.value })}
                            error={errors.name}
                            placeholder="my-secret"
                            required
                        />
                        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                            Unique identifier for your secret
                        </p>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Type
                        </label>
                        <Dropdown
                            value={values.type || 'text'}
                            onChange={(value) => form.setValues({ type: value as SecretType })}
                            options={SECRET_TYPES}
                            error={errors.type}
                        />
                        {values.type && (
                            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                                {SECRET_TYPES.find(t => t.value === values.type)?.description}
                            </p>
                        )}
                    </div>
                </div>

                {/* Secret Value */}
                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Value *
                    </label>
                    <div className="relative">
                        {values.type === 'json' ? (
                            <Textarea
                                value={values.value || ''}
                                onChange={(e) => form.setValues({ value: e.target.value })}
                                error={errors.value}
                                placeholder='{"key": "value"}'
                                rows={6}
                                className="font-mono text-sm"
                                required
                            />
                        ) : (
                            <Input
                                type={showValue ? 'text' : 'password'}
                                value={values.value || ''}
                                onChange={(e) => form.setValues({ value: e.target.value })}
                                error={errors.value}
                                placeholder="Enter secret value"
                                className="pr-20"
                                required
                            />
                        )}

                        <div className="absolute inset-y-0 right-0 flex items-center pr-3 space-x-1">
                            <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                onClick={() => setShowValue(!showValue)}
                                title={showValue ? 'Hide value' : 'Show value'}
                            >
                                {showValue ? (
                                    <EyeSlashIcon className="h-4 w-4" />
                                ) : (
                                    <EyeIcon className="h-4 w-4" />
                                )}
                            </Button>

                            {values.value && (
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    onClick={handleCopyValue}
                                    title="Copy to clipboard"
                                >
                                    <DocumentDuplicateIcon className="h-4 w-4" />
                                </Button>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* Location */}
            <div className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Location
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <Input
                            label="Namespace"
                            type="text"
                            value={values.namespace || ''}
                            onChange={(e) => form.setValues({ namespace: e.target.value })}
                            error={errors.namespace}
                            placeholder="default"
                            required
                        />
                    </div>

                    <div>
                        <Input
                            label="Zone"
                            type="text"
                            value={values.zone || ''}
                            onChange={(e) => form.setValues({ zone: e.target.value })}
                            error={errors.zone}
                            placeholder="us-east-1"
                            required
                        />
                    </div>

                    <div>
                        <Input
                            label="Environment"
                            type="text"
                            value={values.environment || ''}
                            onChange={(e) => form.setValues({ environment: e.target.value })}
                            error={errors.environment}
                            placeholder="production"
                            required
                        />
                    </div>
                </div>
            </div>

            {/* Tags */}
            <div className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Tags
                </h3>

                <div className="flex items-center space-x-2">
                    <Input
                        type="text"
                        value={newTag}
                        onChange={(e) => setNewTag(e.target.value)}
                        placeholder="Add tag"
                        onKeyPress={(e) => {
                            if (e.key === 'Enter') {
                                e.preventDefault();
                                handleAddTag();
                            }
                        }}
                    />
                    <Button
                        type="button"
                        variant="outline"
                        onClick={handleAddTag}
                        disabled={!newTag.trim()}
                    >
                        <PlusIcon className="h-4 w-4" />
                    </Button>
                </div>

                {values.tags && values.tags.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                        {values.tags.map((tag) => (
                            <span
                                key={tag}
                                className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                            >
                                {tag}
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleRemoveTag(tag)}
                                    className="ml-2 -mr-1 h-4 w-4 p-0"
                                >
                                    <XMarkIcon className="h-3 w-3" />
                                </Button>
                            </span>
                        ))}
                    </div>
                )}
            </div>

            {/* Metadata */}
            <div className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Metadata
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <Input
                        type="text"
                        value={newMetadataKey}
                        onChange={(e) => setNewMetadataKey(e.target.value)}
                        placeholder="Key"
                    />
                    <Input
                        type="text"
                        value={newMetadataValue}
                        onChange={(e) => setNewMetadataValue(e.target.value)}
                        placeholder="Value"
                    />
                    <Button
                        type="button"
                        variant="outline"
                        onClick={handleAddMetadata}
                        disabled={!newMetadataKey.trim() || !newMetadataValue.trim()}
                    >
                        <PlusIcon className="h-4 w-4 mr-2" />
                        Add
                    </Button>
                </div>

                {values.metadata && Object.keys(values.metadata).length > 0 && (
                    <div className="space-y-2">
                        {Object.entries(values.metadata).map(([key, value]) => (
                            <div
                                key={key}
                                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-md"
                            >
                                <div className="flex-1">
                                    <span className="font-medium text-gray-900 dark:text-white">
                                        {key}:
                                    </span>
                                    <span className="ml-2 text-gray-600 dark:text-gray-300">
                                        {value}
                                    </span>
                                </div>
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleRemoveMetadata(key)}
                                    className="text-red-600 hover:text-red-700"
                                >
                                    <XMarkIcon className="h-4 w-4" />
                                </Button>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Actions */}
            <div className="flex items-center justify-end space-x-3 pt-6 border-t border-gray-200 dark:border-gray-700">
                <Button
                    type="button"
                    variant="outline"
                    onClick={onCancel}
                    disabled={isSubmitting}
                >
                    Cancel
                </Button>
                <Button
                    type="submit"
                    disabled={isSubmitting || !form.isValid()}
                >
                    {isSubmitting && <Loading size="sm" className="mr-2" />}
                    {isEditing ? 'Update Secret' : 'Create Secret'}
                </Button>
            </div>
        </form>
    );
};