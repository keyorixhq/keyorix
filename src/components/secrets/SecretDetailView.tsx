import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    EyeIcon,
    EyeSlashIcon,
    DocumentDuplicateIcon,
    PencilIcon,
    ShareIcon,
    TrashIcon,
    ClockIcon,
    TagIcon,
    MapPinIcon,
    UserIcon,
    KeyIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { queryKeys } from '../../lib/queryClient';
import { usePreferencesStore } from '../../store/preferencesStore';
import { Secret } from '../../types';
import { Button } from '../ui/Button';
import { Loading } from '../ui/Loading';
import { Alert } from '../ui/Alert';

interface SecretDetailViewProps {
    secret: Secret;
    onEdit?: (secret: Secret) => void;
    onShare?: (secret: Secret) => void;
    onDelete?: (secret: Secret) => void;
    onClose?: () => void;
}

export const SecretDetailView: React.FC<SecretDetailViewProps> = ({
    secret,
    onEdit,
    onShare,
    onDelete,
    onClose
}) => {
    const { getFormattedDate, getFormattedTime, clipboardTimeout } = usePreferencesStore();
    const [showValue, setShowValue] = useState(false);
    const [copySuccess, setCopySuccess] = useState(false);

    // Fetch secret versions to reveal the latest value
    const { data: versions, isLoading, error } = useQuery({
        queryKey: queryKeys.secrets.versions(secret.id),
        queryFn: () => apiService.secrets.getVersions(secret.id),
        enabled: showValue,
    });

    const latestVersion = versions && versions.length > 0
        ? versions.reduce((a, b) => a.VersionNumber >= b.VersionNumber ? a : b)
        : null;
    const secretValue = latestVersion ? atob(latestVersion.EncryptedValue) : null;

    // Copy to clipboard with auto-clear
    const handleCopyValue = async (value: string) => {
        try {
            await navigator.clipboard.writeText(value);
            setCopySuccess(true);

            // Clear clipboard after timeout
            setTimeout(async () => {
                try {
                    await navigator.clipboard.writeText('');
                } catch (error) {
                    console.warn('Failed to clear clipboard:', error);
                }
            }, clipboardTimeout);

            // Reset success state
            setTimeout(() => {
                setCopySuccess(false);
            }, 2000);
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
        }
    };

    const handleToggleValue = () => {
        setShowValue(!showValue);
    };

    const formatSecretValue = (value: string, type: string) => {
        if (type === 'json') {
            try {
                return JSON.stringify(JSON.parse(value), null, 2);
            } catch {
                return value;
            }
        }
        return value;
    };

    const getTypeColor = (type: string) => {
        const colors = {
            text: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
            password: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
            api_key: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
            certificate: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
            json: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
        };
        return colors[type as keyof typeof colors] || colors.text;
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div className="flex-1">
                    <div className="flex items-center space-x-3">
                        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">
                            {secret.name}
                        </h2>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTypeColor(secret.type)}`}>
                            {secret.type}
                        </span>
                    </div>

                    <div className="mt-2 flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                        <div className="flex items-center">
                            <MapPinIcon className="h-4 w-4 mr-1" />
                            {secret.namespace} / {secret.zone} / {secret.environment}
                        </div>
                        <div className="flex items-center">
                            <UserIcon className="h-4 w-4 mr-1" />
                            {secret.owner}
                        </div>
                        <div className="flex items-center">
                            <ClockIcon className="h-4 w-4 mr-1" />
                            {getFormattedDate(secret.lastModified)} at {getFormattedTime(secret.lastModified)}
                        </div>
                    </div>
                </div>

                <div className="flex items-center space-x-2">
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onEdit?.(secret)}
                    >
                        <PencilIcon className="h-4 w-4 mr-2" />
                        Edit
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onShare?.(secret)}
                    >
                        <ShareIcon className="h-4 w-4 mr-2" />
                        Share
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onDelete?.(secret)}
                        className="text-red-600 hover:text-red-700"
                    >
                        <TrashIcon className="h-4 w-4 mr-2" />
                        Delete
                    </Button>
                </div>
            </div>

            {/* Secret Value */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                        <KeyIcon className="h-5 w-5 mr-2" />
                        Secret Value
                    </h3>
                    <div className="flex items-center space-x-2">
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={handleToggleValue}
                            disabled={showValue && isLoading}
                        >
                            {(showValue && isLoading) ? (
                                <Loading size="sm" />
                            ) : showValue ? (
                                <>
                                    <EyeSlashIcon className="h-4 w-4 mr-2" />
                                    Hide
                                </>
                            ) : (
                                <>
                                    <EyeIcon className="h-4 w-4 mr-2" />
                                    Reveal
                                </>
                            )}
                        </Button>

                        {showValue && secretValue && (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleCopyValue(secretValue)}
                                className={copySuccess ? 'text-green-600' : ''}
                            >
                                <DocumentDuplicateIcon className="h-4 w-4 mr-2" />
                                {copySuccess ? 'Copied!' : 'Copy'}
                            </Button>
                        )}
                    </div>
                </div>

                {error && (
                    <Alert
                        type="error"
                        title="Failed to load secret value"
                        message="There was an error loading the secret value. Please try again."
                    />
                )}

                {!showValue ? (
                    <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4 text-center">
                        <div className="text-gray-400 dark:text-gray-500 mb-2">
                            <EyeSlashIcon className="h-8 w-8 mx-auto" />
                        </div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Secret value is hidden for security. Click "Reveal" to view.
                        </p>
                    </div>
                ) : (showValue && isLoading) ? (
                    <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4">
                        <Loading />
                    </div>
                ) : secretValue ? (
                    <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4">
                        {secret.type === 'json' ? (
                            <pre className="text-sm font-mono text-gray-900 dark:text-white whitespace-pre-wrap overflow-x-auto">
                                {formatSecretValue(secretValue, secret.type)}
                            </pre>
                        ) : (
                            <div className="text-sm font-mono text-gray-900 dark:text-white break-all">
                                {secretValue}
                            </div>
                        )}
                    </div>
                ) : null}

                {copySuccess && (
                    <div className="mt-2">
                        <Alert
                            type="success"
                            title="Copied to clipboard"
                            message={`Secret value copied. Clipboard will be cleared in ${Math.round(clipboardTimeout / 1000)} seconds.`}
                        />
                    </div>
                )}
            </div>

            {/* Tags */}
            {secret.tags.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4 flex items-center">
                        <TagIcon className="h-5 w-5 mr-2" />
                        Tags
                    </h3>
                    <div className="flex flex-wrap gap-2">
                        {secret.tags.map((tag) => (
                            <span
                                key={tag}
                                className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                            >
                                {tag}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Metadata */}
            {Object.keys(secret.metadata).length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                        Metadata
                    </h3>
                    <div className="space-y-3">
                        {Object.entries(secret.metadata).map(([key, value]) => (
                            <div key={key} className="flex items-start">
                                <div className="w-1/3 text-sm font-medium text-gray-500 dark:text-gray-400">
                                    {key}
                                </div>
                                <div className="w-2/3 text-sm text-gray-900 dark:text-white">
                                    {value}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Sharing Information */}
            {secret.isShared && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4 flex items-center">
                        <ShareIcon className="h-5 w-5 mr-2" />
                        Sharing
                    </h3>
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-900 dark:text-white">
                                This secret is shared with <span className="font-medium">{secret.shareCount}</span> recipients
                            </p>
                            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                Click "Share" to manage sharing permissions
                            </p>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => onShare?.(secret)}
                        >
                            Manage Shares
                        </Button>
                    </div>
                </div>
            )}

            {/* Permissions */}
            {secret.permissions.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                        Permissions
                    </h3>
                    <div className="flex flex-wrap gap-2">
                        {secret.permissions.map((permission) => (
                            <span
                                key={permission}
                                className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                            >
                                {permission}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-end space-x-3 pt-6 border-t border-gray-200 dark:border-gray-700">
                <Button
                    variant="outline"
                    onClick={onClose}
                >
                    Close
                </Button>
            </div>
        </div>
    );
};