import React from 'react';
import {
    EyeIcon, PencilIcon, TrashIcon, ShareIcon,
    DocumentDuplicateIcon, CheckIcon, ArrowPathIcon,
} from '@heroicons/react/24/outline';
import { Secret } from '../../types';
import { Button } from '../../components/ui/Button';

const formatDate = (d: string | Date) =>
    new Intl.DateTimeFormat('en', { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(d));

interface SecretTableRowProps {
    secret: Secret;
    bulkActionMode: boolean;
    isSelected: boolean;
    onToggleSelect: (id: number) => void;
    onView: (secret: Secret) => void;
    onEdit: (secret: Secret) => void;
    onDelete: (secret: Secret) => void;
    onShare: (secret: Secret) => void;
    onRotate: (secret: Secret) => void;
    onCopy: (secret: Secret) => void;
    copyingId: number | null;
    copiedId: number | null;
    copyErrorId: number | null;
}

export const SecretTableRow: React.FC<SecretTableRowProps> = ({
    secret, bulkActionMode, isSelected, onToggleSelect,
    onView, onEdit, onDelete, onShare, onRotate, onCopy,
    copyingId, copiedId, copyErrorId,
}) => (
    <tr className="hover:bg-gray-50 dark:hover:bg-gray-700">
        {bulkActionMode && (
            <td className="px-6 py-4">
                <input
                    type="checkbox"
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    checked={isSelected}
                    onChange={() => onToggleSelect(secret.id)}
                />
            </td>
        )}
        <td className="px-6 py-4">
            <div className="text-sm font-medium text-gray-900 dark:text-white">{secret.name}</div>
            {secret.tags.length > 0 && (
                <div className="flex items-center space-x-1 mt-1">
                    {secret.tags.slice(0, 3).map(tag => (
                        <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                            {tag}
                        </span>
                    ))}
                    {secret.tags.length > 3 && (
                        <span className="text-xs text-gray-500 dark:text-gray-400">+{secret.tags.length - 3} more</span>
                    )}
                </div>
            )}
        </td>
        <td className="px-6 py-4 whitespace-nowrap">
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                {secret.type}
            </span>
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 capitalize">
                {secret.environment || 'production'}
            </span>
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
            {secret.isShared ? (
                <div className="flex items-center">
                    <ShareIcon className="h-4 w-4 mr-1 text-green-500" />
                    <span>{secret.shareCount} shares</span>
                </div>
            ) : <span>Private</span>}
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
            <div>
                <div>{formatDate(secret.lastModified)}</div>
                <div className="text-xs">by {secret.owner}</div>
            </div>
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
            <div className="flex items-center justify-end space-x-2">
                <Button variant="ghost" size="sm" onClick={() => onView(secret)} title="View secret">
                    <EyeIcon className="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="sm" onClick={() => onEdit(secret)} title="Edit secret">
                    <PencilIcon className="h-4 w-4" />
                </Button>
                <button
                    onClick={() => onRotate(secret)}
                    className="p-1 text-gray-400 hover:text-green-600 dark:hover:text-green-400 transition-colors"
                    title="Rotate secret"
                >
                    <ArrowPathIcon className="h-4 w-4" />
                </button>
                <Button variant="ghost" size="sm" onClick={() => onShare(secret)} title="Share secret">
                    <ShareIcon className="h-4 w-4" />
                </Button>
                <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onCopy(secret)}
                    title="Copy value to clipboard"
                    disabled={copyingId === secret.id}
                    className={copyErrorId === secret.id ? 'text-red-500' : ''}
                >
                    {copyingId === secret.id ? (
                        <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                    ) : copiedId === secret.id ? (
                        <CheckIcon className="h-4 w-4 text-green-500" />
                    ) : (
                        <DocumentDuplicateIcon className="h-4 w-4" />
                    )}
                </Button>
                <Button variant="ghost" size="sm" onClick={() => onDelete(secret)} title="Delete secret" className="text-red-600 hover:text-red-700">
                    <TrashIcon className="h-4 w-4" />
                </Button>
            </div>
        </td>
    </tr>
);
