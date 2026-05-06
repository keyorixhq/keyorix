import React from 'react';
import {
    EyeIcon, PencilIcon, TrashIcon, ShareIcon,
    DocumentDuplicateIcon, CheckIcon, ArrowPathIcon,
} from '@heroicons/react/24/outline';
import { Secret } from '../../types';

const formatDate = (d: string | Date) =>
    new Intl.DateTimeFormat('en', { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(d));

interface SecretTableRowProps {
    secret: Secret;
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
    secret, isSelected, onToggleSelect,
    onView, onEdit, onDelete, onShare, onRotate, onCopy,
    copyingId, copiedId, copyErrorId,
}) => (
    <tr className={`hover:bg-subtle ${isSelected ? 'bg-accent-subtle' : ''}`}>
        <td className="px-4 py-4 w-10">
            <input
                type="checkbox"
                className="rounded border-base text-blue-600 focus:ring-blue-500"
                checked={isSelected}
                onChange={() => onToggleSelect(secret.id)}
            />
        </td>
        <td className="px-6 py-4">
            <div className="text-sm font-medium text-base-primary">{secret.name}</div>
            {secret.tags.length > 0 && (
                <div className="flex items-center space-x-1 mt-1">
                    {secret.tags.slice(0, 3).map(tag => (
                        <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-subtle text-base-secondary">
                            {tag}
                        </span>
                    ))}
                    {secret.tags.length > 3 && (
                        <span className="text-xs text-base-muted">+{secret.tags.length - 3} more</span>
                    )}
                </div>
            )}
        </td>
        <td className="px-6 py-4 whitespace-nowrap">
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                {secret.type}
            </span>
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-subtle text-base-secondary capitalize">
                {secret.environment || 'production'}
            </span>
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
            {secret.isShared ? (
                <div className="flex items-center">
                    <ShareIcon className="h-4 w-4 mr-1 text-green-500" />
                    <span>{secret.shareCount} shares</span>
                </div>
            ) : <span>Private</span>}
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
            <div>
                <div>{formatDate(secret.lastModified)}</div>
                <div className="text-xs">by {secret.owner}</div>
            </div>
        </td>
        <td className="px-3 py-4 whitespace-nowrap text-right text-sm font-medium">
            <div className="flex items-center justify-end gap-0.5">
                <button onClick={() => onView(secret)} title="View" className="p-1 text-base-muted hover:text-base-primary transition-colors"><EyeIcon className="h-4 w-4" /></button>
                <button onClick={() => onEdit(secret)} title="Edit" className="p-1 text-base-muted hover:text-base-primary transition-colors"><PencilIcon className="h-4 w-4" /></button>
                <button onClick={() => onRotate(secret)} title="Rotate" className="p-1 text-base-muted hover:text-green-600 transition-colors"><ArrowPathIcon className="h-4 w-4" /></button>
                <button onClick={() => onShare(secret)} title="Share" className="p-1 text-base-muted hover:text-blue-600 transition-colors"><ShareIcon className="h-4 w-4" /></button>
                <button
                    onClick={() => onCopy(secret)}
                    title="Copy value"
                    disabled={copyingId === secret.id}
                    className={`p-1 transition-colors ${copyErrorId === secret.id ? 'text-red-500' : 'text-base-muted hover:text-base-primary'}`}
                >
                    {copyingId === secret.id ? (
                        <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                    ) : copiedId === secret.id ? (
                        <CheckIcon className="h-4 w-4 text-green-500" />
                    ) : (
                        <DocumentDuplicateIcon className="h-4 w-4" />
                    )}
                </button>
                <button onClick={() => onDelete(secret)} title="Delete" className="p-1 text-base-muted hover:text-red-600 transition-colors"><TrashIcon className="h-4 w-4" /></button>
            </div>
        </td>
    </tr>
);
