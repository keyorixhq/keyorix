import React, { useState } from 'react';
import { apiService } from '../../services/api';
import { Secret } from '../../types';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { Alert } from '../ui/Alert';

interface ShareSecretModalProps {
    secret: Secret;
    isOpen: boolean;
    onClose: () => void;
    onSuccess?: () => void;
}

const PERMISSION_OPTIONS = [
    { value: 'read', label: 'Read Only' },
    { value: 'write', label: 'Read & Write' },
];

export const ShareSecretModal: React.FC<ShareSecretModalProps> = ({
    secret,
    isOpen,
    onClose,
    onSuccess,
}) => {
    const [username, setUsername] = useState('');
    const [permission, setPermission] = useState<'read' | 'write'>('read');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState(false);

    const handleClose = () => {
        setUsername('');
        setPermission('read');
        setError(null);
        setSuccess(false);
        onClose();
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!username.trim()) {
            setError('Please enter a recipient username.');
            return;
        }

        setIsSubmitting(true);
        setError(null);

        try {
            // Look up the user by username
            const results = await apiService.users.search(username.trim());
            const match = results.find(
                (r) => r.name.toLowerCase() === username.trim().toLowerCase()
            );
            if (!match) {
                setError(`User "${username}" not found.`);
                return;
            }

            await apiService.sharing.create({
                secretId: secret.id,
                recipientType: match.type,
                recipientId: match.id,
                permission,
            });

            setSuccess(true);
            onSuccess?.();
            setTimeout(handleClose, 1000);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to share secret.');
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title={`Share "${secret.name}"`} size="md">
            <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                    <Alert type="error" title="Error" message={error} />
                )}
                {success && (
                    <Alert type="success" title="Shared!" message="Secret shared successfully." />
                )}

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Recipient username
                    </label>
                    <Input
                        type="text"
                        placeholder="Enter username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        disabled={isSubmitting || success}
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Permission
                    </label>
                    <Select
                        value={permission}
                        onChange={(e) => setPermission(e.target.value as 'read' | 'write')}
                        options={PERMISSION_OPTIONS}
                        disabled={isSubmitting || success}
                    />
                </div>

                <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <Button type="button" variant="outline" onClick={handleClose} disabled={isSubmitting}>
                        Cancel
                    </Button>
                    <Button type="submit" disabled={isSubmitting || success}>
                        {isSubmitting ? 'Sharing…' : 'Share'}
                    </Button>
                </div>
            </form>
        </Modal>
    );
};
