import React, { useState } from 'react';
import { Secret } from '../../types';
import { Modal } from '../../components/ui/Modal';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Select } from '../../components/ui/Select';
import { Alert } from '../../components/ui/Alert';
import { useShareSecret } from './api';

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
    const [success, setSuccess] = useState(false);

    const shareSecret = useShareSecret(secret.id);

    const handleClose = () => {
        setUsername('');
        setPermission('read');
        setSuccess(false);
        shareSecret.reset();
        onClose();
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!username.trim()) return;

        shareSecret.mutate(
            { username, permission },
            {
                onSuccess: () => {
                    setSuccess(true);
                    onSuccess?.();
                    setTimeout(handleClose, 1000);
                },
            }
        );
    };

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title={`Share "${secret.name}"`} size="md">
            <form onSubmit={handleSubmit} className="space-y-4">
                {shareSecret.isError && (
                    <Alert
                        type="error"
                        title="Error"
                        message={shareSecret.error instanceof Error ? shareSecret.error.message : 'Failed to share secret.'}
                    />
                )}
                {success && (
                    <Alert type="success" title="Shared!" message="Secret shared successfully." />
                )}

                <div>
                    <label className="block text-sm font-medium text-base-secondary mb-1">
                        Recipient username
                    </label>
                    <Input
                        type="text"
                        placeholder="Enter username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        disabled={shareSecret.isPending || success}
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-base-secondary mb-1">
                        Permission
                    </label>
                    <Select
                        value={permission}
                        onChange={(e) => setPermission(e.target.value as 'read' | 'write')}
                        options={PERMISSION_OPTIONS}
                        disabled={shareSecret.isPending || success}
                    />
                </div>

                <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <Button type="button" variant="outline" onClick={handleClose} disabled={shareSecret.isPending}>
                        Cancel
                    </Button>
                    <Button type="submit" disabled={shareSecret.isPending || success || !username.trim()}>
                        {shareSecret.isPending ? 'Sharing…' : 'Share'}
                    </Button>
                </div>
            </form>
        </Modal>
    );
};
