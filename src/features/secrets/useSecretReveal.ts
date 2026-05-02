import { useState } from 'react';
import { apiService } from '../../services/api';
import { Secret } from '../../types';

export const useSecretReveal = () => {
    const [copyingSecretId, setCopyingSecretId] = useState<number | null>(null);
    const [copiedSecretId, setCopiedSecretId] = useState<number | null>(null);
    const [copyErrorId, setCopyErrorId] = useState<number | null>(null);

    const handleCopySecretValue = async (secret: Secret) => {
        setCopyingSecretId(secret.id);
        setCopyErrorId(null);
        try {
            const versions = await apiService.secrets.getVersions(secret.id);
            if (!versions || versions.length === 0) throw new Error('No versions found');
            const latest = versions[0];
            const decoded = atob(latest.EncryptedValue as unknown as string);
            await navigator.clipboard.writeText(decoded);
            setCopiedSecretId(secret.id);
            setTimeout(() => setCopiedSecretId(null), 2000);
        } catch {
            setCopyErrorId(secret.id);
            setTimeout(() => setCopyErrorId(null), 2000);
        } finally {
            setCopyingSecretId(null);
        }
    };

    return { copyingSecretId, copiedSecretId, copyErrorId, handleCopySecretValue };
};
