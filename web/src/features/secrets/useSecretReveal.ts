import { useState } from 'react';
import { secretsApi } from '../../services/secrets';
import { Secret } from '../../types';
import { copyToClipboard } from '../../utils';

export const useSecretReveal = () => {
    const [copyingSecretId, setCopyingSecretId] = useState<number | null>(null);
    const [copiedSecretId, setCopiedSecretId] = useState<number | null>(null);
    const [copyErrorId, setCopyErrorId] = useState<number | null>(null);

    const handleCopySecretValue = async (secret: Secret) => {
        setCopyingSecretId(secret.id);
        setCopyErrorId(null);
        try {
            // #2450: GET .../versions never carries a value field (it's version
            // METADATA only) -- the actual plaintext comes from
            // secretsApi.getValue (GET /secrets/{id}?include_value=true).
            const value = await secretsApi.getValue(secret.id);
            await copyToClipboard(value);
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
