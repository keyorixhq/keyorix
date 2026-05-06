import { useState } from 'react';
import { secretsApi } from '../../services/secrets';
import { Secret } from '../../types';

export const useSecretReveal = () => {
    const [copyingSecretId, setCopyingSecretId] = useState<number | null>(null);
    const [copiedSecretId, setCopiedSecretId] = useState<number | null>(null);
    const [copyErrorId, setCopyErrorId] = useState<number | null>(null);

    const handleCopySecretValue = async (secret: Secret) => {
        setCopyingSecretId(secret.id);
        setCopyErrorId(null);
        try {
            const versions = await secretsApi.getVersions(secret.id);
            if (!versions || versions.length === 0) throw new Error('No versions found');
            const latest = versions[0]!;
            const decoded = atob(latest.EncryptedValue as unknown as string);
            await navigator.clipboard.writeText(decoded);

            // Clear clipboard after 30s
            const CLEAR_MS = 30000;
            const clearClipboard = async () => {
                try {
                    const text = await navigator.clipboard.readText();
                    if (text === decoded) await navigator.clipboard.writeText('');
                } catch {
                    try { await navigator.clipboard.writeText(''); } catch {}
                }
            };
            setTimeout(async () => {
                if (document.hasFocus()) {
                    await clearClipboard();
                } else {
                    const onVisible = async () => {
                        if (document.visibilityState === 'visible') {
                            document.removeEventListener('visibilitychange', onVisible);
                            await clearClipboard();
                        }
                    };
                    document.addEventListener('visibilitychange', onVisible);
                }
            }, CLEAR_MS);
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
