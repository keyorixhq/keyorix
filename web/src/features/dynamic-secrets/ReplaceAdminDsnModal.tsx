import React, { useRef, useState, SubmitEvent } from 'react';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { ADMIN_DSN_FORBIDDEN_MESSAGE, isCloudBackend } from '../../services/dynamicSecrets';
import { useUpdateDynamicConfigAdminDSN } from './api';

export interface ReplaceAdminDsnTarget {
    id: number;
    name: string;
    backendType: string;
}

// What the operator reads for each way the PATCH can fail. `message` is the server's own
// reason (already scrubbed of the DSN by the service layer).
const failureText = (error: unknown): string => {
    const e = error as { kind?: string; message?: string } | null;
    const reason = e?.message ? ` ${e.message}` : '';
    switch (e?.kind) {
        case 'refused':
            return `The server refused this connection string.${reason}`;
        case 'forbidden':
            return ADMIN_DSN_FORBIDDEN_MESSAGE;
        case 'conflict':
            return `While this config has active leases, the new connection string must name the same host(s).${reason}`;
        case 'audit_unavailable':
            return 'The audit log is unavailable, so nothing was changed. Try again shortly.';
        default:
            return e?.message || 'Failed to replace the admin connection string.';
    }
};

/**
 * Replaces a config's stored admin DSN (PATCH .../admin-dsn), e.g. to drop an option the
 * server refuses since #3952. The DSN is a secret: the field is an UNCONTROLLED password
 * input read from a ref at submit, so it is never React state and never rendered; it is
 * emptied the moment the form is submitted or cancelled, whatever the outcome (a refused DSN
 * has to be typed again), and the mutation is reset once it settles.
 */
export const ReplaceAdminDsnModal: React.FC<{
    config: ReplaceAdminDsnTarget;
    onClose: () => void;
    onReplaced: (configName: string) => void;
}> = ({ config, onClose, onReplaced }) => {
    const dsnRef = useRef<HTMLInputElement>(null);
    const [error, setError] = useState('');
    const update = useUpdateDynamicConfigAdminDSN();
    const cloud = isCloudBackend(config.backendType as never);

    const clearDsn = () => {
        if (dsnRef.current) dsnRef.current.value = '';
    };

    const close = () => {
        clearDsn();
        onClose();
    };

    const submit = async (e: SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        const adminDsn = dsnRef.current?.value ?? '';
        if (!adminDsn.trim()) {
            setError(cloud ? 'The cloud config (JSON) is required.' : 'The admin connection string is required.');
            return;
        }
        setError('');
        clearDsn();
        try {
            await update.mutateAsync({ id: config.id, adminDsn });
            onReplaced(config.name);
            onClose();
        } catch (err) {
            setError(failureText(err));
        } finally {
            update.reset();
        }
    };

    return (
        <Modal isOpen onClose={close} title={`Replace admin DSN for ${config.name}`} size="lg">
            <form onSubmit={submit} className="space-y-3" autoComplete="off">
                {error && <Alert type="error" message={error} />}
                <Input
                    ref={dsnRef}
                    label={cloud ? 'New cloud config (JSON)' : 'New admin connection string'}
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={cloud ? '{"…":"…"}' : 'postgres://admin:****@host:5432/db'}
                    helperText="Encrypted at rest; never shown again. It replaces the stored value, so type the whole string. With active leases it must name the same host(s)."
                />
                <div className="flex justify-end gap-2 pt-1">
                    <Button type="button" variant="secondary" onClick={close}>
                        Cancel
                    </Button>
                    <Button type="submit" disabled={update.isPending}>
                        {update.isPending ? 'Replacing…' : 'Replace admin DSN'}
                    </Button>
                </div>
            </form>
        </Modal>
    );
};
