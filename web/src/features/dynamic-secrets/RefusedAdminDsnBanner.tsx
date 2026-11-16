import React from 'react';
import { isAxiosError } from 'axios';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import { useRefusedAdminDsn } from './api';
import type { ReplaceAdminDsnTarget } from './ReplaceAdminDsnModal';

/**
 * Lists the selected project's configs whose stored admin DSN names an option the server has
 * refused since #3952 (they can no longer issue), with a button that opens the replace form.
 * The report carries config and option NAMES only (never a DSN). It needs dynamic-secret
 * admin authority on the server, so it is only requested for roles that can manage configs,
 * and a 403 (a writer without that authority) shows nothing rather than an error.
 */
export const RefusedAdminDsnBanner: React.FC<{
    projectId: number;
    canManage: boolean;
    onReplace: (config: ReplaceAdminDsnTarget) => void;
}> = ({ projectId, canManage, onReplace }) => {
    const { data, error } = useRefusedAdminDsn(projectId, canManage);

    if (!canManage || projectId <= 0) return null;
    if (error) {
        if (isAxiosError(error) && error.response?.status === 403) return null;
        return (
            <div className="mb-4">
                <Alert type="warning" message="Could not check this project for refused admin DSNs." />
            </div>
        );
    }
    const configs = data?.configs ?? [];
    const unreadable = data?.unreadable ?? 0;
    if (configs.length === 0 && unreadable === 0) return null;

    return (
        <div className="mb-4" data-testid="refused-admin-dsn-banner">
            <Alert
                type="warning"
                title={
                    configs.length > 0
                        ? `${configs.length} ${configs.length === 1 ? 'config has' : 'configs have'} a refused admin DSN`
                        : 'Some admin DSNs could not be checked'
                }
            >
                {configs.length > 0 && (
                    <>
                        <p className="mb-2">
                            The stored admin connection string names a driver option the server no longer accepts, so
                            these configs cannot issue credentials until it is replaced.
                        </p>
                        <ul className="space-y-2">
                            {configs.map((c) => (
                                <li key={c.id} className="flex items-center justify-between gap-3">
                                    <span className="min-w-0">
                                        <span className="font-medium">{c.name}</span>
                                        <span className="block text-xs">
                                            {c.backendType} · refused: {c.refusedOptions.join(', ') || 'unknown option'}
                                            {c.liveLeases > 0
                                                ? ` · ${c.liveLeases} active ${c.liveLeases === 1 ? 'lease' : 'leases'}`
                                                : ''}
                                        </span>
                                    </span>
                                    <Button
                                        type="button"
                                        size="sm"
                                        variant="secondary"
                                        aria-label={`Fix admin DSN for ${c.name}`}
                                        onClick={() =>
                                            onReplace({ id: c.id, name: c.name, backendType: c.backendType })
                                        }
                                    >
                                        Replace admin DSN
                                    </Button>
                                </li>
                            ))}
                        </ul>
                    </>
                )}
                {unreadable > 0 && (
                    <p className="mt-2 text-xs">
                        {unreadable} {unreadable === 1 ? 'config' : 'configs'} could not be checked because the stored
                        admin DSN could not be decrypted.
                    </p>
                )}
            </Alert>
        </div>
    );
};
