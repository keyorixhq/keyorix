import React, { useState } from 'react';
import { CpuChipIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useStaleMachineTokens } from './api';
import { lastUsedLabel } from './tokenUtils';

/**
 * Machine-token hygiene (#359), the non-human counterpart to PATHygieneSection.
 * Surfaces the deployment-wide machine-identity credentials an admin should revoke —
 * expired-but-never-revoked or stale (unused beyond the window). Admin-only
 * (system.read); a 403 yields no rows, so non-admins (and the empty case) render
 * nothing. Read-only awareness surface; revoke happens per-machine.
 */
export const MachineTokenHygieneSection: React.FC = () => {
    const { data: tokens = [] } = useStaleMachineTokens(90);
    const [dismissed, setDismissed] = useState(false);

    if (dismissed || tokens.length === 0) return null;

    const flag = (t: { expired: boolean; stale: boolean }) => {
        const expiredLabel = t.stale ? 'expired · stale' : 'expired';
        return t.expired ? expiredLabel : 'stale';
    };

    return (
        <div
            className="rounded-lg border mb-4 overflow-hidden"
            style={{ borderColor: 'var(--warning, #d97706)', backgroundColor: 'var(--warning-subtle, #fffbeb)' }}
        >
            <div className="flex items-center justify-between px-4 py-2.5">
                <div className="flex items-center gap-2" style={{ color: 'var(--warning, #92400e)' }}>
                    <CpuChipIcon className="h-5 w-5 shrink-0" />
                    <span className="text-sm font-semibold">
                        {tokens.length} machine token{tokens.length !== 1 ? 's' : ''} stale or expired-but-active
                    </span>
                </div>
                <button
                    type="button"
                    onClick={() => setDismissed(true)}
                    className="p-1 rounded-sm hover:opacity-70"
                    style={{ color: 'var(--warning, #92400e)' }}
                    title="Dismiss"
                >
                    <XMarkIcon className="h-4 w-4" />
                </button>
            </div>

            <p className="px-4 pb-1 text-xs" style={{ color: 'var(--warning, #92400e)' }}>
                Non-human credentials that are candidates for revocation. Revoke them from the owning machine identity.
            </p>

            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {tokens.map((t) => (
                    <li
                        key={t.id}
                        className="flex items-center gap-3 px-4 py-2.5"
                        style={{ backgroundColor: 'var(--bg-surface)' }}
                    >
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                {t.name}{' '}
                                <span className="font-normal" style={{ color: 'var(--text-muted)' }}>
                                    {t.token_prefix}…
                                </span>
                            </p>
                            <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                machine #{t.machine_identity_id} · {lastUsedLabel(t.last_used_at)}
                            </p>
                        </div>
                        <span
                            className="px-2 py-0.5 rounded-full text-xs font-medium shrink-0 capitalize"
                            style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--warning, #92400e)' }}
                        >
                            {flag(t)}
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    );
};
