import React, { useState } from 'react';
import { ExclamationTriangleIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useStaleAccounts, useResendSetupLink, useSuspendUser } from './api';
import { copyToClipboard } from '../../utils';

// daysSince returns whole days between now and an ISO timestamp (>= 0).
function daysSince(iso: string): number {
    const ms = Date.now() - new Date(iso).getTime();
    return Math.max(0, Math.floor(ms / (24 * 60 * 60 * 1000)));
}

/**
 * ADR-025 stale-account warnings. Surfaces accounts an admin provisioned but the
 * user never completed (pending_first_login > 7 days), each with a **Resend setup
 * link** action and a **Revoke** (suspend — reversible) action. The query is
 * admin-only; a 403 yields no rows, so non-admins (and the empty case) render
 * nothing. Soft-delete already exists as a row action on the table, so "revoke"
 * here is the distinct, reversible suspend.
 */
export const StaleAccountsSection: React.FC = () => {
    const { data: stale = [] } = useStaleAccounts(7);
    const resend = useResendSetupLink();
    const suspend = useSuspendUser();
    const [dismissed, setDismissed] = useState(false);
    const [note, setNote] = useState('');
    const [confirmingId, setConfirmingId] = useState<number | null>(null);

    if (dismissed || stale.length === 0) return null;

    const handleResend = (id: number, email: string) => {
        setNote('');
        resend.mutate(id, {
            onSuccess: async (outcome) => {
                if (outcome?.link_for_admin) {
                    try {
                        await copyToClipboard(outcome.link_for_admin);
                        setNote(`Setup link for ${email} copied to clipboard.`);
                    } catch {
                        setNote(`Setup link reissued for ${email} (copy it from the user detail page).`);
                    }
                } else {
                    setNote(`Setup link re-sent to ${email}.`);
                }
            },
            onError: (err: any) =>
                setNote(err?.response?.data?.error ?? err?.message ?? 'Failed to resend setup link.'),
        });
    };

    const handleRevoke = (id: number) => {
        setNote('');
        suspend.mutate(id, {
            onSuccess: () => setConfirmingId(null),
            onError: (err: any) => setNote(err?.response?.data?.error ?? err?.message ?? 'Failed to revoke account.'),
        });
    };

    return (
        <div
            className="rounded-lg border mb-4 overflow-hidden"
            style={{ borderColor: 'var(--warning, #d97706)', backgroundColor: 'var(--warning-subtle, #fffbeb)' }}
        >
            <div className="flex items-center justify-between px-4 py-2.5">
                <div className="flex items-center gap-2" style={{ color: 'var(--warning, #92400e)' }}>
                    <ExclamationTriangleIcon className="h-5 w-5 shrink-0" />
                    <span className="text-sm font-semibold">
                        {stale.length} account{stale.length !== 1 ? 's' : ''} pending setup for over 7 days
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

            {note && (
                <p className="px-4 pb-1 text-xs" style={{ color: 'var(--warning, #92400e)' }}>
                    {note}
                </p>
            )}

            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {stale.map((u) => (
                    <li
                        key={u.id}
                        className="flex items-center gap-3 px-4 py-2.5"
                        style={{ backgroundColor: 'var(--bg-surface)' }}
                    >
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                {u.display_name || u.username}
                            </p>
                            <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                {u.email} · {daysSince(u.created_at)} days pending
                            </p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                            <button
                                type="button"
                                onClick={() => handleResend(u.id, u.email)}
                                disabled={resend.isPending}
                                className="px-2.5 py-1 rounded-md text-xs font-medium disabled:opacity-50"
                                style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                            >
                                Resend link
                            </button>
                            {confirmingId === u.id ? (
                                <>
                                    <button
                                        type="button"
                                        onClick={() => handleRevoke(u.id)}
                                        disabled={suspend.isPending}
                                        className="px-2.5 py-1 rounded-md text-xs font-medium disabled:opacity-50"
                                        style={{ backgroundColor: 'var(--error, #b91c1c)', color: '#fff' }}
                                    >
                                        Confirm
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setConfirmingId(null)}
                                        className="px-2.5 py-1 rounded-md text-xs font-medium"
                                        style={{ color: 'var(--text-muted)' }}
                                    >
                                        Cancel
                                    </button>
                                </>
                            ) : (
                                <button
                                    type="button"
                                    onClick={() => setConfirmingId(u.id)}
                                    className="px-2.5 py-1 rounded-md text-xs font-medium border"
                                    style={{ borderColor: 'var(--error, #b91c1c)', color: 'var(--error, #b91c1c)' }}
                                    title="Suspend the account (reversible)"
                                >
                                    Revoke
                                </button>
                            )}
                        </div>
                    </li>
                ))}
            </ul>
        </div>
    );
};
