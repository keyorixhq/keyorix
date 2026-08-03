import React, { useMemo, useState } from 'react';
import { EnvelopeIcon, ExclamationTriangleIcon, TrashIcon } from '@heroicons/react/24/outline';
import { ProjectInvitation } from '../../services/projectInvitations';
import { useProjectInvitations, useRevokeInvitation } from './api';

// "project_developer" → "Developer"
const roleLabel = (role: string) => role.replace(/^project_/, '').replace(/^\w/, (c) => c.toUpperCase());

// A pending invitation older than this is "stale" — likely forgotten. Mirrors the
// backend staleInviteThreshold (ADR-022, 7 days) so the UI flags the same records
// the server's ?stale=true filter would.
const STALE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

// Days since an ISO timestamp, or null if absent/unparseable.
const daysSince = (iso?: string): number | null => {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return null;
    return Math.floor((Date.now() - t) / (24 * 60 * 60 * 1000));
};

// A pending invite is stale once it has been waiting longer than the threshold.
const isStale = (inv: ProjectInvitation): boolean => {
    if (inv.state !== 'pending' || !inv.createdAt) return false;
    const t = new Date(inv.createdAt).getTime();
    return !Number.isNaN(t) && Date.now() - t > STALE_AFTER_MS;
};

const stateStyle = (state: string): React.CSSProperties => {
    switch (state) {
        case 'pending':
            return { backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' };
        case 'accepted':
            return { backgroundColor: 'var(--success-subtle, #dcfce7)', color: 'var(--success, #15803d)' };
        case 'revoked':
        case 'expired':
        default:
            return { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' };
    }
};

const fmtDate = (iso?: string): string => {
    if (!iso) return '';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString();
};

/**
 * ADR-024 invitations list for the Members tab. Shows this project's
 * invitations (pending first) with a revoke action on pending ones. The accept
 * (email/setup-link) half is a backend follow-up; here we surface and manage the
 * pending records.
 */
export const ProjectInvitationsSection: React.FC<{ projectId: number }> = ({ projectId }) => {
    const { data: invitations = [] } = useProjectInvitations(projectId);
    const revoke = useRevokeInvitation(projectId);
    const [error, setError] = useState('');

    // Stale pending first (most urgent), then other pending, then the rest; the
    // query 403s for non-admins → empty.
    const ordered = useMemo(() => {
        const rank = (inv: ProjectInvitation) => {
            const nonStaleRank = inv.state === 'pending' ? 1 : 2;
            return isStale(inv) ? 0 : nonStaleRank;
        };
        return [...invitations].sort((a, b) => rank(a) - rank(b));
    }, [invitations]);

    const staleCount = useMemo(() => invitations.filter(isStale).length, [invitations]);

    if (ordered.length === 0) return null;

    const handleRevoke = (inv: ProjectInvitation) => {
        setError('');
        revoke.mutate(inv.id, {
            onError: (err: any) =>
                setError(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Failed to revoke invitation.'),
        });
    };

    return (
        <div className="mt-6">
            <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
                Invitations
            </h3>

            {error && (
                <div
                    className="rounded-lg px-3 py-2 text-sm mb-2"
                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                >
                    {error}
                </div>
            )}

            {staleCount > 0 && (
                <div
                    className="rounded-lg px-3 py-2 text-sm mb-2 flex items-start gap-2"
                    style={{ backgroundColor: 'var(--warning-subtle, #fffbeb)', color: 'var(--warning, #b45309)' }}
                >
                    <ExclamationTriangleIcon className="h-4 w-4 mt-0.5 shrink-0" />
                    <span>
                        {staleCount === 1 ? '1 invitation has' : `${staleCount} invitations have`} been pending over a
                        week. Consider resending the setup link or revoking.
                    </span>
                </div>
            )}

            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {ordered.map((inv) => {
                        const stale = isStale(inv);
                        const pendingDays = stale ? daysSince(inv.createdAt) : null;
                        return (
                            <li key={inv.id} className="flex items-center gap-3 px-4 py-3">
                                <div
                                    className="h-8 w-8 rounded-full flex items-center justify-center shrink-0"
                                    style={
                                        stale
                                            ? {
                                                  backgroundColor: 'var(--warning-subtle, #fffbeb)',
                                                  color: 'var(--warning, #b45309)',
                                              }
                                            : { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }
                                    }
                                >
                                    <EnvelopeIcon className="h-4 w-4" />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p
                                        className="text-sm font-medium truncate"
                                        style={{ color: 'var(--text-primary)' }}
                                    >
                                        {inv.email}
                                    </p>
                                    <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                        {roleLabel(inv.role)}
                                        {stale && pendingDays != null
                                            ? ` · pending ${pendingDays} days`
                                            : inv.expiresAt &&
                                              inv.state === 'pending' &&
                                              ` · expires ${fmtDate(inv.expiresAt)}`}
                                    </p>
                                </div>
                                {stale && (
                                    <span
                                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium shrink-0"
                                        style={{
                                            backgroundColor: 'var(--warning-subtle, #fffbeb)',
                                            color: 'var(--warning, #b45309)',
                                        }}
                                    >
                                        <ExclamationTriangleIcon className="h-3 w-3" />
                                        Stale
                                    </span>
                                )}
                                <span
                                    className="px-2 py-0.5 rounded-full text-xs font-medium capitalize shrink-0"
                                    style={stateStyle(inv.state)}
                                >
                                    {inv.state}
                                </span>
                                {inv.state === 'pending' && (
                                    <button
                                        type="button"
                                        onClick={() => handleRevoke(inv)}
                                        disabled={revoke.isPending}
                                        className="p-1.5 rounded-sm transition-colors hover:bg-red-50 disabled:opacity-50 shrink-0"
                                        style={{ color: 'var(--error)' }}
                                        title="Revoke invitation"
                                    >
                                        <TrashIcon className="h-4 w-4" />
                                    </button>
                                )}
                            </li>
                        );
                    })}
                </ul>
            </div>
        </div>
    );
};
