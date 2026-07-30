import React, { useMemo, useState } from 'react';
import { ClockIcon, TrashIcon } from '@heroicons/react/24/outline';
import { useProjectMemberships, useTransitionMembership } from '../projects/api';
import type { ProjectMembership, MembershipState } from '../../services/projectMemberships';

interface User {
    id: number;
    username?: string;
    displayName?: string;
    email?: string;
}

interface PendingOnboardingSectionProps {
    projectId: number;
    users: User[];
}

// Every non-terminal, non-active state gets the same "still onboarding" tone —
// none of them is the healthy end state (ADR-022: active gets no badge at all).
const STATE_LABEL: Record<string, string> = {
    invited: 'Invite sent — awaiting email confirmation',
    identity_verified: 'Identity verified — awaiting first login',
    provisioned: 'Account ready — awaiting first project access',
};

// The one valid forward transition from each state (the backend enforces this
// linear chain — invited → identity_verified → provisioned → active).
const NEXT_ACTION: Record<string, { action: 'verify' | 'provision' | 'activate'; label: string }> = {
    invited: { action: 'verify', label: 'Mark identity verified' },
    identity_verified: { action: 'provision', label: 'Mark account provisioned' },
    provisioned: { action: 'activate', label: 'Activate — grants project role' },
};

const daysSince = (iso?: string): number | null => {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return null;
    return Math.floor((Date.now() - t) / (24 * 60 * 60 * 1000));
};

const userLabel = (u?: User): string => (u ? u.displayName || u.username || u.email || `user ${u.id}` : 'Unknown user');

/**
 * ADR-022: memberships stuck mid-onboarding (invited / identity_verified /
 * provisioned) under the install's default "allowlist" validation mode don't
 * grant a project role — and so don't appear in the main Members list at all
 * — until an admin walks them through each state to `active`. This section
 * surfaces exactly those stuck memberships (sourced from the lifecycle
 * endpoint, independent of the flat member roster) with a one-step-forward
 * action, so onboarding someone by email invite doesn't silently stall with
 * no visible next step.
 */
export const PendingOnboardingSection: React.FC<PendingOnboardingSectionProps> = ({ projectId, users }) => {
    const { data: memberships = [] } = useProjectMemberships(projectId);
    const transition = useTransitionMembership(projectId);
    const [error, setError] = useState('');

    const usersById = useMemo(() => new Map(users.map((u) => [u.id, u])), [users]);

    const pending = useMemo(
        () => memberships.filter((m) => m.state !== 'active' && m.state !== 'revoked'),
        [memberships]
    );

    if (pending.length === 0) return null;

    const handleTransition = (membership: ProjectMembership, action: 'verify' | 'provision' | 'activate' | 'revoke') => {
        setError('');
        transition.mutate(
            { membershipId: membership.id, action },
            {
                onError: (err: any) =>
                    setError(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Failed to update onboarding.'),
            }
        );
    };

    return (
        <div className="mt-6">
            <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
                Pending onboarding ({pending.length})
            </h3>
            <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
                These people accepted an invite but haven't been stepped through onboarding yet — they don't have
                project access until they reach "active."
            </p>

            {error && (
                <div
                    className="rounded-lg px-3 py-2 text-sm mb-2"
                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                >
                    {error}
                </div>
            )}

            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {pending.map((m) => {
                        const user = usersById.get(m.userId);
                        const next = NEXT_ACTION[m.state as MembershipState];
                        const days = daysSince(m.invitedAt);
                        return (
                            <li key={m.id} className="flex items-center gap-3 px-4 py-3">
                                <div
                                    className="h-8 w-8 rounded-full flex items-center justify-center shrink-0"
                                    style={{ backgroundColor: 'var(--warning-subtle, #fffbeb)', color: 'var(--warning, #b45309)' }}
                                >
                                    <ClockIcon className="h-4 w-4" />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                        {userLabel(user)}
                                    </p>
                                    <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                        {STATE_LABEL[m.state] ?? m.state}
                                        {days != null ? ` · invited ${days} day${days === 1 ? '' : 's'} ago` : ''}
                                    </p>
                                </div>
                                {next && (
                                    <button
                                        type="button"
                                        onClick={() => handleTransition(m, next.action)}
                                        disabled={transition.isPending}
                                        className="px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 shrink-0"
                                        style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                                    >
                                        {next.label}
                                    </button>
                                )}
                                <button
                                    type="button"
                                    onClick={() => handleTransition(m, 'revoke')}
                                    disabled={transition.isPending}
                                    className="p-1.5 rounded-sm transition-colors hover:bg-red-50 disabled:opacity-50 shrink-0"
                                    style={{ color: 'var(--error)' }}
                                    title="Cancel onboarding"
                                >
                                    <TrashIcon className="h-4 w-4" />
                                </button>
                            </li>
                        );
                    })}
                </ul>
            </div>
        </div>
    );
};
