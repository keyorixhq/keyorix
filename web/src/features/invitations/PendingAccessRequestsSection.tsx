import React, { useMemo, useState } from 'react';
import { CheckIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { PROJECT_ROLES } from '../../services/projects';
import { AccessRequest } from '../../services/projectInvitations';
import { useProjectAccessRequests, useResolveAccessRequest } from './api';

// "project_developer" → "Developer"
const roleLabel = (role: string) => role.replace(/^project_/, '').replace(/^\w/, (c) => c.toUpperCase());

interface UserLite {
    id: number;
    username?: string;
    displayName?: string;
    email?: string;
}

interface PendingAccessRequestsSectionProps {
    projectId: number;
    /** Users already loaded by the Members tab, used to resolve userId → name. */
    users: UserLite[];
}

/**
 * ADR-024 "Pending requests" section for the Members tab. Lists pending access
 * requests with approve-with-role / reject-with-reason. No bulk approve — each
 * request is resolved individually so the granted role is a deliberate choice.
 */
export const PendingAccessRequestsSection: React.FC<PendingAccessRequestsSectionProps> = ({ projectId, users }) => {
    const { data: requests = [] } = useProjectAccessRequests(projectId);
    const pending = useMemo(() => requests.filter((r) => r.state === 'pending'), [requests]);

    const userById = useMemo(() => {
        const m = new Map<number, UserLite>();
        users.forEach((u) => m.set(u.id, u));
        return m;
    }, [users]);

    // The query 403s for non-admins (retry disabled) → nothing pending to show.
    if (pending.length === 0) return null;

    return (
        <div className="mt-6">
            <div className="flex items-center gap-2 mb-2">
                <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Pending requests
                </h3>
                <span
                    className="inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 rounded-full text-xs font-semibold"
                    style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' }}
                >
                    {pending.length}
                </span>
            </div>
            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {pending.map((req) => (
                        <AccessRequestRow
                            key={req.id}
                            projectId={projectId}
                            request={req}
                            user={userById.get(req.userId)}
                        />
                    ))}
                </ul>
            </div>
        </div>
    );
};

interface AccessRequestRowProps {
    projectId: number;
    request: AccessRequest;
    user: UserLite | undefined;
}

const AccessRequestRow: React.FC<AccessRequestRowProps> = ({ projectId, request, user }) => {
    const resolve = useResolveAccessRequest(projectId);
    const initialRole =
        request.suggestedRole && PROJECT_ROLES.includes(request.suggestedRole as any)
            ? request.suggestedRole
            : PROJECT_ROLES[2]; // project_viewer
    const [grantRole, setGrantRole] = useState<string>(initialRole);
    const [rejecting, setRejecting] = useState(false);
    const [reason, setReason] = useState('');
    const [error, setError] = useState('');

    const name = user?.displayName || user?.username || `User #${request.userId}`;
    const subtitle = user?.email || (request.suggestedRole ? `requested ${roleLabel(request.suggestedRole)}` : '');

    const onError = (err: any) =>
        setError(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Failed to resolve request.');

    const approve = () => {
        setError('');
        resolve.mutate({ requestId: request.id, action: 'approve', grantedRole: grantRole }, { onError });
    };

    const confirmReject = () => {
        setError('');
        resolve.mutate(
            { requestId: request.id, action: 'reject', reason: reason.trim() },
            { onError, onSuccess: () => setRejecting(false) }
        );
    };

    const controlStyle: React.CSSProperties = {
        backgroundColor: 'var(--bg-app)',
        border: '1px solid var(--border)',
        color: 'var(--text-primary)',
    };

    return (
        <li className="px-4 py-3">
            <div className="flex items-center gap-3">
                <div
                    className="h-8 w-8 rounded-full flex items-center justify-center shrink-0 text-xs font-semibold"
                    style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' }}
                >
                    {name.charAt(0).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                        {name}
                    </p>
                    <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                        {subtitle}
                    </p>
                    {request.reason && (
                        <p className="text-xs mt-0.5 italic truncate" style={{ color: 'var(--text-secondary)' }}>
                            “{request.reason}”
                        </p>
                    )}
                </div>

                {request.requiredApprovals > 1 && (
                    <span
                        className="text-xs px-2 py-1 rounded-md shrink-0"
                        style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-secondary)' }}
                        title="Dual control: distinct approvers required before the role is granted"
                    >
                        {request.approvalsReceived} of {request.requiredApprovals} approvals
                    </span>
                )}

                {!rejecting && (
                    <>
                        <select
                            value={grantRole}
                            onChange={(e) => setGrantRole(e.target.value)}
                            disabled={resolve.isPending}
                            className="rounded-lg px-2 py-1 text-xs outline-hidden shrink-0"
                            style={controlStyle}
                            title="Role to grant on approval"
                        >
                            {PROJECT_ROLES.map((r) => (
                                <option key={r} value={r}>
                                    {roleLabel(r)}
                                </option>
                            ))}
                        </select>
                        <button
                            type="button"
                            onClick={approve}
                            disabled={resolve.isPending}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium disabled:opacity-50 shrink-0"
                            style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                            title="Approve and grant the selected role"
                        >
                            <CheckIcon className="h-3.5 w-3.5" />
                            Approve
                        </button>
                        <button
                            type="button"
                            onClick={() => setRejecting(true)}
                            disabled={resolve.isPending}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium disabled:opacity-50 shrink-0"
                            style={{ border: '1px solid var(--border)', color: 'var(--error)' }}
                            title="Reject this request"
                        >
                            <XMarkIcon className="h-3.5 w-3.5" />
                            Reject
                        </button>
                    </>
                )}
            </div>

            {rejecting && (
                <div className="mt-2 flex items-center gap-2">
                    <input
                        type="text"
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                        placeholder="Reason (optional)"
                        autoFocus
                        className="flex-1 rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={controlStyle}
                    />
                    <button
                        type="button"
                        onClick={confirmReject}
                        disabled={resolve.isPending}
                        className="px-2.5 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 shrink-0"
                        style={{ backgroundColor: 'var(--error)', color: '#fff' }}
                    >
                        Confirm reject
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setRejecting(false);
                            setReason('');
                        }}
                        disabled={resolve.isPending}
                        className="px-2.5 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 shrink-0"
                        style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                    >
                        Cancel
                    </button>
                </div>
            )}

            {error && (
                <p className="text-xs mt-1.5" style={{ color: 'var(--error)' }}>
                    {error}
                </p>
            )}
        </li>
    );
};
