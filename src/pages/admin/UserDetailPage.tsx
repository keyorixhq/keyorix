import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeftIcon } from '@heroicons/react/24/outline';
import { ROUTES } from '../../constants';
import {
    useUserDetail,
    useUserMemberships,
    useUserRoles,
    useUserPermissions,
    useSuspendUser,
    useReactivateUser,
    useUnlockUser,
    useRequirePasswordReset,
    useRevokeSessions,
    useResendSetupLink,
    AccountStateBadge,
} from '../../features/admin';
import { useMigrateUserToMachine } from '../../features/admin';
import { useAuth } from '../../features/auth';
import { useProjects } from '../../features/projects/api';
import { Button } from '../../components/ui/Button';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { Input } from '../../components/ui/Input';
import { Select } from '../../components/ui/Select';
import { copyToClipboard } from '../../utils';
import { Loading } from '../../components/ui/Loading';
import { MACHINE_IDENTITY_TYPES } from '../../services/machineIdentities';
import type { AdminUser, SetupLinkResult } from '../../services/users';

function formatDate(iso?: string | null): string {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleString(undefined, {
            year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
        });
    } catch {
        return iso;
    }
}

type PendingAction = null | 'suspend' | 'reactivate' | 'reset' | 'unlock' | 'revoke-sessions';

const ACTION_COPY: Record<Exclude<PendingAction, null>, { title: string; body: string; confirm: string; danger?: boolean }> = {
    suspend: { title: 'Suspend user', body: 'Block this user from logging in. This is reversible — you can reactivate them later.', confirm: 'Suspend', danger: true },
    reactivate: { title: 'Reactivate user', body: 'Return this user to the active state and restore their login.', confirm: 'Reactivate' },
    reset: { title: 'Force password reset', body: 'Confine this user to a restricted session until they set a new password at next login.', confirm: 'Force reset', danger: true },
    unlock: { title: 'Clear login lockout', body: 'Remove the active brute-force lockout so this user can sign in again immediately. Does not change their account state.', confirm: 'Unlock' },
    'revoke-sessions': { title: 'Force log out', body: 'Revoke all of this user’s active sessions immediately. They can log back in after re-authenticating — use this for a suspected stolen session or device. Does not change their account state.', confirm: 'Force log out', danger: true },
};

export const UserDetailPage: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const userId = id ? Number(id) : null;
    const navigate = useNavigate();
    const { user: currentUser } = useAuth();

    const { data: detail, isLoading, isError } = useUserDetail(userId);
    const { data: roles = [] } = useUserRoles(userId);
    const { data: permissions = [] } = useUserPermissions(userId);
    const { data: memberships = [] } = useUserMemberships(userId);

    const suspend = useSuspendUser();
    const reactivate = useReactivateUser();
    const unlock = useUnlockUser();
    const requireReset = useRequirePasswordReset();
    const revokeSessions = useRevokeSessions();
    const resend = useResendSetupLink();

    const [pending, setPending] = useState<PendingAction>(null);
    const [note, setNote] = useState('');
    const [error, setError] = useState('');
    const [resentLink, setResentLink] = useState<SetupLinkResult | null>(null);
    const [linkCopied, setLinkCopied] = useState(false);

    // Convert-to-machine-identity form modal (ADR-023).
    const { data: projects = [] } = useProjects();
    const migrate = useMigrateUserToMachine();
    const [showMigrate, setShowMigrate] = useState(false);
    const [migProjectId, setMigProjectId] = useState('');
    const [migType, setMigType] = useState('service');
    const [migName, setMigName] = useState('');
    const [migKeepUser, setMigKeepUser] = useState(false);

    if (isLoading) return <Loading className="py-20" />;
    if (isError || !detail) {
        return (
            <div className="max-w-3xl mx-auto px-4 py-8">
                <Alert type="error" title="Failed to load user" message="The user could not be found or you lack access." />
            </div>
        );
    }

    const user = detail as unknown as AdminUser;
    const isSelf = currentUser?.id === user.id;
    const state = user.account_state || 'active';
    // login_locked_until is emitted by the API only while a lockout is active (ADR-040).
    const locked = !!user.login_locked_until;
    const surface = (err: any, fallback: string) => setError(err?.response?.data?.error ?? err?.message ?? fallback);

    const runAction = () => {
        if (!pending || userId === null) return;
        setError('');
        const opts = {
            onSuccess: () => { setPending(null); setNote(`${ACTION_COPY[pending].confirm} applied.`); },
            onError: (err: any) => { setPending(null); surface(err, 'Action failed.'); },
        };
        if (pending === 'suspend') suspend.mutate(userId, opts);
        else if (pending === 'reactivate') reactivate.mutate(userId, opts);
        else if (pending === 'unlock') unlock.mutate(userId, opts);
        else if (pending === 'revoke-sessions') revokeSessions.mutate(userId, opts);
        else requireReset.mutate(userId, opts);
    };

    const runMigrate = () => {
        if (userId === null || !migProjectId) return;
        setError('');
        migrate.mutate(
            {
                projectId: Number(migProjectId),
                userId,
                body: {
                    username: user.username,
                    identity_type: migType,
                    ...(migName.trim() ? { name: migName.trim() } : {}),
                    keep_user: migKeepUser,
                },
            },
            {
                onSuccess: (d) => {
                    setShowMigrate(false);
                    setNote(`Created machine identity “${d?.machine_identity?.name ?? user.username}”${migKeepUser ? '' : '; source user suspended'}.`);
                },
                onError: (err: any) => surface(err, 'Migration failed.'),
            },
        );
    };

    const handleResend = () => {
        if (userId === null) return;
        setError(''); setNote(''); setResentLink(null); setLinkCopied(false);
        resend.mutate(userId, {
            onSuccess: (outcome) => {
                if (outcome?.link_for_admin) setResentLink(outcome);
                else setNote(`Setup link re-sent to ${user.email}.`);
            },
            onError: (err: any) => surface(err, 'Failed to resend setup link.'),
        });
    };

    const copyLink = async () => {
        if (!resentLink?.link_for_admin) return;
        try {
            await copyToClipboard(resentLink.link_for_admin);
            setLinkCopied(true);
            window.setTimeout(() => setLinkCopied(false), 2000);
        } catch {
            /* link is visible for manual selection */
        }
    };

    const Stat: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
        <div>
            <p className="text-xs uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</p>
            <div className="text-sm mt-0.5" style={{ color: 'var(--text-primary)' }}>{value}</div>
        </div>
    );

    return (
        <div className="max-w-4xl mx-auto px-4 py-8">
            <button
                type="button"
                onClick={() => navigate(ROUTES.ADMIN_USERS)}
                className="inline-flex items-center gap-1.5 text-sm mb-4 hover:opacity-75"
                style={{ color: 'var(--text-muted)' }}
            >
                <ArrowLeftIcon className="h-4 w-4" /> Back to users
            </button>

            {/* Header */}
            <div className="flex items-start justify-between gap-4 mb-6">
                <div className="flex items-center gap-3 min-w-0">
                    <div className="shrink-0 h-12 w-12 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--accent-subtle)' }}>
                        <span className="text-lg font-semibold" style={{ color: 'var(--accent-text)' }}>
                            {(user.display_name || user.username).charAt(0).toUpperCase()}
                        </span>
                    </div>
                    <div className="min-w-0">
                        <h1 className="text-xl font-bold truncate" style={{ color: 'var(--text-primary)' }}>
                            {user.display_name || user.username}
                        </h1>
                        <p className="text-sm truncate" style={{ color: 'var(--text-muted)' }}>@{user.username} · {user.email}</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    {locked && (
                        <span
                            className="text-xs font-medium px-2.5 py-1 rounded-full"
                            style={{ color: 'var(--danger-text, #b91c1c)', backgroundColor: 'var(--danger-subtle, #fee2e2)' }}
                            title={`Locked until ${formatDate(user.login_locked_until)}`}
                        >
                            Locked out
                        </span>
                    )}
                    <AccountStateBadge state={state} deleted={!!user.deleted_at} />
                </div>
            </div>

            {error && <Alert type="error" message={error} dismissible onDismiss={() => setError('')} className="mb-4" />}
            {note && <Alert type="success" message={note} dismissible onDismiss={() => setNote('')} className="mb-4" />}

            {/* Stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6 p-4 rounded-lg border" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                <Stat label="Last login" value={user.last_login_at ? formatDate(user.last_login_at) : <span style={{ color: 'var(--text-muted)' }} className="italic">Never</span>} />
                <Stat label="Created" value={formatDate(user.created_at)} />
                <Stat label="Active projects" value={user.active_project_count ?? 0} />
                <Stat label="Total projects" value={user.project_count ?? 0} />
            </div>

            {/* Action hub */}
            {!user.deleted_at && !isSelf && (
                <div className="mb-6">
                    <h2 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>Account actions</h2>
                    <div className="flex flex-wrap gap-2">
                        {locked && (
                            <Button variant="outline" size="sm" onClick={() => setPending('unlock')}>Unlock login</Button>
                        )}
                        {state === 'suspended' ? (
                            <Button variant="outline" size="sm" onClick={() => setPending('reactivate')}>Reactivate</Button>
                        ) : (
                            <Button variant="outline" size="sm" onClick={() => setPending('suspend')}>Suspend</Button>
                        )}
                        {state === 'active' && (
                            <Button variant="outline" size="sm" onClick={() => setPending('reset')}>Force password reset</Button>
                        )}
                        {state !== 'suspended' && (
                            <Button variant="outline" size="sm" onClick={() => setPending('revoke-sessions')}>Force log out</Button>
                        )}
                        {state === 'pending_first_login' && (
                            <Button variant="outline" size="sm" onClick={handleResend} disabled={resend.isPending}>
                                {resend.isPending ? 'Resending…' : 'Resend setup link'}
                            </Button>
                        )}
                        {state !== 'suspended' && (
                            <Button variant="outline" size="sm" onClick={() => { setError(''); setMigProjectId(''); setMigType('service'); setMigName(''); setMigKeepUser(false); setShowMigrate(true); }}>
                                Convert to machine identity
                            </Button>
                        )}
                    </div>
                    {isSelf && <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>You cannot run lifecycle actions on your own account.</p>}
                </div>
            )}
            {isSelf && (
                <p className="text-xs mb-6" style={{ color: 'var(--text-muted)' }}>Lifecycle actions are unavailable on your own account.</p>
            )}

            {/* Resent out-of-band link */}
            {resentLink?.link_for_admin && (
                <div className="mb-6 p-3 rounded-lg border" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    <p className="text-sm mb-2" style={{ color: 'var(--text-secondary)' }}>Relay this single-use setup link to the user securely:</p>
                    <div className="flex items-stretch gap-2">
                        <code className="flex-1 min-w-0 px-3 py-2 text-xs font-mono break-all rounded-lg border" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-app)', color: 'var(--text-secondary)' }}>
                            {resentLink.link_for_admin}
                        </code>
                        <Button variant="outline" onClick={copyLink} className="shrink-0">{linkCopied ? 'Copied' : 'Copy'}</Button>
                    </div>
                </div>
            )}

            {/* Assignments */}
            <h2 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>Roles</h2>
            <div className="flex flex-wrap gap-1.5 mb-6">
                {roles.length === 0 ? (
                    <span className="text-sm" style={{ color: 'var(--text-muted)' }}>No roles assigned.</span>
                ) : (
                    roles.map((r) => (
                        <span key={r.id} className="px-2 py-0.5 rounded-full text-xs font-medium" style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-secondary)' }}>
                            {r.name}
                        </span>
                    ))
                )}
            </div>

            {/* Effective permissions: what the user's roles actually grant (union,
                excluding expired time-bound grants). Read-only, for audit/review. */}
            <h2 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>Effective permissions</h2>
            <div className="flex flex-wrap gap-1.5 mb-6">
                {permissions.length === 0 ? (
                    <span className="text-sm" style={{ color: 'var(--text-muted)' }}>No permissions.</span>
                ) : (
                    [...permissions]
                        .sort((a, b) => a.name.localeCompare(b.name))
                        .map((p) => (
                            <span key={p.id ?? p.name} title={p.description || undefined}
                                className="px-2 py-0.5 rounded-full text-xs font-mono"
                                style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}>
                                {p.name}
                            </span>
                        ))
                )}
            </div>

            <h2 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>Project assignments</h2>
            <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                {memberships.length === 0 ? (
                    <p className="p-4 text-sm" style={{ color: 'var(--text-muted)' }}>Not a member of any project.</p>
                ) : (
                    <table className="min-w-full text-sm">
                        <thead>
                            <tr style={{ backgroundColor: 'var(--bg-surface)' }}>
                                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Project</th>
                                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Role</th>
                                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Membership</th>
                            </tr>
                        </thead>
                        <tbody>
                            {memberships.map((m) => (
                                <tr key={`${m.project_id}-${m.role}`} className="border-t" style={{ borderColor: 'var(--border)' }}>
                                    <td className="px-4 py-2" style={{ color: 'var(--text-primary)' }}>{m.project_name || `#${m.project_id}`}</td>
                                    <td className="px-4 py-2" style={{ color: 'var(--text-secondary)' }}>{m.role || '—'}</td>
                                    <td className="px-4 py-2 capitalize" style={{ color: 'var(--text-secondary)' }}>{m.state}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {/* Confirm modal for consequential transitions */}
            <Modal isOpen={pending !== null} onClose={() => setPending(null)} title={pending ? ACTION_COPY[pending].title : ''} size="sm">
                {pending && (
                    <div className="space-y-4">
                        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{ACTION_COPY[pending].body}</p>
                        <div className="flex justify-end gap-3 pt-2">
                            <Button variant="ghost" onClick={() => setPending(null)}>Cancel</Button>
                            <Button variant={ACTION_COPY[pending].danger ? 'danger' : 'primary'} onClick={runAction}>
                                {ACTION_COPY[pending].confirm}
                            </Button>
                        </div>
                    </div>
                )}
            </Modal>

            {/* Convert to machine identity (ADR-023) */}
            <Modal isOpen={showMigrate} onClose={() => setShowMigrate(false)} title="Convert to machine identity" size="sm">
                <div className="space-y-4">
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Create a project machine identity for <span className="font-medium">{user.username}</span>. Unless you keep the user, the source account is suspended so it can no longer log in (it is never deleted).
                    </p>
                    <Select
                        label="Project"
                        placeholder="Select a project"
                        value={migProjectId}
                        onChange={(e) => setMigProjectId(e.target.value)}
                        options={projects.map((p) => ({ value: String(p.id), label: p.name }))}
                        fullWidth
                    />
                    <Select
                        label="Identity type"
                        value={migType}
                        onChange={(e) => setMigType(e.target.value)}
                        options={MACHINE_IDENTITY_TYPES.map((t) => ({ value: t, label: t }))}
                        fullWidth
                    />
                    <Input
                        label="Name (optional)"
                        placeholder={user.username}
                        value={migName}
                        onChange={(e) => setMigName(e.target.value)}
                        fullWidth
                    />
                    <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
                        <input type="checkbox" checked={migKeepUser} onChange={(e) => setMigKeepUser(e.target.checked)} />
                        Keep the source user active (don’t suspend)
                    </label>
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={() => setShowMigrate(false)}>Cancel</Button>
                        <Button variant="primary" onClick={runMigrate} disabled={!migProjectId || migrate.isPending} loading={migrate.isPending}>
                            Convert
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
