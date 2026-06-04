import React, { useState } from 'react';
import {
    UserIcon,
    ShieldCheckIcon,
    ComputerDesktopIcon,
    KeyIcon,
    DevicePhoneMobileIcon,
    TrashIcon,
    ClipboardDocumentIcon,
    CheckIcon,
    PlusIcon,
} from '@heroicons/react/24/outline';
import { useAuthStore } from '../../store/authStore';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Alert } from '../../components/ui/Alert';
import { Spinner } from '../../components/ui/Loading';
import { Modal } from '../../components/ui/Modal';
import {
    useUpdateProfile,
    useChangePassword,
    useSessions,
    useRevokeSession,
    usePersonalTokens,
    useCreatePersonalToken,
    useRevokePersonalToken,
} from '../../features/account';
import type { AccountSession } from '../../services/account';
import type { PersonalAccessToken } from '../../services/personalTokens';

const TABS = [
    { id: 'profile', label: 'Basic Info', icon: UserIcon },
    { id: 'security', label: 'Security', icon: ShieldCheckIcon },
    { id: 'sessions', label: 'Active Sessions', icon: ComputerDesktopIcon },
    { id: 'tokens', label: 'API Tokens', icon: KeyIcon },
] as const;

function formatDate(value?: string | null): string {
    if (!value) return '—';
    const d = new Date(value);
    return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

// ── Basic Info ──────────────────────────────────────────────────────────────

const BasicInfoTab: React.FC = () => {
    const { user, setUser } = useAuthStore();
    const [displayName, setDisplayName] = useState(user?.displayName || '');
    const [email, setEmail] = useState(user?.email || '');
    const [saved, setSaved] = useState(false);
    const updateProfile = useUpdateProfile();

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setSaved(false);
        updateProfile.mutate(
            { display_name: displayName, email },
            {
                onSuccess: (p) => {
                    setSaved(true);
                    if (user) {
                        setUser({ ...user, displayName: p.display_name, email: p.email });
                    }
                },
            }
        );
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6 max-w-xl">
            <div>
                <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                    Profile Information
                </h3>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Update your display name and email address.
                </p>
            </div>

            {updateProfile.isError && (
                <Alert
                    type="error"
                    title="Could not update profile"
                    message={(updateProfile.error as Error)?.message || 'Please try again.'}
                />
            )}
            {saved && !updateProfile.isPending && (
                <Alert type="success" title="Saved" message="Your profile has been updated." />
            )}

            <Input
                label="Display Name"
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                required
            />
            <Input
                label="Email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
            />

            <div>
                <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                    Username
                </label>
                <div
                    className="text-sm px-3 py-2 rounded-md"
                    style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-app)' }}
                >
                    {user?.username}
                </div>
                <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                    Your username and roles are managed by administrators.
                </p>
            </div>

            <div className="flex justify-end">
                <Button type="submit" disabled={updateProfile.isPending}>
                    {updateProfile.isPending && <Spinner size="sm" className="mr-2" />}
                    Save Changes
                </Button>
            </div>
        </form>
    );
};

// ── Security ────────────────────────────────────────────────────────────────

const SecurityTab: React.FC = () => {
    const [current, setCurrent] = useState('');
    const [next, setNext] = useState('');
    const [confirm, setConfirm] = useState('');
    const [localError, setLocalError] = useState('');
    const [done, setDone] = useState(false);
    const changePassword = useChangePassword();

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setLocalError('');
        setDone(false);
        if (next !== confirm) {
            setLocalError('New passwords do not match.');
            return;
        }
        if (next.length < 8) {
            setLocalError('New password must be at least 8 characters.');
            return;
        }
        changePassword.mutate(
            { current_password: current, new_password: next },
            {
                onSuccess: () => {
                    setDone(true);
                    setCurrent('');
                    setNext('');
                    setConfirm('');
                },
            }
        );
    };

    return (
        <div className="space-y-10 max-w-xl">
            <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                    <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                        Change Password
                    </h3>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Changing your password signs out your other active sessions.
                    </p>
                </div>

                {(localError || changePassword.isError) && (
                    <Alert
                        type="error"
                        title="Could not change password"
                        message={localError || (changePassword.error as Error)?.message || 'Please try again.'}
                    />
                )}
                {done && !changePassword.isPending && (
                    <Alert type="success" title="Password changed" message="Other sessions have been signed out." />
                )}

                <Input
                    label="Current Password"
                    type="password"
                    value={current}
                    onChange={(e) => setCurrent(e.target.value)}
                    required
                />
                <Input
                    label="New Password"
                    type="password"
                    value={next}
                    onChange={(e) => setNext(e.target.value)}
                    required
                />
                <Input
                    label="Confirm New Password"
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    required
                />
                <div className="flex justify-end">
                    <Button type="submit" disabled={changePassword.isPending}>
                        {changePassword.isPending && <Spinner size="sm" className="mr-2" />}
                        <KeyIcon className="h-4 w-4 mr-2" />
                        Change Password
                    </Button>
                </div>
            </form>

            <div className="pt-8 border-t" style={{ borderColor: 'var(--border)' }}>
                <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                    Two-Factor Authentication
                </h3>
                <div
                    className="mt-4 rounded-lg p-5 flex items-center justify-between"
                    style={{ backgroundColor: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
                >
                    <div className="flex items-center">
                        <DevicePhoneMobileIcon className="h-7 w-7 mr-4" style={{ color: 'var(--text-muted)' }} />
                        <div>
                            <h4 className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                                Authenticator App
                            </h4>
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                Coming soon — TOTP-based two-factor authentication.
                            </p>
                        </div>
                    </div>
                    <span
                        className="text-xs font-medium px-2.5 py-1 rounded-full"
                        style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-app)' }}
                    >
                        Soon
                    </span>
                </div>
            </div>
        </div>
    );
};

// ── Active Sessions ───────────────────────────────────────────────────────────

const SessionsTab: React.FC = () => {
    const { data: sessions, isLoading, isError } = useSessions();
    const revoke = useRevokeSession();

    if (isLoading) {
        return (
            <div className="flex justify-center py-10">
                <Spinner />
            </div>
        );
    }
    if (isError) {
        return <Alert type="error" title="Could not load sessions" message="Please try again." />;
    }

    return (
        <div className="space-y-4">
            <div>
                <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                    Active Sessions
                </h3>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Devices currently signed in to your account. End any session you don't recognise.
                </p>
            </div>

            <div className="space-y-3">
                {(sessions || []).map((s: AccountSession) => (
                    <div
                        key={s.id}
                        className="rounded-lg p-4 flex items-center justify-between"
                        style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)' }}
                    >
                        <div className="min-w-0">
                            <div className="flex items-center gap-2">
                                <span className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                    {s.user_agent || 'Unknown device'}
                                </span>
                                {s.current && (
                                    <span
                                        className="text-xs font-medium px-2 py-0.5 rounded-full"
                                        style={{ color: 'var(--accent-text)', backgroundColor: 'var(--accent-subtle)' }}
                                    >
                                        Current
                                    </span>
                                )}
                            </div>
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                {s.ip_address || 'unknown IP'} · last active {formatDate(s.last_seen_at)}
                            </p>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            disabled={s.current || revoke.isPending}
                            onClick={() => revoke.mutate(s.id)}
                            title={s.current ? 'You cannot end your current session here' : 'End this session'}
                        >
                            End Session
                        </Button>
                    </div>
                ))}
                {(sessions || []).length === 0 && (
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        No active sessions.
                    </p>
                )}
            </div>
        </div>
    );
};

// ── API Tokens ────────────────────────────────────────────────────────────────

const TokensTab: React.FC = () => {
    const { data: tokens, isLoading, isError } = usePersonalTokens();
    const createToken = useCreatePersonalToken();
    const revoke = useRevokePersonalToken();

    const [showCreate, setShowCreate] = useState(false);
    const [name, setName] = useState('');
    const [expiresAt, setExpiresAt] = useState('');
    const [newToken, setNewToken] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);

    const openCreate = () => {
        setName('');
        setExpiresAt('');
        setNewToken(null);
        setCopied(false);
        createToken.reset();
        setShowCreate(true);
    };

    const handleCreate = (e: React.FormEvent) => {
        e.preventDefault();
        const body = expiresAt
            ? { name, expires_at: new Date(expiresAt).toISOString() }
            : { name };
        createToken.mutate(body, { onSuccess: (res) => setNewToken(res.token) });
    };

    const copy = async () => {
        if (!newToken) return;
        await navigator.clipboard.writeText(newToken);
        setCopied(true);
    };

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between">
                <div>
                    <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                        Personal Access Tokens
                    </h3>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Tokens authenticate API and CLI requests as you, with all of your permissions.
                    </p>
                </div>
                <Button size="sm" onClick={openCreate}>
                    <PlusIcon className="h-4 w-4 mr-1.5" />
                    New Token
                </Button>
            </div>

            {isLoading ? (
                <div className="flex justify-center py-10">
                    <Spinner />
                </div>
            ) : isError ? (
                <Alert type="error" title="Could not load tokens" message="Please try again." />
            ) : (
                <div className="space-y-3">
                    {(tokens || []).map((t: PersonalAccessToken) => (
                        <div
                            key={t.id}
                            className="rounded-lg p-4 flex items-center justify-between"
                            style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', opacity: t.revoked ? 0.5 : 1 }}
                        >
                            <div className="min-w-0">
                                <div className="flex items-center gap-2">
                                    <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                                        {t.name}
                                    </span>
                                    <code className="text-xs" style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                                        {t.token_prefix}…
                                    </code>
                                    {t.revoked && (
                                        <span className="text-xs px-2 py-0.5 rounded-full" style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-app)' }}>
                                            revoked
                                        </span>
                                    )}
                                </div>
                                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                    created {formatDate(t.created_at)} · last used {formatDate(t.last_used_at)} ·{' '}
                                    {t.expires_at ? `expires ${formatDate(t.expires_at)}` : 'never expires'}
                                </p>
                            </div>
                            {!t.revoked && (
                                <Button
                                    variant="outline"
                                    size="sm"
                                    disabled={revoke.isPending}
                                    onClick={() => revoke.mutate(t.id)}
                                    title="Revoke this token"
                                >
                                    <TrashIcon className="h-4 w-4" />
                                </Button>
                            )}
                        </div>
                    ))}
                    {(tokens || []).length === 0 && (
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                            You have no personal access tokens yet.
                        </p>
                    )}
                </div>
            )}

            <Modal isOpen={showCreate} onClose={() => setShowCreate(false)} title="New Personal Access Token">
                {newToken ? (
                    <div className="space-y-4">
                        <Alert
                            type="warning"
                            title="Copy your token now"
                            message="This is the only time the token will be shown. Store it somewhere safe."
                        />
                        <div
                            className="rounded-md p-3 flex items-center justify-between gap-2"
                            style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border)' }}
                        >
                            <code className="text-sm break-all" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                                {newToken}
                            </code>
                            <Button variant="outline" size="sm" onClick={copy} title="Copy token">
                                {copied ? <CheckIcon className="h-4 w-4" /> : <ClipboardDocumentIcon className="h-4 w-4" />}
                            </Button>
                        </div>
                        <div className="flex justify-end">
                            <Button onClick={() => setShowCreate(false)}>Done</Button>
                        </div>
                    </div>
                ) : (
                    <form onSubmit={handleCreate} className="space-y-4">
                        {createToken.isError && (
                            <Alert
                                type="error"
                                title="Could not create token"
                                message={(createToken.error as Error)?.message || 'Please try again.'}
                            />
                        )}
                        <Input
                            label="Token name"
                            type="text"
                            placeholder="e.g. ci-pipeline"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            required
                        />
                        <Input
                            label="Expires (optional)"
                            type="date"
                            value={expiresAt}
                            onChange={(e) => setExpiresAt(e.target.value)}
                        />
                        <div className="flex justify-end gap-2">
                            <Button type="button" variant="outline" onClick={() => setShowCreate(false)}>
                                Cancel
                            </Button>
                            <Button type="submit" disabled={createToken.isPending || !name.trim()}>
                                {createToken.isPending && <Spinner size="sm" className="mr-2" />}
                                Create Token
                            </Button>
                        </div>
                    </form>
                )}
            </Modal>
        </div>
    );
};

// ── Page ────────────────────────────────────────────────────────────────────

export const ProfilePage: React.FC = () => {
    const [activeTab, setActiveTab] = useState<(typeof TABS)[number]['id']>('profile');

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <div className="mb-6">
                <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                    My Account
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Manage your profile, password, sessions, and API tokens.
                </p>
            </div>

            <div className="border-b mb-6" style={{ borderColor: 'var(--border)' }}>
                <nav className="-mb-px flex gap-6">
                    {TABS.map((tab) => {
                        const Icon = tab.icon;
                        const active = activeTab === tab.id;
                        return (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className="flex items-center py-3 px-1 border-b-2 font-medium text-sm transition-colors"
                                style={{
                                    borderColor: active ? 'var(--accent)' : 'transparent',
                                    color: active ? 'var(--accent-text)' : 'var(--text-muted)',
                                }}
                            >
                                <Icon className="h-5 w-5 mr-2" />
                                {tab.label}
                            </button>
                        );
                    })}
                </nav>
            </div>

            {activeTab === 'profile' && <BasicInfoTab />}
            {activeTab === 'security' && <SecurityTab />}
            {activeTab === 'sessions' && <SessionsTab />}
            {activeTab === 'tokens' && <TokensTab />}
        </div>
    );
};
