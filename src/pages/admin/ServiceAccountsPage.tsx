import React, { useState } from 'react';
import { PlusIcon, ClipboardDocumentIcon, KeyIcon, PencilIcon, TrashIcon } from '@heroicons/react/24/outline';
import {
    useServiceAccounts,
    useCreateServiceAccount,
    useUpdateServiceAccount,
    useDeactivateServiceAccount,
    useServiceAccountTokens,
    useCreateToken,
    useRevokeToken,
} from '../../features/admin';
import { ServiceAccount, APIToken } from '../../types/serviceAccounts';
import { Button } from '../../components/ui/Button';
import { Modal } from '../../components/ui/Modal';
import { copyToClipboard } from '../../utils';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';
import { useUIStore } from '../../store/uiStore';
import { OIDCFederationSection } from './OIDCFederationSection';

type PageTab = 'accounts' | 'oidc';

const SCOPES = [
    { value: 'secrets:read', description: 'Read secrets' },
    { value: 'secrets:write', description: 'Create and update secrets' },
    { value: 'secrets:delete', description: 'Delete secrets' },
    { value: 'audit:read', description: 'Read audit logs' },
] as const;

function formatDate(iso: string): string {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    } catch {
        return iso;
    }
}

function getTokenStatus(token: APIToken): 'active' | 'revoked' | 'expired' {
    if (token.revoked) return 'revoked';
    if (token.expires_at && new Date(token.expires_at) <= new Date()) return 'expired';
    return 'active';
}

type ActiveModal =
    | null
    | { type: 'create' }
    | { type: 'edit'; sa: ServiceAccount }
    | { type: 'deactivate'; sa: ServiceAccount }
    | { type: 'tokens'; sa: ServiceAccount };

export const ServiceAccountsPage: React.FC = () => {
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

    const [activeTab, setActiveTab] = useState<PageTab>('accounts');
    const [activeModal, setActiveModal] = useState<ActiveModal>(null);
    const [pageError, setPageError] = useState('');

    // Create / Edit form
    const [formName, setFormName] = useState('');
    const [formDescription, setFormDescription] = useState('');
    const [formScopes, setFormScopes] = useState<Set<string>>(new Set());
    const [formError, setFormError] = useState('');

    // Shown after SA creation — dismissed by user
    const [createdCreds, setCreatedCreds] = useState<{
        clientId: string;
        clientSecret: string;
        saName: string;
    } | null>(null);
    const [copiedField, setCopiedField] = useState<string | null>(null);

    // Tokens modal sub-state
    const [showTokenForm, setShowTokenForm] = useState(false);
    const [tokenDescription, setTokenDescription] = useState('');
    const [tokenExpiresAt, setTokenExpiresAt] = useState('');
    const [tokenFormError, setTokenFormError] = useState('');
    const [createdAccessToken, setCreatedAccessToken] = useState<string | null>(null);
    const [pendingRevokeTokenId, setPendingRevokeTokenId] = useState<number | null>(null);

    const { data: serviceAccounts = [], isLoading, isError } = useServiceAccounts();
    const tokensServiceAccountId = activeModal?.type === 'tokens' ? activeModal.sa.id : null;
    const { data: tokens = [], isLoading: tokensLoading } = useServiceAccountTokens(tokensServiceAccountId);

    const createMutation = useCreateServiceAccount();
    const updateMutation = useUpdateServiceAccount();
    const deactivateMutation = useDeactivateServiceAccount();
    const createTokenMutation = useCreateToken();
    const revokeTokenMutation = useRevokeToken();

    function closeModal() {
        setActiveModal(null);
        setFormError('');
        setFormName('');
        setFormDescription('');
        setFormScopes(new Set());
        setShowTokenForm(false);
        setTokenDescription('');
        setTokenExpiresAt('');
        setTokenFormError('');
        setCreatedAccessToken(null);
        setPendingRevokeTokenId(null);
    }

    function openCreate() {
        setFormName('');
        setFormDescription('');
        setFormScopes(new Set());
        setFormError('');
        setActiveModal({ type: 'create' });
    }

    function openEdit(sa: ServiceAccount) {
        setFormName(sa.name);
        setFormDescription(sa.description);
        setFormScopes(
            new Set(
                sa.scopes
                    .split(',')
                    .map((s) => s.trim())
                    .filter(Boolean)
            )
        );
        setFormError('');
        setActiveModal({ type: 'edit', sa });
    }

    function openTokens(sa: ServiceAccount) {
        setShowTokenForm(false);
        setCreatedAccessToken(null);
        setPendingRevokeTokenId(null);
        setActiveModal({ type: 'tokens', sa });
    }

    function toggleScope(scope: string) {
        setFormScopes((prev) => {
            const next = new Set(prev);
            if (next.has(scope)) next.delete(scope);
            else next.add(scope);
            return next;
        });
    }

    function handleCreate() {
        if (!formName.trim()) {
            setFormError('Name is required');
            return;
        }
        if (formScopes.size === 0) {
            setFormError('At least one scope is required');
            return;
        }
        setFormError('');
        createMutation.mutate(
            {
                name: formName.trim(),
                description: formDescription.trim(),
                scopes: Array.from(formScopes).join(','),
            },
            {
                onSuccess: (data) => {
                    closeModal();
                    setCreatedCreds({
                        clientId: data.service_account.client_id,
                        clientSecret: data.client_secret,
                        saName: data.service_account.name,
                    });
                },
                onError: (err: unknown) => {
                    const e = err as { response?: { data?: { error?: string } }; message?: string };
                    setFormError(e.response?.data?.error ?? e.message ?? 'Failed to create service account');
                },
            }
        );
    }

    function handleUpdate() {
        if (activeModal?.type !== 'edit') return;
        if (!formName.trim()) {
            setFormError('Name is required');
            return;
        }
        if (formScopes.size === 0) {
            setFormError('At least one scope is required');
            return;
        }
        setFormError('');
        updateMutation.mutate(
            {
                id: activeModal.sa.id,
                body: {
                    name: formName.trim(),
                    description: formDescription.trim(),
                    scopes: Array.from(formScopes).join(','),
                },
            },
            {
                onSuccess: closeModal,
                onError: (err: unknown) => {
                    const e = err as { response?: { data?: { error?: string } }; message?: string };
                    setFormError(e.response?.data?.error ?? e.message ?? 'Failed to update service account');
                },
            }
        );
    }

    function handleDeactivate() {
        if (activeModal?.type !== 'deactivate') return;
        deactivateMutation.mutate(activeModal.sa.id, {
            onSuccess: closeModal,
            onError: (err: unknown) => {
                const e = err as { response?: { data?: { error?: string } }; message?: string };
                setPageError(e.response?.data?.error ?? e.message ?? 'Failed to deactivate service account');
            },
        });
    }

    function handleCreateToken() {
        if (activeModal?.type !== 'tokens') return;
        setTokenFormError('');
        const tokenBody: { description?: string; expires_at?: string } = {};
        if (tokenDescription.trim()) tokenBody.description = tokenDescription.trim();
        if (tokenExpiresAt) tokenBody.expires_at = tokenExpiresAt;
        createTokenMutation.mutate(
            { serviceAccountId: activeModal.sa.id, body: tokenBody },
            {
                onSuccess: (data) => {
                    setShowTokenForm(false);
                    setTokenDescription('');
                    setTokenExpiresAt('');
                    setCreatedAccessToken(data.access_token);
                },
                onError: (err: unknown) => {
                    const e = err as { response?: { data?: { error?: string } }; message?: string };
                    setTokenFormError(e.response?.data?.error ?? e.message ?? 'Failed to create token');
                },
            }
        );
    }

    function handleRevokeToken(tokenId: number) {
        revokeTokenMutation.mutate(
            { tokenId },
            {
                onSuccess: () => setPendingRevokeTokenId(null),
                onError: (err: unknown) => {
                    const e = err as { response?: { data?: { error?: string } }; message?: string };
                    setPageError(e.response?.data?.error ?? e.message ?? 'Failed to revoke token');
                },
            }
        );
    }

    async function handleCopy(text: string, field: string) {
        await copyToClipboard(text);
        setCopiedField(field);
        setTimeout(() => setCopiedField(null), 2000);
    }

    const scopeFormBlock = (
        <div>
            <label className="block text-sm font-medium text-base-secondary mb-2">
                Scopes <span className="text-red-500">*</span>
            </label>
            <div className="space-y-2">
                {SCOPES.map(({ value, description }) => (
                    <label
                        key={value}
                        className="flex items-start gap-3 p-3 rounded-lg border border-base hover:bg-subtle cursor-pointer transition-colors"
                    >
                        <input
                            type="checkbox"
                            checked={formScopes.has(value)}
                            onChange={() => toggleScope(value)}
                            className="mt-0.5 h-4 w-4 rounded-sm border-base"
                            style={{ accentColor: 'var(--accent)' }}
                        />
                        <div>
                            <p className="text-sm font-medium text-base-primary font-mono">{value}</p>
                            <p className="text-xs text-base-muted mt-0.5">{description}</p>
                        </div>
                    </label>
                ))}
            </div>
        </div>
    );

    return (
        <>
            <div className="max-w-6xl mx-auto px-4 py-8">
                <div className="flex items-center justify-between mb-6">
                    <div>
                        <h1 className="text-2xl font-bold text-base-primary">Service Accounts</h1>
                        <p className="text-sm text-base-muted mt-1">
                            Machine identities for CI/CD pipelines and automated workflows
                        </p>
                    </div>
                    {activeTab === 'accounts' && (
                        <Button variant="default" onClick={openCreate}>
                            <PlusIcon className="h-4 w-4 mr-1.5" />
                            New Service Account
                        </Button>
                    )}
                </div>

                {/* Tab bar */}
                <div className="flex gap-1 mb-6 border-b border-base">
                    {(['accounts', 'oidc'] as const).map((tab) => (
                        <button
                            key={tab}
                            type="button"
                            onClick={() => setActiveTab(tab)}
                            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                                activeTab === tab
                                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                    : 'border-transparent text-base-muted hover:text-base-primary'
                            }`}
                        >
                            {tab === 'accounts' ? 'Service Accounts' : 'OIDC Federation'}
                        </button>
                    ))}
                </div>

                {activeTab === 'oidc' && (
                    <OIDCFederationSection serviceAccounts={serviceAccounts} />
                )}

                {activeTab === 'accounts' && pageError && (
                    <Alert
                        type="error"
                        title={pageError}
                        dismissible
                        onDismiss={() => setPageError('')}
                        className="mb-4"
                    />
                )}

                {activeTab === 'accounts' && (isLoading ? (
                    <Loading className="py-20" />
                ) : isError ? (
                    <Alert
                        type="error"
                        title="Failed to load service accounts"
                        message="Check that the server is running and you have admin access."
                    />
                ) : serviceAccounts.length === 0 ? (
                    <div className="text-center py-20 text-base-muted">
                        <KeyIcon className="h-12 w-12 mx-auto mb-3 opacity-40" />
                        <p className="text-sm">
                            No service accounts yet. Create one to enable CI/CD pipeline access to secrets.
                        </p>
                    </div>
                ) : (
                    <div className="bg-surface border border-base rounded-lg overflow-hidden shadow-xs">
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-base">
                                <thead>
                                    <tr>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Name
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Client ID
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Scopes
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Status
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Created
                                        </th>
                                        <th className="px-6 py-3 text-right text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Actions
                                        </th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-base">
                                    {serviceAccounts.map((sa) => (
                                        <tr key={sa.id} className="hover:bg-subtle transition-colors">
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div>
                                                    <p className="text-sm font-medium text-base-primary">{sa.name}</p>
                                                    {sa.description && (
                                                        <p className="text-xs text-base-muted mt-0.5">
                                                            {sa.description}
                                                        </p>
                                                    )}
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <span className="font-mono text-sm text-base-secondary">
                                                    {sa.client_id.length > 12
                                                        ? sa.client_id.slice(0, 12) + '…'
                                                        : sa.client_id}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex flex-wrap gap-1">
                                                    {sa.scopes
                                                        .split(',')
                                                        .map((s) => s.trim())
                                                        .filter(Boolean)
                                                        .map((scope) => (
                                                            <span
                                                                key={scope}
                                                                className="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[11px] font-medium font-mono"
                                                                style={{
                                                                    backgroundColor: isDark
                                                                        ? 'rgba(59,130,246,0.15)'
                                                                        : '#eff6ff',
                                                                    color: isDark ? '#93c5fd' : '#1d4ed8',
                                                                }}
                                                            >
                                                                {scope}
                                                            </span>
                                                        ))}
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <span
                                                    className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
                                                    style={
                                                        sa.is_active
                                                            ? {
                                                                  backgroundColor: isDark
                                                                      ? 'rgba(16,185,129,0.15)'
                                                                      : '#dcfce7',
                                                                  color: isDark ? '#34d399' : '#166534',
                                                              }
                                                            : {
                                                                  backgroundColor: isDark
                                                                      ? 'rgba(148,163,184,0.15)'
                                                                      : '#f1f5f9',
                                                                  color: isDark ? '#94a3b8' : '#475569',
                                                              }
                                                    }
                                                >
                                                    {sa.is_active ? 'Active' : 'Inactive'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
                                                {formatDate(sa.created_at)}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-right">
                                                <div className="flex items-center justify-end gap-2">
                                                    <button
                                                        onClick={() => openTokens(sa)}
                                                        className="p-1.5 text-base-muted hover:text-blue-600 hover:bg-accent-subtle rounded-sm transition-colors"
                                                        title="Manage tokens"
                                                    >
                                                        <KeyIcon className="h-4 w-4" />
                                                    </button>
                                                    <button
                                                        onClick={() => openEdit(sa)}
                                                        className="p-1.5 text-base-muted hover:text-blue-600 hover:bg-accent-subtle rounded-sm transition-colors"
                                                        title="Edit"
                                                    >
                                                        <PencilIcon className="h-4 w-4" />
                                                    </button>
                                                    {sa.is_active && (
                                                        <button
                                                            onClick={() => setActiveModal({ type: 'deactivate', sa })}
                                                            className="p-1.5 text-base-muted hover:text-red-600 hover:bg-red-50 rounded-sm transition-colors"
                                                            title="Deactivate"
                                                        >
                                                            <TrashIcon className="h-4 w-4" />
                                                        </button>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ))}
            </div>

            {/* ── Create modal ─────────────────────────────────────────────────── */}
            <Modal isOpen={activeModal?.type === 'create'} onClose={closeModal} title="New Service Account" size="md">
                <div className="space-y-4">
                    {formError && <Alert type="error" message={formError} />}
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">
                            Name <span className="text-red-500">*</span>
                        </label>
                        <input
                            type="text"
                            value={formName}
                            onChange={(e) => setFormName(e.target.value)}
                            placeholder="e.g. ci-deploy"
                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border-strong)',
                            }}
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">Description</label>
                        <input
                            type="text"
                            value={formDescription}
                            onChange={(e) => setFormDescription(e.target.value)}
                            placeholder="Optional description"
                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border-strong)',
                            }}
                        />
                    </div>
                    {scopeFormBlock}
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={closeModal} disabled={createMutation.isPending}>
                            Cancel
                        </Button>
                        <Button variant="default" onClick={handleCreate} disabled={createMutation.isPending}>
                            {createMutation.isPending ? 'Creating…' : 'Create Service Account'}
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* ── Edit modal ───────────────────────────────────────────────────── */}
            <Modal isOpen={activeModal?.type === 'edit'} onClose={closeModal} title="Edit Service Account" size="md">
                <div className="space-y-4">
                    {formError && <Alert type="error" message={formError} />}
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">
                            Name <span className="text-red-500">*</span>
                        </label>
                        <input
                            type="text"
                            value={formName}
                            onChange={(e) => setFormName(e.target.value)}
                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border-strong)',
                            }}
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">Description</label>
                        <input
                            type="text"
                            value={formDescription}
                            onChange={(e) => setFormDescription(e.target.value)}
                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border-strong)',
                            }}
                        />
                    </div>
                    {scopeFormBlock}
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={closeModal} disabled={updateMutation.isPending}>
                            Cancel
                        </Button>
                        <Button variant="default" onClick={handleUpdate} disabled={updateMutation.isPending}>
                            {updateMutation.isPending ? 'Saving…' : 'Save Changes'}
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* ── Deactivate modal ─────────────────────────────────────────────── */}
            <Modal
                isOpen={activeModal?.type === 'deactivate'}
                onClose={closeModal}
                title="Deactivate Service Account"
                size="sm"
            >
                <div className="space-y-4">
                    {activeModal?.type === 'deactivate' && (
                        <p className="text-sm text-base-secondary">
                            Deactivate <span className="font-semibold">{activeModal.sa.name}</span>? All tokens issued
                            to this service account will stop working.
                        </p>
                    )}
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={closeModal} disabled={deactivateMutation.isPending}>
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={handleDeactivate}
                            disabled={deactivateMutation.isPending}
                        >
                            {deactivateMutation.isPending ? 'Deactivating…' : 'Deactivate'}
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* ── One-time credentials modal (shown after create) ───────────────── */}
            {createdCreds && (
                <Modal isOpen onClose={() => setCreatedCreds(null)} title="Service Account Created" size="md">
                    <div className="space-y-4">
                        <div
                            className="p-3 rounded-lg border"
                            style={{
                                backgroundColor: isDark ? 'rgba(217,119,6,0.12)' : '#fffbeb',
                                borderColor: isDark ? 'rgba(217,119,6,0.35)' : '#fcd34d',
                            }}
                        >
                            <p className="text-sm font-semibold" style={{ color: isDark ? '#fbbf24' : '#92400e' }}>
                                ⚠️ Save these credentials — they won't be shown again
                            </p>
                        </div>

                        <div>
                            <label className="block text-xs font-medium text-base-muted mb-1 uppercase tracking-wide">
                                Client ID
                            </label>
                            <div className="flex items-center gap-2">
                                <code
                                    className="flex-1 px-3 py-2 rounded-lg text-sm font-mono border border-base break-all"
                                    style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-primary)' }}
                                >
                                    {createdCreds.clientId}
                                </code>
                                <button
                                    onClick={() => handleCopy(createdCreds.clientId, 'clientId')}
                                    className="p-2 rounded-lg border border-base hover:bg-subtle transition-colors shrink-0"
                                    style={{ color: 'var(--text-muted)' }}
                                    title="Copy Client ID"
                                >
                                    <ClipboardDocumentIcon className="h-4 w-4" />
                                </button>
                            </div>
                            {copiedField === 'clientId' && <p className="text-xs text-green-600 mt-1">Copied!</p>}
                        </div>

                        <div>
                            <label className="block text-xs font-medium text-base-muted mb-1 uppercase tracking-wide">
                                Client Secret
                            </label>
                            <div className="flex items-center gap-2">
                                <code
                                    className="flex-1 px-3 py-2 rounded-lg text-sm font-mono border border-base break-all"
                                    style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-primary)' }}
                                >
                                    {createdCreds.clientSecret}
                                </code>
                                <button
                                    onClick={() => handleCopy(createdCreds.clientSecret, 'clientSecret')}
                                    className="p-2 rounded-lg border border-base hover:bg-subtle transition-colors shrink-0"
                                    style={{ color: 'var(--text-muted)' }}
                                    title="Copy Client Secret"
                                >
                                    <ClipboardDocumentIcon className="h-4 w-4" />
                                </button>
                            </div>
                            {copiedField === 'clientSecret' && <p className="text-xs text-green-600 mt-1">Copied!</p>}
                        </div>

                        <div className="flex justify-end pt-2">
                            <Button
                                variant="default"
                                onClick={() => {
                                    setCreatedCreds(null);
                                    setCopiedField(null);
                                }}
                            >
                                I've saved these credentials
                            </Button>
                        </div>
                    </div>
                </Modal>
            )}

            {/* ── Tokens modal ─────────────────────────────────────────────────── */}
            <Modal
                isOpen={activeModal?.type === 'tokens'}
                onClose={closeModal}
                title={activeModal?.type === 'tokens' ? `Tokens — ${activeModal.sa.name}` : 'Tokens'}
                size="lg"
            >
                <div className="space-y-4">
                    {/* One-time access token display */}
                    {createdAccessToken && (
                        <div
                            className="p-4 rounded-lg border space-y-3"
                            style={{
                                backgroundColor: isDark ? 'rgba(217,119,6,0.12)' : '#fffbeb',
                                borderColor: isDark ? 'rgba(217,119,6,0.35)' : '#fcd34d',
                            }}
                        >
                            <p className="text-sm font-semibold" style={{ color: isDark ? '#fbbf24' : '#92400e' }}>
                                ⚠️ Save this token — it won't be shown again
                            </p>
                            <div>
                                <label className="block text-xs font-medium text-base-muted mb-1 uppercase tracking-wide">
                                    Token
                                </label>
                                <div className="flex items-center gap-2">
                                    <code
                                        className="flex-1 px-3 py-2 rounded-lg text-sm font-mono border border-base break-all"
                                        style={{
                                            backgroundColor: 'var(--bg-app)',
                                            color: 'var(--text-primary)',
                                        }}
                                    >
                                        {createdAccessToken}
                                    </code>
                                    <button
                                        onClick={() => handleCopy(createdAccessToken, 'accessToken')}
                                        className="p-2 rounded-lg border border-base hover:bg-subtle transition-colors shrink-0"
                                        style={{ color: 'var(--text-muted)' }}
                                        title="Copy token"
                                    >
                                        <ClipboardDocumentIcon className="h-4 w-4" />
                                    </button>
                                </div>
                                {copiedField === 'accessToken' && (
                                    <p className="text-xs text-green-600 mt-1">Copied!</p>
                                )}
                            </div>
                            <Button
                                variant="default"
                                size="sm"
                                onClick={() => {
                                    setCreatedAccessToken(null);
                                    setCopiedField(null);
                                }}
                            >
                                I've saved this token
                            </Button>
                        </div>
                    )}

                    {/* New token button + inline form */}
                    {!createdAccessToken && (
                        <div className="space-y-3">
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                    setShowTokenForm((f) => !f);
                                    setTokenFormError('');
                                }}
                            >
                                <PlusIcon className="h-4 w-4 mr-1.5" />
                                New Token
                            </Button>

                            {showTokenForm && (
                                <div
                                    className="p-4 rounded-lg border border-base space-y-3"
                                    style={{ backgroundColor: 'var(--bg-subtle)' }}
                                >
                                    {tokenFormError && <Alert type="error" message={tokenFormError} />}
                                    <div>
                                        <label className="block text-sm font-medium text-base-secondary mb-1">
                                            Description
                                        </label>
                                        <input
                                            type="text"
                                            value={tokenDescription}
                                            onChange={(e) => setTokenDescription(e.target.value)}
                                            placeholder="Optional description"
                                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                                            style={{
                                                backgroundColor: 'var(--bg-app)',
                                                color: 'var(--text-primary)',
                                                borderColor: 'var(--border-strong)',
                                            }}
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-base-secondary mb-1">
                                            Expires At <span className="text-base-muted font-normal">(optional)</span>
                                        </label>
                                        <input
                                            type="date"
                                            value={tokenExpiresAt}
                                            onChange={(e) => setTokenExpiresAt(e.target.value)}
                                            min={new Date().toISOString().split('T')[0]}
                                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                                            style={{
                                                backgroundColor: 'var(--bg-app)',
                                                color: 'var(--text-primary)',
                                                borderColor: 'var(--border-strong)',
                                            }}
                                        />
                                    </div>
                                    <div className="flex justify-end gap-2">
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => {
                                                setShowTokenForm(false);
                                                setTokenFormError('');
                                            }}
                                        >
                                            Cancel
                                        </Button>
                                        <Button
                                            variant="default"
                                            size="sm"
                                            onClick={handleCreateToken}
                                            disabled={createTokenMutation.isPending}
                                        >
                                            {createTokenMutation.isPending ? 'Creating…' : 'Create Token'}
                                        </Button>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Token list */}
                    {tokensLoading ? (
                        <Loading />
                    ) : tokens.length === 0 ? (
                        <p className="text-sm text-base-muted text-center py-6">No tokens yet. Create one above.</p>
                    ) : (
                        <div className="border border-base rounded-lg overflow-hidden">
                            <table className="min-w-full divide-y divide-base">
                                <thead>
                                    <tr style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                        <th className="px-4 py-2.5 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Created
                                        </th>
                                        <th className="px-4 py-2.5 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Expires
                                        </th>
                                        <th className="px-4 py-2.5 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Status
                                        </th>
                                        <th className="px-4 py-2.5 text-right text-xs font-medium text-base-muted uppercase tracking-wider">
                                            Actions
                                        </th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-base">
                                    {tokens.map((token) => {
                                        const status = getTokenStatus(token);
                                        const inactive = status === 'revoked' || status === 'expired';
                                        const isPending = pendingRevokeTokenId === token.id;
                                        return (
                                            <tr key={token.id} className="hover:bg-subtle transition-colors">
                                                <td className="px-4 py-3 text-sm text-base-secondary">
                                                    {formatDate(token.created_at)}
                                                </td>
                                                <td className="px-4 py-3 text-sm text-base-secondary">
                                                    {token.expires_at ? formatDate(token.expires_at) : '—'}
                                                </td>
                                                <td className="px-4 py-3">
                                                    <TokenStatusBadge status={status} isDark={isDark} />
                                                </td>
                                                <td className="px-4 py-3 text-right">
                                                    {isPending ? (
                                                        <div className="flex items-center justify-end gap-2">
                                                            <span className="text-xs text-base-muted">
                                                                Revoke this token?
                                                            </span>
                                                            <Button
                                                                variant="destructive"
                                                                size="sm"
                                                                onClick={() => handleRevokeToken(token.id)}
                                                                disabled={revokeTokenMutation.isPending}
                                                            >
                                                                {revokeTokenMutation.isPending ? '…' : 'Revoke'}
                                                            </Button>
                                                            <Button
                                                                variant="ghost"
                                                                size="sm"
                                                                onClick={() => setPendingRevokeTokenId(null)}
                                                            >
                                                                Cancel
                                                            </Button>
                                                        </div>
                                                    ) : (
                                                        <button
                                                            onClick={() => setPendingRevokeTokenId(token.id)}
                                                            disabled={inactive}
                                                            className="text-xs font-medium px-2.5 py-1 rounded-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                                                            style={{
                                                                color: inactive
                                                                    ? 'var(--text-muted)'
                                                                    : isDark
                                                                      ? '#f87171'
                                                                      : '#dc2626',
                                                                backgroundColor: 'transparent',
                                                            }}
                                                            onMouseEnter={(e) => {
                                                                if (!inactive)
                                                                    (
                                                                        e.currentTarget as HTMLElement
                                                                    ).style.backgroundColor = isDark
                                                                        ? 'rgba(239,68,68,0.12)'
                                                                        : '#fee2e2';
                                                            }}
                                                            onMouseLeave={(e) => {
                                                                (e.currentTarget as HTMLElement).style.backgroundColor =
                                                                    'transparent';
                                                            }}
                                                        >
                                                            Revoke
                                                        </button>
                                                    )}
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </Modal>
        </>
    );
};

function TokenStatusBadge({ status, isDark }: { status: 'active' | 'revoked' | 'expired'; isDark: boolean }) {
    const styles: Record<string, React.CSSProperties> = {
        active: {
            backgroundColor: isDark ? 'rgba(16,185,129,0.15)' : '#dcfce7',
            color: isDark ? '#34d399' : '#166534',
        },
        revoked: {
            backgroundColor: isDark ? 'rgba(239,68,68,0.15)' : '#fee2e2',
            color: isDark ? '#f87171' : '#991b1b',
        },
        expired: {
            backgroundColor: isDark ? 'rgba(217,119,6,0.12)' : '#fef3c7',
            color: isDark ? '#fbbf24' : '#92400e',
        },
    };
    const labels = { active: 'Active', revoked: 'Revoked', expired: 'Expired' };
    return (
        <span
            className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
            style={styles[status]}
        >
            {labels[status]}
        </span>
    );
}
