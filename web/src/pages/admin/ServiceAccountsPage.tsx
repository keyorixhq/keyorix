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
import { ServiceAccount } from '../../types/serviceAccounts';
import { Button } from '../../components/ui/Button';
import { Modal } from '../../components/ui/Modal';
import { copyToClipboard, formatDateShort } from '../../utils';
import { RevokeTokenCell } from '../../components/ui/RevokeTokenCell';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';
import { TokenStatusBadge, getTokenStatus } from '../../components/ui/TokenStatusBadge';
import { useUIStore } from '../../store/uiStore';
import { OIDCFederationSection } from './OIDCFederationSection';

type PageTab = 'accounts' | 'oidc';

const SCOPES = [
    { value: 'secrets:read', description: 'Read secrets' },
    { value: 'secrets:write', description: 'Create and update secrets' },
    { value: 'secrets:delete', description: 'Delete secrets' },
    { value: 'audit:read', description: 'Read audit logs' },
] as const;

type ActiveModal =
    | null
    | { type: 'create' }
    | { type: 'edit'; sa: ServiceAccount }
    | { type: 'deactivate'; sa: ServiceAccount }
    | { type: 'tokens'; sa: ServiceAccount };

// ── Helpers extracted to reduce cognitive complexity ──────────────────────────

function renderAccountsContent(
    isLoading: boolean,
    isError: boolean,
    serviceAccounts: ServiceAccount[],
    isDark: boolean,
    openTokens: (sa: ServiceAccount) => void,
    openEdit: (sa: ServiceAccount) => void,
    setActiveModal: (m: ActiveModal) => void
) {
    if (isLoading) {
        return <Loading className="py-20" />;
    }
    if (isError) {
        return (
            <Alert
                type="error"
                title="Failed to load service accounts"
                message="Check that the server is running and you have admin access."
            />
        );
    }
    if (serviceAccounts.length === 0) {
        return (
            <div className="text-center py-20 text-base-muted">
                <KeyIcon className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p className="text-sm">
                    No service accounts yet. Create one to enable CI/CD pipeline access to secrets.
                </p>
            </div>
        );
    }
    return (
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
                                            <p className="text-xs text-base-muted mt-0.5">{sa.description}</p>
                                        )}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className="font-mono text-sm text-base-secondary">
                                        {sa.client_id.length > 12 ? sa.client_id.slice(0, 12) + '…' : sa.client_id}
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
                                                        backgroundColor: isDark ? 'rgba(59,130,246,0.15)' : '#eff6ff',
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
                                                      backgroundColor: isDark ? 'rgba(16,185,129,0.15)' : '#dcfce7',
                                                      color: isDark ? '#34d399' : '#166534',
                                                  }
                                                : {
                                                      backgroundColor: isDark ? 'rgba(148,163,184,0.15)' : '#f1f5f9',
                                                      color: isDark ? '#94a3b8' : '#475569',
                                                  }
                                        }
                                    >
                                        {sa.is_active ? 'Active' : 'Inactive'}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
                                    {formatDateShort(sa.created_at)}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right">
                                    <div className="flex items-center justify-end gap-2">
                                        <button
                                            type="button"
                                            onClick={() => openTokens(sa)}
                                            className="p-1.5 text-base-muted hover:text-blue-600 hover:bg-accent-subtle rounded-sm transition-colors"
                                            title="Manage tokens"
                                        >
                                            <KeyIcon className="h-4 w-4" />
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => openEdit(sa)}
                                            className="p-1.5 text-base-muted hover:text-blue-600 hover:bg-accent-subtle rounded-sm transition-colors"
                                            title="Edit"
                                        >
                                            <PencilIcon className="h-4 w-4" />
                                        </button>
                                        {sa.is_active && (
                                            <button
                                                type="button"
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
    );
}

type Token = NonNullable<ReturnType<typeof useServiceAccountTokens>['data']>[number];

interface AccountsHeaderProps {
    activeTab: PageTab;
    onNewAccount: () => void;
}

const AccountsHeader: React.FC<AccountsHeaderProps> = ({ activeTab, onNewAccount }) => (
    <div className="flex items-center justify-between mb-6">
        <div>
            <h1 className="text-2xl font-bold text-base-primary">Service Accounts</h1>
            <p className="text-sm text-base-muted mt-1">
                Machine identities for CI/CD pipelines and automated workflows
            </p>
        </div>
        {activeTab === 'accounts' && (
            <Button variant="default" onClick={onNewAccount}>
                <PlusIcon className="h-4 w-4 mr-1.5" />
                New Service Account
            </Button>
        )}
    </div>
);

interface TabBarProps {
    activeTab: PageTab;
    onChange: (tab: PageTab) => void;
}

const TabBar: React.FC<TabBarProps> = ({ activeTab, onChange }) => (
    <div className="flex gap-1 mb-6 border-b border-base">
        {(['accounts', 'oidc'] as const).map((tab) => (
            <button
                key={tab}
                type="button"
                onClick={() => onChange(tab)}
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
);

interface ScopeCheckboxListProps {
    formScopes: Set<string>;
    onToggle: (scope: string) => void;
}

const ScopeCheckboxList: React.FC<ScopeCheckboxListProps> = ({ formScopes, onToggle }) => (
    <div>
        <p className="block text-sm font-medium text-base-secondary mb-2">
            Scopes <span className="text-red-500">*</span>
        </p>
        <div className="space-y-2">
            {SCOPES.map(({ value, description }) => (
                <label
                    key={value}
                    htmlFor={`scope-${value}`}
                    aria-label={`${value} — ${description}`}
                    className="flex items-start gap-3 p-3 rounded-lg border border-base hover:bg-subtle cursor-pointer transition-colors"
                >
                    <input
                        id={`scope-${value}`}
                        type="checkbox"
                        checked={formScopes.has(value)}
                        onChange={() => onToggle(value)}
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

interface CreateServiceAccountModalProps {
    isOpen: boolean;
    formError: string;
    formName: string;
    setFormName: (v: string) => void;
    formDescription: string;
    setFormDescription: (v: string) => void;
    formScopes: Set<string>;
    onToggleScope: (scope: string) => void;
    onSubmit: () => void;
    onClose: () => void;
    isPending: boolean;
}

const CreateServiceAccountModal: React.FC<CreateServiceAccountModalProps> = ({
    isOpen,
    formError,
    formName,
    setFormName,
    formDescription,
    setFormDescription,
    formScopes,
    onToggleScope,
    onSubmit,
    onClose,
    isPending,
}) => (
    <Modal isOpen={isOpen} onClose={onClose} title="New Service Account" size="md">
        <div className="space-y-4">
            {formError && <Alert type="error" message={formError} />}
            <div>
                <label htmlFor="create-sa-name" className="block text-sm font-medium text-base-secondary mb-1">
                    Name <span className="text-red-500">*</span>
                </label>
                <input
                    id="create-sa-name"
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
                <label htmlFor="create-sa-description" className="block text-sm font-medium text-base-secondary mb-1">
                    Description
                </label>
                <input
                    id="create-sa-description"
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
            <ScopeCheckboxList formScopes={formScopes} onToggle={onToggleScope} />
            <div className="flex justify-end gap-3 pt-2">
                <Button variant="ghost" onClick={onClose} disabled={isPending}>
                    Cancel
                </Button>
                <Button variant="default" onClick={onSubmit} disabled={isPending}>
                    {isPending ? 'Creating…' : 'Create Service Account'}
                </Button>
            </div>
        </div>
    </Modal>
);

interface EditServiceAccountModalProps {
    isOpen: boolean;
    formError: string;
    formName: string;
    setFormName: (v: string) => void;
    formDescription: string;
    setFormDescription: (v: string) => void;
    formScopes: Set<string>;
    onToggleScope: (scope: string) => void;
    onSubmit: () => void;
    onClose: () => void;
    isPending: boolean;
}

const EditServiceAccountModal: React.FC<EditServiceAccountModalProps> = ({
    isOpen,
    formError,
    formName,
    setFormName,
    formDescription,
    setFormDescription,
    formScopes,
    onToggleScope,
    onSubmit,
    onClose,
    isPending,
}) => (
    <Modal isOpen={isOpen} onClose={onClose} title="Edit Service Account" size="md">
        <div className="space-y-4">
            {formError && <Alert type="error" message={formError} />}
            <div>
                <label htmlFor="edit-sa-name" className="block text-sm font-medium text-base-secondary mb-1">
                    Name <span className="text-red-500">*</span>
                </label>
                <input
                    id="edit-sa-name"
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
                <label htmlFor="edit-sa-description" className="block text-sm font-medium text-base-secondary mb-1">
                    Description
                </label>
                <input
                    id="edit-sa-description"
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
            <ScopeCheckboxList formScopes={formScopes} onToggle={onToggleScope} />
            <div className="flex justify-end gap-3 pt-2">
                <Button variant="ghost" onClick={onClose} disabled={isPending}>
                    Cancel
                </Button>
                <Button variant="default" onClick={onSubmit} disabled={isPending}>
                    {isPending ? 'Saving…' : 'Save Changes'}
                </Button>
            </div>
        </div>
    </Modal>
);

interface DeactivateServiceAccountModalProps {
    activeModal: ActiveModal;
    onDeactivate: () => void;
    onClose: () => void;
    isPending: boolean;
}

const DeactivateServiceAccountModal: React.FC<DeactivateServiceAccountModalProps> = ({
    activeModal,
    onDeactivate,
    onClose,
    isPending,
}) => (
    <Modal isOpen={activeModal?.type === 'deactivate'} onClose={onClose} title="Deactivate Service Account" size="sm">
        <div className="space-y-4">
            {activeModal?.type === 'deactivate' && (
                <p className="text-sm text-base-secondary">
                    Deactivate <span className="font-semibold">{activeModal.sa.name}</span>? All tokens issued to this
                    service account will stop working.
                </p>
            )}
            <div className="flex justify-end gap-3 pt-2">
                <Button variant="ghost" onClick={onClose} disabled={isPending}>
                    Cancel
                </Button>
                <Button variant="destructive" onClick={onDeactivate} disabled={isPending}>
                    {isPending ? 'Deactivating…' : 'Deactivate'}
                </Button>
            </div>
        </div>
    </Modal>
);

interface CreatedCreds {
    clientId: string;
    clientSecret: string;
    saName: string;
}

interface CredentialsModalProps {
    createdCreds: CreatedCreds | null;
    isDark: boolean;
    copiedField: string | null;
    onCopy: (text: string, field: string) => void;
    onClose: () => void;
    onConfirm: () => void;
}

const CredentialsModal: React.FC<CredentialsModalProps> = ({
    createdCreds,
    isDark,
    copiedField,
    onCopy,
    onClose,
    onConfirm,
}) => {
    if (!createdCreds) return null;
    return (
        <Modal isOpen onClose={onClose} title="Service Account Created" size="md">
            <div className="space-y-4">
                <div
                    className="p-3 rounded-lg border"
                    style={{
                        backgroundColor: isDark ? 'rgba(217,119,6,0.12)' : '#fffbeb',
                        borderColor: isDark ? 'rgba(217,119,6,0.35)' : '#fcd34d',
                    }}
                >
                    <p className="text-sm font-semibold" style={{ color: isDark ? '#fbbf24' : '#92400e' }}>
                        Save these credentials — they won't be shown again
                    </p>
                </div>

                <div>
                    <label
                        htmlFor="creds-client-id"
                        className="block text-xs font-medium text-base-muted mb-1 uppercase tracking-wide"
                    >
                        Client ID
                    </label>
                    <div className="flex items-center gap-2">
                        <code
                            id="creds-client-id"
                            className="flex-1 px-3 py-2 rounded-lg text-sm font-mono border border-base break-all"
                            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-primary)' }}
                        >
                            {createdCreds.clientId}
                        </code>
                        <button
                            type="button"
                            onClick={() => onCopy(createdCreds.clientId, 'clientId')}
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
                    <label
                        htmlFor="creds-client-secret"
                        className="block text-xs font-medium text-base-muted mb-1 uppercase tracking-wide"
                    >
                        Client Secret
                    </label>
                    <div className="flex items-center gap-2">
                        <code
                            id="creds-client-secret"
                            className="flex-1 px-3 py-2 rounded-lg text-sm font-mono border border-base break-all"
                            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-primary)' }}
                        >
                            {createdCreds.clientSecret}
                        </code>
                        <button
                            type="button"
                            onClick={() => onCopy(createdCreds.clientSecret, 'clientSecret')}
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
                    <Button variant="default" onClick={onConfirm}>
                        I've saved these credentials
                    </Button>
                </div>
            </div>
        </Modal>
    );
};

interface TokensModalProps {
    activeModal: ActiveModal;
    isDark: boolean;
    tokens: Token[];
    tokensLoading: boolean;
    createdAccessToken: string | null;
    copiedField: string | null;
    onCopy: (text: string, field: string) => void;
    onDismissAccessToken: () => void;
    showTokenForm: boolean;
    onToggleTokenForm: () => void;
    tokenFormError: string;
    tokenDescription: string;
    setTokenDescription: (v: string) => void;
    tokenExpiresAt: string;
    setTokenExpiresAt: (v: string) => void;
    onCancelTokenForm: () => void;
    onCreateToken: () => void;
    createTokenPending: boolean;
    pendingRevokeTokenId: number | null;
    setPendingRevokeTokenId: (id: number | null) => void;
    revokeTokenMutation: ReturnType<typeof useRevokeToken>;
    onRevokeToken: (tokenId: number) => void;
    onClose: () => void;
}

const TokensModal: React.FC<TokensModalProps> = ({
    activeModal,
    isDark,
    tokens,
    tokensLoading,
    createdAccessToken,
    copiedField,
    onCopy,
    onDismissAccessToken,
    showTokenForm,
    onToggleTokenForm,
    tokenFormError,
    tokenDescription,
    setTokenDescription,
    tokenExpiresAt,
    setTokenExpiresAt,
    onCancelTokenForm,
    onCreateToken,
    createTokenPending,
    pendingRevokeTokenId,
    setPendingRevokeTokenId,
    revokeTokenMutation,
    onRevokeToken,
    onClose,
}) => {
    const title = activeModal?.type === 'tokens' ? `Tokens — ${activeModal.sa.name}` : 'Tokens';

    let tokensListContent: React.ReactNode;
    if (tokensLoading) {
        tokensListContent = <Loading />;
    } else if (tokens.length === 0) {
        tokensListContent = (
            <p className="text-sm text-base-muted text-center py-6">No tokens yet. Create one above.</p>
        );
    } else {
        tokensListContent = (
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
                            const isPending = pendingRevokeTokenId === token.id;
                            return (
                                <tr key={token.id} className="hover:bg-subtle transition-colors">
                                    <td className="px-4 py-3 text-sm text-base-secondary">
                                        {formatDateShort(token.created_at)}
                                    </td>
                                    <td className="px-4 py-3 text-sm text-base-secondary">
                                        {token.expires_at ? formatDateShort(token.expires_at) : '—'}
                                    </td>
                                    <td className="px-4 py-3">
                                        <TokenStatusBadge status={status} isDark={isDark} />
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                        <RevokeTokenCell
                                            isPending={isPending}
                                            isMutating={revokeTokenMutation.isPending}
                                            inactive={status === 'revoked' || status === 'expired'}
                                            isDark={isDark}
                                            onRevoke={() => onRevokeToken(token.id)}
                                            onCancel={() => setPendingRevokeTokenId(null)}
                                            onSetPending={() => setPendingRevokeTokenId(token.id)}
                                        />
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        );
    }

    return (
        <Modal isOpen={activeModal?.type === 'tokens'} onClose={onClose} title={title} size="lg">
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
                            Save this token — it won't be shown again
                        </p>
                        <div>
                            <label
                                htmlFor="new-access-token"
                                className="block text-xs font-medium text-base-muted mb-1 uppercase tracking-wide"
                            >
                                Token
                            </label>
                            <div className="flex items-center gap-2">
                                <code
                                    id="new-access-token"
                                    className="flex-1 px-3 py-2 rounded-lg text-sm font-mono border border-base break-all"
                                    style={{
                                        backgroundColor: 'var(--bg-app)',
                                        color: 'var(--text-primary)',
                                    }}
                                >
                                    {createdAccessToken}
                                </code>
                                <button
                                    type="button"
                                    onClick={() => onCopy(createdAccessToken, 'accessToken')}
                                    className="p-2 rounded-lg border border-base hover:bg-subtle transition-colors shrink-0"
                                    style={{ color: 'var(--text-muted)' }}
                                    title="Copy token"
                                >
                                    <ClipboardDocumentIcon className="h-4 w-4" />
                                </button>
                            </div>
                            {copiedField === 'accessToken' && <p className="text-xs text-green-600 mt-1">Copied!</p>}
                        </div>
                        <Button variant="default" size="sm" onClick={onDismissAccessToken}>
                            I've saved this token
                        </Button>
                    </div>
                )}

                {/* New token button + inline form */}
                {!createdAccessToken && (
                    <div className="space-y-3">
                        <Button variant="outline" size="sm" onClick={onToggleTokenForm}>
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
                                    <label
                                        htmlFor="token-description"
                                        className="block text-sm font-medium text-base-secondary mb-1"
                                    >
                                        Description
                                    </label>
                                    <input
                                        id="token-description"
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
                                    <label
                                        htmlFor="token-expires-at"
                                        className="block text-sm font-medium text-base-secondary mb-1"
                                    >
                                        Expires At <span className="text-base-muted font-normal">(optional)</span>
                                    </label>
                                    <input
                                        id="token-expires-at"
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
                                    <Button variant="ghost" size="sm" onClick={onCancelTokenForm}>
                                        Cancel
                                    </Button>
                                    <Button
                                        variant="default"
                                        size="sm"
                                        onClick={onCreateToken}
                                        disabled={createTokenPending}
                                    >
                                        {createTokenPending ? 'Creating…' : 'Create Token'}
                                    </Button>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* Token list */}
                {tokensListContent}
            </div>
        </Modal>
    );
};

// ─── Main component ─────────────────────────────────────────────────────────

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

    const handleRevokeToken = (tokenId: number) => {
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
    };

    async function handleCopy(text: string, field: string) {
        await copyToClipboard(text);
        setCopiedField(field);
        setTimeout(() => setCopiedField(null), 2000);
    }

    return (
        <>
            <div className="max-w-6xl mx-auto px-4 py-8">
                <AccountsHeader activeTab={activeTab} onNewAccount={openCreate} />

                <TabBar activeTab={activeTab} onChange={setActiveTab} />

                {activeTab === 'oidc' && <OIDCFederationSection serviceAccounts={serviceAccounts} />}

                {activeTab === 'accounts' && pageError && (
                    <Alert
                        type="error"
                        title={pageError}
                        dismissible
                        onDismiss={() => setPageError('')}
                        className="mb-4"
                    />
                )}

                {activeTab === 'accounts' &&
                    renderAccountsContent(
                        isLoading,
                        isError,
                        serviceAccounts,
                        isDark,
                        openTokens,
                        openEdit,
                        setActiveModal
                    )}
            </div>

            <CreateServiceAccountModal
                isOpen={activeModal?.type === 'create'}
                formError={formError}
                formName={formName}
                setFormName={setFormName}
                formDescription={formDescription}
                setFormDescription={setFormDescription}
                formScopes={formScopes}
                onToggleScope={toggleScope}
                onSubmit={handleCreate}
                onClose={closeModal}
                isPending={createMutation.isPending}
            />

            <EditServiceAccountModal
                isOpen={activeModal?.type === 'edit'}
                formError={formError}
                formName={formName}
                setFormName={setFormName}
                formDescription={formDescription}
                setFormDescription={setFormDescription}
                formScopes={formScopes}
                onToggleScope={toggleScope}
                onSubmit={handleUpdate}
                onClose={closeModal}
                isPending={updateMutation.isPending}
            />

            <DeactivateServiceAccountModal
                activeModal={activeModal}
                onDeactivate={handleDeactivate}
                onClose={closeModal}
                isPending={deactivateMutation.isPending}
            />

            <CredentialsModal
                createdCreds={createdCreds}
                isDark={isDark}
                copiedField={copiedField}
                onCopy={handleCopy}
                onClose={() => setCreatedCreds(null)}
                onConfirm={() => {
                    setCreatedCreds(null);
                    setCopiedField(null);
                }}
            />

            <TokensModal
                activeModal={activeModal}
                isDark={isDark}
                tokens={tokens}
                tokensLoading={tokensLoading}
                createdAccessToken={createdAccessToken}
                copiedField={copiedField}
                onCopy={handleCopy}
                onDismissAccessToken={() => {
                    setCreatedAccessToken(null);
                    setCopiedField(null);
                }}
                showTokenForm={showTokenForm}
                onToggleTokenForm={() => {
                    setShowTokenForm((f) => !f);
                    setTokenFormError('');
                }}
                tokenFormError={tokenFormError}
                tokenDescription={tokenDescription}
                setTokenDescription={setTokenDescription}
                tokenExpiresAt={tokenExpiresAt}
                setTokenExpiresAt={setTokenExpiresAt}
                onCancelTokenForm={() => {
                    setShowTokenForm(false);
                    setTokenFormError('');
                }}
                onCreateToken={handleCreateToken}
                createTokenPending={createTokenMutation.isPending}
                pendingRevokeTokenId={pendingRevokeTokenId}
                setPendingRevokeTokenId={setPendingRevokeTokenId}
                revokeTokenMutation={revokeTokenMutation}
                onRevokeToken={handleRevokeToken}
                onClose={closeModal}
            />
        </>
    );
};
