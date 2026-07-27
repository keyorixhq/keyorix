import React, { useState } from 'react';
import { useQueries } from '@tanstack/react-query';
import { CircleStackIcon } from '@heroicons/react/24/outline';
import { useServiceAccounts, useRevokeToken } from '../../features/admin';
import { serviceAccountsApi } from '../../services/serviceAccounts';
import { APIToken } from '../../types/serviceAccounts';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';
import { TokenStatusBadge, getTokenStatus } from '../../components/ui/TokenStatusBadge';
import { useUIStore } from '../../store/uiStore';
import { formatDateShort } from '../../utils';

interface FlatToken extends APIToken {
    serviceAccountName: string;
}


export const APITokensPage: React.FC = () => {
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

    const [pageError, setPageError] = useState('');
    const [pendingRevokeTokenId, setPendingRevokeTokenId] = useState<number | null>(null);

    const { data: serviceAccounts = [], isLoading: saLoading, isError: saError } = useServiceAccounts();

    const tokenQueries = useQueries({
        queries: serviceAccounts.map((sa) => ({
            queryKey: ['service-account-tokens', sa.id],
            queryFn: () => serviceAccountsApi.listTokens(sa.id),
            staleTime: 60 * 1000,
        })),
    });

    const tokensLoading = tokenQueries.some((q) => q.isLoading);

    const flatTokens: FlatToken[] = [];
    serviceAccounts.forEach((sa, i) => {
        const tokens = tokenQueries[i]?.data ?? [];
        tokens.forEach((token) => {
            flatTokens.push({ ...token, serviceAccountName: sa.name });
        });
    });

    const revokeTokenMutation = useRevokeToken();

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

    let mainContent: React.ReactNode;
    if (saLoading || tokensLoading) {
        mainContent = <Loading className="py-20" />;
    } else if (saError) {
        mainContent = (
            <Alert
                type="error"
                title="Failed to load service accounts"
                message="Check that the server is running and you have admin access."
            />
        );
    } else if (flatTokens.length === 0) {
        mainContent = (
            <div className="text-center py-20 text-base-muted">
                <CircleStackIcon className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p className="text-sm">No tokens found across any service accounts.</p>
            </div>
        );
    } else {
        mainContent = (
            <div className="bg-surface border border-base rounded-lg overflow-hidden shadow-xs">
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-base">
                        <thead>
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                    Token ID
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                    Service Account
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                    Scope
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                    Created
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                    Expires
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">
                                    Status
                                </th>
                                <th className="px-6 py-3 text-right text-xs font-medium text-base-muted uppercase tracking-wider">
                                    Actions
                                </th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-base">
                            {flatTokens.map((token) => {
                                const status = getTokenStatus(token);
                                const inactive = status === 'revoked' || status === 'expired';
                                const isPending = pendingRevokeTokenId === token.id;
                                const activeRevokeColor = isDark ? '#f87171' : '#dc2626';
                                const revokeButtonColor = inactive ? 'var(--text-muted)' : activeRevokeColor;
                                return (
                                    <tr key={token.id} className="hover:bg-subtle transition-colors">
                                        <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-base-secondary">
                                            #{token.id}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-base-secondary">
                                            {token.serviceAccountName}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            {token.scope ? (
                                                <span
                                                    className="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[11px] font-medium font-mono"
                                                    style={{
                                                        backgroundColor: isDark
                                                            ? 'rgba(59,130,246,0.15)'
                                                            : '#eff6ff',
                                                        color: isDark ? '#93c5fd' : '#1d4ed8',
                                                    }}
                                                >
                                                    {token.scope}
                                                </span>
                                            ) : (
                                                '—'
                                            )}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
                                            {formatDateShort(token.created_at)}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
                                            {token.expires_at ? formatDateShort(token.expires_at) : '—'}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <TokenStatusBadge status={status} isDark={isDark} />
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right">
                                            {isPending ? (
                                                <div className="flex items-center justify-end gap-2">
                                                    <span className="text-xs text-base-muted">Revoke?</span>
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
                                                    type="button"
                                                    onClick={() => setPendingRevokeTokenId(token.id)}
                                                    disabled={inactive}
                                                    className="text-xs font-medium px-2.5 py-1 rounded-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                                                    style={{
                                                        color: revokeButtonColor,
                                                        backgroundColor: 'transparent',
                                                    }}
                                                    onMouseEnter={(e) => {
                                                        if (!inactive)
                                                            (e.currentTarget as HTMLElement).style.backgroundColor =
                                                                isDark ? 'rgba(239,68,68,0.12)' : '#fee2e2';
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
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto px-4 py-8">
            <div className="mb-6">
                <h1 className="text-2xl font-bold text-base-primary">API Tokens</h1>
                <p className="text-sm text-base-muted mt-1">All active tokens across service accounts</p>
            </div>

            <div
                className="p-3 mb-6 rounded-lg border text-sm text-base-secondary"
                style={{ backgroundColor: 'var(--bg-subtle)', borderColor: 'var(--border)' }}
            >
                Tokens are created from individual Service Account pages. This view shows all tokens for monitoring and
                revocation.
            </div>

            {pageError && (
                <Alert type="error" title={pageError} dismissible onDismiss={() => setPageError('')} className="mb-4" />
            )}

            {mainContent}
        </div>
    );
};
