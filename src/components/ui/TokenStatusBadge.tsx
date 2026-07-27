import React from 'react';

export type TokenStatus = 'active' | 'revoked' | 'expired';

interface TokenLike {
    revoked: boolean;
    expires_at?: string | null;
}

export function getTokenStatus(token: TokenLike): TokenStatus {
    if (token.revoked) return 'revoked';
    if (token.expires_at && new Date(token.expires_at) <= new Date()) return 'expired';
    return 'active';
}

interface Props {
    status: TokenStatus;
    isDark: boolean;
}

export function TokenStatusBadge({ status, isDark }: Readonly<Props>) {
    const styles: Record<TokenStatus, React.CSSProperties> = {
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
    const labels: Record<TokenStatus, string> = { active: 'Active', revoked: 'Revoked', expired: 'Expired' };
    return (
        <span
            className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
            style={styles[status]}
        >
            {labels[status]}
        </span>
    );
}
