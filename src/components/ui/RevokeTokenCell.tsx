import React from 'react';
import { Button } from './Button';

interface RevokeTokenCellProps {
    isPending: boolean;
    isMutating: boolean;
    inactive: boolean;
    isDark: boolean;
    onRevoke: () => void;
    onCancel: () => void;
    onSetPending: () => void;
}

export const RevokeTokenCell: React.FC<RevokeTokenCellProps> = ({
    isPending,
    isMutating,
    inactive,
    isDark,
    onRevoke,
    onCancel,
    onSetPending,
}) => {
    const activeRed = isDark ? '#f87171' : '#dc2626';
    const revokeColor = inactive ? 'var(--text-muted)' : activeRed;

    if (isPending) {
        return (
            <div className="flex items-center justify-end gap-2">
                <span className="text-xs text-base-muted">Revoke?</span>
                <Button variant="destructive" size="sm" onClick={onRevoke} disabled={isMutating}>
                    {isMutating ? '…' : 'Revoke'}
                </Button>
                <Button variant="ghost" size="sm" onClick={onCancel}>
                    Cancel
                </Button>
            </div>
        );
    }
    return (
        <button
            type="button"
            onClick={onSetPending}
            disabled={inactive}
            className="text-xs font-medium px-2.5 py-1 rounded-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            style={{ color: revokeColor, backgroundColor: 'transparent' }}
            onMouseEnter={(e) => {
                if (!inactive)
                    (e.currentTarget as HTMLElement).style.backgroundColor =
                        isDark ? 'rgba(239,68,68,0.12)' : '#fee2e2';
            }}
            onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent';
            }}
        >
            Revoke
        </button>
    );
};
