import React from 'react';

// ADR-025 account-state pill, shared by the user table and the detail page. A
// soft-deleted row shows "Deleted" regardless of its underlying state.

const LABEL: Record<string, string> = {
    active: 'Active',
    pending_first_login: 'Pending setup',
    password_reset_required: 'Reset required',
    suspended: 'Suspended',
    deleted: 'Deleted',
};

const STYLE: Record<string, React.CSSProperties> = {
    active: { backgroundColor: 'var(--success-subtle, #dcfce7)', color: 'var(--success, #15803d)' },
    pending_first_login: { backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' },
    password_reset_required: { backgroundColor: 'var(--warning-subtle, #fef9c3)', color: 'var(--warning, #a16207)' },
    suspended: { backgroundColor: 'var(--error-subtle, #fee2e2)', color: 'var(--error, #b91c1c)' },
    deleted: { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' },
};

export const AccountStateBadge: React.FC<{ state?: string | undefined; deleted?: boolean | undefined }> = ({
    state,
    deleted,
}) => {
    const key = deleted ? 'deleted' : state || 'active';
    return (
        <span
            className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
            style={STYLE[key] ?? STYLE.active}
        >
            {LABEL[key] ?? key}
        </span>
    );
};
