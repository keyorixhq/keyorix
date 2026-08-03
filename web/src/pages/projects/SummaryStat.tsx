import React from 'react';

interface SummaryStatProps {
    label: string;
    value: number;
    tone?: string | undefined;
}

export const SummaryStat: React.FC<SummaryStatProps> = ({ label, value, tone }) => (
    <div
        className="rounded-lg border px-4 py-3"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="text-2xl font-semibold" style={{ color: tone ?? 'var(--text-primary)' }}>
            {value}
        </div>
        <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {label}
        </div>
    </div>
);
