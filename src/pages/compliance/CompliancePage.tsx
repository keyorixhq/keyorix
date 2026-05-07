import React from 'react';

interface SectionCardProps {
    title: string;
    children: React.ReactNode;
}

const SectionCard: React.FC<SectionCardProps> = ({ title, children }) => (
    <div className="rounded-xl border overflow-hidden mb-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-sm font-semibold uppercase tracking-widest"
                style={{ color: 'var(--text-muted)' }}>
                {title}
            </h2>
        </div>
        <div className="px-6 py-5">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                {children}
            </p>
        </div>
    </div>
);

export const CompliancePage: React.FC = () => (
    <div className="max-w-2xl mx-auto px-6 py-8">
        <div className="mb-8">
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                Compliance
            </h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                How Keyorix is designed to support your regulatory obligations.
            </p>
        </div>

        <SectionCard title="NIS2 Directive">
            Keyorix supports NIS2 Article 21 technical requirements — access controls, encryption
            of data at rest and in transit, and audit logging. Every secret access, rotation, and
            user action is logged with actor identity and timestamp. On-premise deployment means
            audit data stays on your infrastructure under your data retention policy.
        </SectionCard>

        <SectionCard title="DORA">
            DORA Article 30 requires financial entities to maintain detailed ICT risk management
            records including access logs and cryptographic controls. Keyorix provides tamper-evident
            audit logs, envelope encryption with key rotation support, and PostgreSQL-backed storage
            designed for long-term operational continuity. Air-gap compatibility means no dependency
            on external cloud services for secret resolution.
        </SectionCard>

        <SectionCard title="ISO 27001">
            Keyorix maps directly to ISO 27001 Annex A controls for access management (A.9),
            cryptography (A.10), and operations security (A.12). RBAC, AES-256-GCM encryption, and
            full audit trails are shipped by default — not add-ons. On-premise deployment supports
            your organisation's asset management and boundary control requirements.
        </SectionCard>

        <p className="text-xs text-center mt-8 pb-4" style={{ color: 'var(--text-muted)' }}>
            Detailed compliance mapping reports — Q3 2026.{' '}
            Contact support@keyorix.com for pre-release access.
        </p>
    </div>
);
