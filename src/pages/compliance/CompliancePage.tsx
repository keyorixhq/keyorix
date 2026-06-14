import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { complianceApi } from '../../services/compliance';

interface SectionCardProps {
    title: string;
    children: React.ReactNode;
}

const Tile: React.FC<{ label: string; value: React.ReactNode; tone?: 'good' | 'warn' | 'bad' | undefined }> = ({ label, value, tone }) => {
    const color = tone === 'good' ? 'var(--success)' : tone === 'warn' ? 'var(--warning)' : tone === 'bad' ? 'var(--error)' : 'var(--text-primary)';
    return (
        <div className="rounded-lg border px-3 py-2.5" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-app)' }}>
            <div className="text-lg font-semibold" style={{ color }}>{value}</div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{label}</div>
        </div>
    );
};

// PosturePanel surfaces the live controls-posture report (GET /compliance/posture).
// It needs system.read; non-admins get 403 and the panel shows a quiet note rather
// than failing the page.
const PosturePanel: React.FC = () => {
    const { data: p, isLoading, isError, error } = useQuery({
        queryKey: ['compliance', 'posture'],
        queryFn: () => complianceApi.getPosture(),
        staleTime: 60_000,
        retry: false,
    });

    if (isLoading) {
        return (
            <div className="rounded-xl border mb-6 p-6" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[1, 2, 3, 4].map(i => <div key={i} className="h-16 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-muted)' }} />)}
                </div>
            </div>
        );
    }
    if (isError || !p) {
        const status = (error as any)?.response?.status;
        return (
            <div className="rounded-xl border mb-6 px-6 py-4 text-sm" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)', color: 'var(--text-muted)' }}>
                {status === 403 ? 'The live controls-posture report is available to administrators (system.read).' : 'Controls posture is currently unavailable.'}
            </div>
        );
    }

    const ag = p.accessGovernance;
    const reviewed = ag.projects - ag.projectsNeverReviewed;
    return (
        <div className="rounded-xl border mb-8 overflow-hidden" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
            <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>Controls posture</h2>
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{p.generatedAt ? new Date(p.generatedAt).toLocaleString() : ''}</span>
            </div>
            <div className="px-6 py-5 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                <Tile label="Audit chain verified (A.5.28)" value={p.auditIntegrity.chainVerified ? 'Yes' : 'No'} tone={p.auditIntegrity.chainVerified ? 'good' : 'bad'} />
                <Tile label="On-box checkpointed" value={p.auditIntegrity.checkpointed ? 'Yes' : 'No'} tone={p.auditIntegrity.checkpointed ? 'good' : undefined} />
                <Tile label="Second-factor coverage" value={`${p.identity.secondFactorPercent}%`} tone={p.identity.secondFactorPercent >= 80 ? 'good' : 'warn'} />
                <Tile label="Active users" value={p.identity.activeUsers} />
                <Tile label="Projects reviewed (A.5.18)" value={`${reviewed}/${ag.projects}`} tone={ag.projectsNeverReviewed > 0 ? 'warn' : 'good'} />
                <Tile label="Open campaigns / pending" value={`${ag.openCampaigns} / ${ag.pendingItems}`} />
                <Tile label="Dormant role grants" value={ag.dormantRoleGrants} tone={ag.dormantRoleGrants > 0 ? 'warn' : 'good'} />
                <Tile label="SoD violations (A.5.3)" value={ag.sodViolations} tone={ag.sodViolations > 0 ? 'bad' : 'good'} />
                <Tile label="Rotation overdue / due-soon (A.5.15)" value={`${p.rotation.overdue} / ${p.rotation.dueSoon}`} tone={p.rotation.overdue > 0 ? 'warn' : 'good'} />
                <Tile label="Break-glass active / total" value={`${p.emergencyAccess.activeActivations} / ${p.emergencyAccess.totalActivations}`} tone={p.emergencyAccess.activeActivations > 0 ? 'warn' : undefined} />
            </div>
        </div>
    );
};

// SoDViolationsSection lists the separation-of-duties violations (principals
// holding a forbidden permission pair). Needs system.read; hidden on 403/empty.
const SoDViolationsSection: React.FC = () => {
    const { data: violations = [], isError } = useQuery({
        queryKey: ['sod', 'violations'],
        queryFn: () => complianceApi.getSoDViolations(),
        staleTime: 60_000,
        retry: false,
    });
    if (isError || violations.length === 0) return null;
    return (
        <div className="rounded-xl border mb-8 overflow-hidden" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
            <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--error)' }}>
                    Separation-of-duties violations ({violations.length})
                </h2>
            </div>
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {violations.map((v, i) => (
                    <li key={i} className="px-6 py-3 flex items-center gap-3">
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                {v.email ? `${v.username} (${v.email})` : v.username}
                            </p>
                            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{v.policyName}</p>
                        </div>
                        <span className="text-xs px-2 py-1 rounded-md shrink-0" style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}>
                            {v.permissionA} + {v.permissionB}
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    );
};

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
    <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="mb-8">
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                Compliance
            </h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                Your live controls posture, and how Keyorix supports your regulatory obligations.
            </p>
        </div>

        <PosturePanel />
        <SoDViolationsSection />

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
