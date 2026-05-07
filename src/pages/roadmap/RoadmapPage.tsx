import React from 'react';

type BadgeVariant = 'shipped' | 'in-progress' | 'planned' | 'roadmap';

const BADGE_STYLES: Record<BadgeVariant, React.CSSProperties> = {
    shipped: { backgroundColor: 'rgba(34,197,94,0.15)', color: '#16a34a' },
    'in-progress': { backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' },
    planned: { backgroundColor: 'rgba(245,158,11,0.15)', color: '#d97706' },
    roadmap: { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' },
};

const BADGE_LABELS: Record<BadgeVariant, string> = {
    shipped: 'Shipped',
    'in-progress': 'In Progress',
    planned: 'Planned',
    roadmap: 'Roadmap',
};

interface QuarterCardProps {
    quarter: string;
    badge: BadgeVariant;
    items: string[];
}

const QuarterCard: React.FC<QuarterCardProps> = ({ quarter, badge, items }) => (
    <div className="rounded-xl border overflow-hidden mb-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
        <div className="px-6 py-4 border-b flex items-center justify-between"
            style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                {quarter}
            </h2>
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full"
                style={BADGE_STYLES[badge]}>
                {BADGE_LABELS[badge]}
            </span>
        </div>
        <div className="px-6 py-5">
            <ul className="space-y-2">
                {items.map((item, i) => (
                    <li key={i} className="flex items-start gap-2.5">
                        <span className="h-1.5 w-1.5 rounded-full flex-shrink-0 mt-1.5 opacity-60"
                            style={{ backgroundColor: 'var(--text-muted)' }} />
                        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{item}</span>
                    </li>
                ))}
            </ul>
        </div>
    </div>
);

export const RoadmapPage: React.FC = () => (
    <div className="max-w-2xl mx-auto px-6 py-8">
        <div className="mb-8">
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                Roadmap
            </h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                What's being built and when. Updated as priorities change.
            </p>
        </div>

        <QuarterCard
            quarter="Now — v0.1.0"
            badge="shipped"
            items={[
                'Secret CRUD, versioning, and rotation',
                'AES-256-GCM envelope encryption with key rotation',
                'Full RBAC with groups and sharing',
                'Two-layer audit logging (system + per-secret)',
                'PostgreSQL + SQLite backends',
                'Go, Python, Node.js SDKs',
                'CLI with project context (keyorix project use)',
                'Docker Compose with auto-seeding',
                'Dark / light / system theme',
            ]}
        />

        <QuarterCard
            quarter="Q3 2026"
            badge="in-progress"
            items={[
                'Compliance mapping reports (NIS2, DORA, ISO 27001)',
                'OIDC service account authentication for CI/CD',
                'Secret rotation trigger via UI',
                'Machine identity support (non-human tokens)',
                'Project switcher in sidebar header',
            ]}
        />

        <QuarterCard
            quarter="Q4 2026"
            badge="planned"
            items={[
                'Two-tier permission model (system + project roles)',
                'User invitation and access request flows',
                'Webhook notifications for rotation events',
                'Kubernetes operator (alpha)',
                'Self-hosted install health monitoring',
            ]}
        />

        <QuarterCard
            quarter="2027"
            badge="roadmap"
            items={[
                'Keyorix Connect federation UI',
                'Cross-environment drift detection',
                'Dynamic secrets (PostgreSQL, AWS, Azure)',
                'ML-based anomaly detection',
                'gRPC client library',
            ]}
        />

        <p className="text-xs text-center mt-8 pb-4" style={{ color: 'var(--text-muted)' }}>
            Roadmap reflects current intentions and may change.{' '}
            Enterprise features require a commercial licence.
        </p>
    </div>
);
