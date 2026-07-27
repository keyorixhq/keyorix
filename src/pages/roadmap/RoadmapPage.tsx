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
    <div
        className="rounded-xl border overflow-hidden mb-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                {quarter}
            </h2>
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full" style={BADGE_STYLES[badge]}>
                {BADGE_LABELS[badge]}
            </span>
        </div>
        <div className="px-6 py-5">
            <ul className="space-y-2">
                {items.map((item) => (
                    <li key={item} className="flex items-start gap-2.5">
                        <span
                            className="h-1.5 w-1.5 rounded-full shrink-0 mt-1.5 opacity-60"
                            style={{ backgroundColor: 'var(--text-muted)' }}
                        />
                        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                            {item}
                        </span>
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
                'Full RBAC — users, groups, roles, permissions',
                'Service accounts and API tokens for CI/CD',
                'User role assignment backed by real DB',
                'Two-layer audit logging (system + per-secret)',
                'Anomaly detection (off-hours, new IP, frequency spike)',
                'Secret expiry tracking and alerts',
                'Rotation policies (time-based, per environment)',
                'Secrets Health dashboard',
                'PostgreSQL + SQLite backends',
                'Go, Python, Node.js SDKs',
                'CLI with project context (keyorix project use)',
                'Docker Compose with auto-seeding',
                'Dark / light / system theme',
                'NIS2, DORA, ISO 27001 compliance page',
            ]}
        />

        <QuarterCard
            quarter="Q3 2026"
            badge="shipped"
            items={[
                'Project-scoped role assignments',
                'RBAC audit log UI with actor / date filters and CSV export',
                'Role creation and management UI',
                'Compliance mapping reports (NIS2, DORA, ISO 27001, SOC 2, DORA, ENS) with per-framework scores',
                'OIDC service account authentication UI for CI/CD (backend in Q4)',
                'Project switcher in sidebar header',
                'Effective permissions panel and role legend in project Members tab',
            ]}
        />

        <QuarterCard
            quarter="Q4 2026"
            badge="planned"
            items={[
                'Dynamic secrets (database credentials, cloud keys)',
                'User invitation and access request flows',
                'Webhook notifications for rotation events',
                'Kubernetes operator (alpha)',
                'Self-hosted install health monitoring',
                'OIDC federation backend (token exchange endpoint)',
                'demo.keyorix.com hosted demo environment',
            ]}
        />

        <QuarterCard
            quarter="2027"
            badge="roadmap"
            items={[
                'Keyorix Connect federation UI',
                'Cross-environment drift detection',
                'ML-based anomaly detection',
                'gRPC client library',
                'Multi-region replication',
            ]}
        />

        <p className="text-xs text-center mt-8 pb-4" style={{ color: 'var(--text-muted)' }}>
            Roadmap reflects current intentions and may change. Enterprise features require a commercial licence.
        </p>
    </div>
);
