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
            {children}
        </div>
    </div>
);

export const KeyorixConnectPage: React.FC = () => (
    <div className="max-w-2xl mx-auto px-6 py-8">
        <div className="mb-8">
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                Keyorix Connect
            </h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                Federation control plane for multi-cloud secret visibility.
            </p>
        </div>

        <SectionCard title="Overview">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                Keyorix Connect lets you keep sensitive secrets on your own infrastructure while extending
                visibility across Azure Key Vault, AWS Secrets Manager, and HashiCorp Vault estates. The
                control plane stays on-premise. Remote stores are read-only federations — secrets do not
                leave their origin.
            </p>
        </SectionCard>

        <SectionCard title="Available Now">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                The <code className="px-1 rounded-sm text-xs font-mono"
                    style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-secondary)' }}>
                    keyorix connect
                </code> CLI command is available in v0.1.0. It establishes a named remote
                connection and validates connectivity.
            </p>
            <pre className="rounded-lg p-4 mt-3 font-mono text-sm overflow-x-auto"
                style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-secondary)' }}>
                {`keyorix connect --name azure-prod \\
  --provider azure \\
  --vault-url https://myvault.vault.azure.net`}
            </pre>
        </SectionCard>

        <SectionCard title="Roadmap — 2027">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                Full federation UI, secret inventory sync, cross-store drift detection, and the Keyorix
                Connect dashboard are planned for 2027 as part of the enterprise commercial tier.
                Air-gap and on-premise deployments are the priority until then.
            </p>
        </SectionCard>

        <SectionCard title="Why This Matters">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                European enterprises running hybrid estates face a choice between vendor lock-in and
                operational complexity. Keyorix Connect is designed so your primary secrets remain on
                your infrastructure while you gain visibility over what lives in cloud-managed stores —
                without routing resolution traffic through a SaaS intermediary.
            </p>
        </SectionCard>
    </div>
);
