import React, { useState } from 'react';
import { ClipboardDocumentIcon, CheckIcon, EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Alert } from '../../components/ui/Alert';
import { Spinner } from '../../components/ui/Loading';
import { useConnectors, useReadFederatedSecret } from '../../features/connect';

interface SectionCardProps {
    title: string;
    children: React.ReactNode;
}

const SectionCard: React.FC<SectionCardProps> = ({ title, children }) => (
    <div
        className="rounded-xl border overflow-hidden mb-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                {title}
            </h2>
        </div>
        <div className="px-6 py-5">{children}</div>
    </div>
);

// FederatedReadPanel lets an operator read a secret's current value through a
// configured connector (read-through; the value is fetched on demand and audited).
const FederatedReadPanel: React.FC = () => {
    const { data: connectors, isLoading, isError } = useConnectors();
    const read = useReadFederatedSecret();
    const [connector, setConnector] = useState('');
    const [ref, setRef] = useState('');
    const [value, setValue] = useState<string | null>(null);
    const [revealed, setRevealed] = useState(false);
    const [copied, setCopied] = useState(false);
    const [error, setError] = useState('');

    if (isLoading) {
        return (
            <div className="flex justify-center py-6">
                <Spinner />
            </div>
        );
    }
    if (isError) {
        return <Alert type="error" title="Could not load connectors" message="Please try again." />;
    }
    if (!connectors || connectors.length === 0) {
        return (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                No connectors are configured. Add one under <code>connect.connectors</code> in the server
                config (AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault).
            </p>
        );
    }

    const effectiveConnector = connector || connectors[0] || '';

    const submit = (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setValue(null);
        setRevealed(false);
        read.mutate(
            { connector: effectiveConnector, ref: ref.trim() },
            {
                onSuccess: (res) => setValue(res.value),
                onError: (err) =>
                    setError(
                        (err as { response?: { data?: { message?: string } } }).response?.data?.message ||
                            (err as Error).message ||
                            'Read failed.',
                    ),
            },
        );
    };

    const copy = async () => {
        if (value == null) return;
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };

    return (
        <form onSubmit={submit} className="space-y-4">
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                Read the current value of a secret held in an external store. The value is proxied on demand,
                audited, and never stored by Keyorix.
            </p>
            {error && <Alert type="error" message={error} />}
            <div>
                <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                    Connector
                </label>
                <select
                    aria-label="Connector"
                    className="text-sm px-3 py-2 rounded-md w-full"
                    style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                    value={effectiveConnector}
                    onChange={(e) => setConnector(e.target.value)}
                >
                    {connectors.map((c) => (
                        <option key={c} value={c}>
                            {c}
                        </option>
                    ))}
                </select>
            </div>
            <Input
                label="Reference"
                placeholder="e.g. prod/db (AWS), projects/p/secrets/x/versions/latest (GCP), secret/data/app (Vault)"
                value={ref}
                onChange={(e) => setRef(e.target.value)}
            />
            <div className="flex justify-end">
                <Button type="submit" disabled={read.isPending || !ref.trim()}>
                    {read.isPending && <Spinner size="sm" className="mr-2" />}
                    Read secret
                </Button>
            </div>

            {value != null && (
                <div
                    className="rounded-lg p-4"
                    style={{ backgroundColor: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
                >
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-xs uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                            Value
                        </span>
                        <div className="flex gap-2">
                            <Button variant="outline" size="sm" onClick={() => setRevealed((r) => !r)} type="button">
                                {revealed ? <EyeSlashIcon className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
                            </Button>
                            <Button variant="outline" size="sm" onClick={copy} type="button">
                                {copied ? <CheckIcon className="h-4 w-4" /> : <ClipboardDocumentIcon className="h-4 w-4" />}
                            </Button>
                        </div>
                    </div>
                    <code
                        className="block break-all font-mono text-sm"
                        style={{ color: 'var(--text-primary)' }}
                    >
                        {revealed ? value : '•'.repeat(Math.min(value.length, 40))}
                    </code>
                </div>
            )}
        </form>
    );
};

export const KeyorixConnectPage: React.FC = () => (
    <div className="max-w-2xl mx-auto px-6 py-8">
        <div className="mb-8">
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                Keyorix Connect
            </h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                Read-through federation for multi-cloud secret visibility.
            </p>
        </div>

        <SectionCard title="Overview">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                Keyorix Connect lets you reach secrets held in AWS Secrets Manager, GCP Secret Manager, and
                HashiCorp Vault through Keyorix's RBAC and audit trail — without migrating them. Reads are
                read-only and proxied on demand; secrets do not leave their origin store, and Keyorix never
                imports or persists their values.
            </p>
        </SectionCard>

        <SectionCard title="Read a federated secret">
            <FederatedReadPanel />
        </SectionCard>
    </div>
);
