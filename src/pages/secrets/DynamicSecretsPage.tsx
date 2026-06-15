import React, { useEffect, useState } from 'react';
import { BoltIcon, PlusIcon, ChevronRightIcon } from '@heroicons/react/24/outline';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Select } from '../../components/ui/Select';
import { Textarea } from '../../components/ui/Textarea';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';
import { useProjects, useProjectEnvironments } from '../../features/projects';
import { useAuth } from '../../features/auth';
import { classificationMeta, CLASSIFICATION_LEVELS } from '../../features/secrets/classification';
import { DYNAMIC_BACKENDS, DynamicBackend } from '../../services/dynamicSecrets';
import {
    useDynamicConfigs,
    useCreateDynamicConfig,
    useClassifyDynamicConfig,
} from '../../features/dynamic-secrets/api';
import { LeasesPanel } from '../../features/dynamic-secrets/LeasesPanel';

/**
 * Dynamic Secrets console (ADR-035). Configs are project + environment scoped, and
 * there is no global project/env in the shell, so this page carries its own
 * project/env picker (mirroring how the all-secrets page scopes its create flow).
 * Lists the configs for the selected scope with their data-classification, lets an
 * admin register a new target and reclassify, and expands each config to its leases.
 */
const DynamicSecretsPage: React.FC = () => {
    const { isAdmin } = useAuth();
    const { data: projects = [] } = useProjects();
    const [projectId, setProjectId] = useState(0);
    const { data: environments = [] } = useProjectEnvironments(projectId);
    const [environmentId, setEnvironmentId] = useState(0);

    // Default to the first project / environment once loaded.
    useEffect(() => {
        const first = projects[0];
        if (!projectId && first) setProjectId(first.id);
    }, [projects, projectId]);
    useEffect(() => {
        const first = environments[0];
        setEnvironmentId(first ? first.id : 0);
    }, [environments]);

    const { data: configs = [], isLoading, error } = useDynamicConfigs(projectId, environmentId);
    const createConfig = useCreateDynamicConfig();
    const classify = useClassifyDynamicConfig();

    const [expanded, setExpanded] = useState<number | null>(null);
    const [showCreate, setShowCreate] = useState(false);

    const reclassify = (id: number, classification: string, current: string) => {
        if (classification === current) return;
        classify.mutate({ id, classification });
    };

    return (
        <div className="p-6 max-w-5xl mx-auto">
            <div className="flex items-center justify-between mb-1">
                <h1 className="text-xl font-semibold flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                    <BoltIcon className="h-6 w-6" style={{ color: 'var(--accent)' }} />
                    Dynamic Secrets
                </h1>
                {isAdmin && projectId > 0 && (
                    <Button onClick={() => setShowCreate(true)} icon={PlusIcon}>
                        New config
                    </Button>
                )}
            </div>
            <p className="text-sm mb-4" style={{ color: 'var(--text-muted)' }}>
                On-demand database credentials (ADR-035) — short-lived leases minted from a registered target and auto-revoked at expiry.
            </p>

            {/* Project / environment scope picker. */}
            <div className="flex flex-wrap gap-3 mb-4">
                <div className="min-w-[12rem]">
                    <Select
                        label="Project"
                        value={String(projectId)}
                        onChange={e => setProjectId(Number(e.target.value))}
                        options={projects.map(p => ({ value: String(p.id), label: p.name }))}
                        placeholder="Select a project…"
                    />
                </div>
                <div className="min-w-[12rem]">
                    <Select
                        label="Environment"
                        value={String(environmentId)}
                        onChange={e => setEnvironmentId(Number(e.target.value))}
                        options={environments.map(env => ({ value: String(env.id), label: env.name }))}
                        placeholder="All environments"
                    />
                </div>
            </div>

            {error ? (
                <Alert type="error" message="Failed to load dynamic-secret configs (you may lack secrets.read on this scope)." />
            ) : isLoading ? (
                <Loading />
            ) : configs.length === 0 ? (
                <div
                    className="rounded-lg border p-8 text-center"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                >
                    <BoltIcon className="h-9 w-9 mx-auto mb-2" style={{ color: 'var(--text-muted)' }} />
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        No dynamic-secret configs in this scope yet.
                    </p>
                </div>
            ) : (
                <div className="rounded-lg border divide-y" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    {configs.map(c => (
                        <div key={c.id}>
                            <div className="flex items-center gap-3 px-4 py-3">
                                <button
                                    onClick={() => setExpanded(expanded === c.id ? null : c.id)}
                                    className="flex items-center gap-2 flex-1 min-w-0 text-left"
                                    aria-label={`Toggle leases for ${c.name}`}
                                >
                                    <ChevronRightIcon
                                        className="h-4 w-4 shrink-0 transition-transform"
                                        style={{ color: 'var(--text-muted)', transform: expanded === c.id ? 'rotate(90deg)' : 'none' }}
                                    />
                                    <span className="min-w-0">
                                        <span className="text-sm font-medium block truncate" style={{ color: 'var(--text-primary)' }}>
                                            {c.name}
                                        </span>
                                        <span className="text-xs block truncate" style={{ color: 'var(--text-muted)' }}>
                                            {c.backendType} · default {c.defaultTtlSeconds}s
                                            {c.maxTtlSeconds > 0 ? ` · max ${c.maxTtlSeconds}s` : ''}
                                        </span>
                                    </span>
                                </button>
                                {isAdmin ? (
                                    <select
                                        aria-label={`Classification for ${c.name}`}
                                        value={c.classification ?? ''}
                                        disabled={classify.isPending}
                                        onChange={e => reclassify(c.id, e.target.value, c.classification ?? '')}
                                        className="rounded-lg px-2 py-1 text-xs outline-hidden shrink-0 disabled:opacity-50"
                                        style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                                        title="Data classification (ISO 27001 A.5.12)"
                                    >
                                        {CLASSIFICATION_LEVELS.map(level => (
                                            <option key={level || 'unclassified'} value={level}>
                                                {classificationMeta(level).label}
                                            </option>
                                        ))}
                                    </select>
                                ) : (
                                    <span
                                        data-testid="dsc-classification-badge"
                                        className={`px-2 py-0.5 rounded-full text-xs font-medium shrink-0 ${classificationMeta(c.classification ?? '').color}`}
                                        title="Data classification (ISO 27001 A.5.12)"
                                    >
                                        {classificationMeta(c.classification ?? '').label}
                                    </span>
                                )}
                            </div>
                            {expanded === c.id && <LeasesPanel configId={c.id} canManage={isAdmin} />}
                        </div>
                    ))}
                </div>
            )}

            {showCreate && (
                <CreateConfigModal
                    projectId={projectId}
                    environmentId={environmentId}
                    onClose={() => setShowCreate(false)}
                    onCreate={(payload, cbs) => createConfig.mutate(payload, cbs)}
                    pending={createConfig.isPending}
                />
            )}
        </div>
    );
};

const CreateConfigModal: React.FC<{
    projectId: number;
    environmentId: number;
    pending: boolean;
    onClose: () => void;
    onCreate: (
        payload: import('../../services/dynamicSecrets').CreateDynamicConfigPayload,
        cbs: { onSuccess: () => void; onError: (e: any) => void }
    ) => void;
}> = ({ projectId, environmentId, pending, onClose, onCreate }) => {
    const [name, setName] = useState('');
    const [backendType, setBackendType] = useState<DynamicBackend>('postgres');
    const [adminDsn, setAdminDsn] = useState('');
    const [creationTemplate, setCreationTemplate] = useState('');
    const [defaultTtl, setDefaultTtl] = useState(3600);
    const [maxTtl, setMaxTtl] = useState(86400);
    const [classification, setClassification] = useState('');
    const [error, setError] = useState('');

    const submit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!name.trim() || !adminDsn.trim()) {
            setError('Name and admin connection string are required.');
            return;
        }
        setError('');
        onCreate(
            {
                name: name.trim(),
                projectId,
                environmentId,
                backendType,
                adminDsn,
                creationTemplate,
                defaultTtlSeconds: defaultTtl,
                maxTtlSeconds: maxTtl,
                classification,
            },
            {
                onSuccess: onClose,
                onError: (err: any) =>
                    setError(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Failed to create config.'),
            }
        );
    };

    return (
        <Modal isOpen onClose={onClose} title="New dynamic-secret config" size="lg">
            <form onSubmit={submit} className="space-y-3">
                {error && <Alert type="error" message={error} />}
                <Input label="Name" value={name} onChange={e => setName(e.target.value)} placeholder="analytics-readonly" />
                <Select
                    label="Backend"
                    value={backendType}
                    onChange={e => setBackendType(e.target.value as DynamicBackend)}
                    options={DYNAMIC_BACKENDS.map(b => ({ value: b, label: b }))}
                />
                <Input
                    label="Admin connection string"
                    type="password"
                    value={adminDsn}
                    onChange={e => setAdminDsn(e.target.value)}
                    placeholder="postgres://admin:****@host:5432/db"
                    helperText="Encrypted at rest; never returned by the API."
                />
                <Textarea
                    label="Creation template (SQL run per lease; {{name}} = generated role)"
                    value={creationTemplate}
                    onChange={e => setCreationTemplate(e.target.value)}
                    rows={3}
                    placeholder={'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";'}
                />
                <div className="grid grid-cols-2 gap-3">
                    <Input
                        label="Default TTL (seconds)"
                        type="number"
                        value={String(defaultTtl)}
                        onChange={e => setDefaultTtl(Number(e.target.value))}
                    />
                    <Input
                        label="Max TTL (seconds, 0 = no cap)"
                        type="number"
                        value={String(maxTtl)}
                        onChange={e => setMaxTtl(Number(e.target.value))}
                    />
                </div>
                <Select
                    label="Classification"
                    value={classification}
                    onChange={e => setClassification(e.target.value)}
                    options={CLASSIFICATION_LEVELS.map(level => ({ value: level, label: classificationMeta(level).label }))}
                />
                <div className="flex justify-end gap-2 pt-1">
                    <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                    <Button type="submit" disabled={pending}>Create</Button>
                </div>
            </form>
        </Modal>
    );
};

export default DynamicSecretsPage;
