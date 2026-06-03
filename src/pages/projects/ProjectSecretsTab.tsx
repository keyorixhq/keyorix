import React from 'react';
import { useSearchParams } from 'react-router-dom';
import {
    PlusIcon, MagnifyingGlassIcon,
    ChevronLeftIcon, ChevronRightIcon, FunnelIcon,
} from '@heroicons/react/24/outline';
import { SecretType } from '../../types';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { Select } from '../../components/ui/Select';
import { Loading } from '../../components/ui/Loading';
import { SecretTableRow, SecretDetailView, useSecretReveal } from '../../features/secrets';
import { useProjectSecrets } from '../../features/secrets/useProjectSecrets';
import { ShareSecretModal } from '../../features/sharing';
import { EnvironmentPills } from '../../features/projects/EnvironmentPills';
import { useProjectEnvironments } from '../../features/projects/api';

const SECRET_TYPES: { value: SecretType | 'all'; label: string }[] = [
    { value: 'all', label: 'All Types' },
    { value: 'text', label: 'Text' },
    { value: 'password', label: 'Password' },
    { value: 'api_key', label: 'API Key' },
    { value: 'certificate', label: 'Certificate' },
    { value: 'json', label: 'JSON' },
];

const PAGE_SIZE_OPTIONS = [
    { value: '10', label: '10 / page' },
    { value: '20', label: '20 / page' },
    { value: '50', label: '50 / page' },
];

function generateSecret(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const arr = new Uint8Array(32);
    window.crypto.getRandomValues(arr);
    return Array.from(arr).map(b => chars[b % chars.length]).join('');
}

interface ProjectSecretsTabProps {
    projectId: number;
}

export const ProjectSecretsTab: React.FC<ProjectSecretsTabProps> = ({ projectId }) => {
    const [searchParams, setSearchParams] = useSearchParams();
    const reveal = useSecretReveal();

    // ── Environment selection ─────────────────────────────────────────────
    const { data: environments = [], isLoading: envsLoading } = useProjectEnvironments(projectId);

    // Default to 'production' if present, otherwise first env
    const defaultEnvName = React.useMemo(() => {
        if (environments.length === 0) return 'production';
        const prod = environments.find(e => e.name.toLowerCase() === 'production');
        return prod?.name ?? environments[0]?.name ?? 'production';
    }, [environments]);

    const activeEnvName = searchParams.get('env') ?? defaultEnvName;

    // Set default env in URL once environments load and no param is set
    React.useEffect(() => {
        if (environments.length > 0 && !searchParams.get('env')) {
            setSearchParams(prev => { prev.set('env', defaultEnvName); return prev; }, { replace: true });
        }
    }, [environments, defaultEnvName, searchParams, setSearchParams]);

    const activeEnv = environments.find(e => e.name === activeEnvName) ?? null;
    const activeEnvId = activeEnv?.id ?? null;

    const handleEnvChange = (envName: string) => {
        setSearchParams(prev => { prev.set('env', envName); return prev; }, { replace: true });
    };

    // ── Secrets data ──────────────────────────────────────────────────────
    const list = useProjectSecrets({ projectId, environmentId: activeEnvId });

    // ── Local modal state (create / edit / rotate) ────────────────────────
    const [viewingSecret, setViewingSecret] = React.useState<any>(null);
    const [createName, setCreateName] = React.useState('');
    const [createValue, setCreateValue] = React.useState('');
    const [createType, setCreateType] = React.useState<SecretType>('text');
    const [editName, setEditName] = React.useState('');
    const [editType, setEditType] = React.useState<SecretType>('text');
    const [editValue, setEditValue] = React.useState('');
    const [rotateValue, setRotateValue] = React.useState('');

    React.useEffect(() => {
        if (list.activeModal === 'edit-secret' && list.modalData?.secret) {
            setEditName(list.modalData.secret.name);
            setEditType(list.modalData.secret.type as SecretType);
            setEditValue('');
        }
        if (list.activeModal === 'rotate-secret') {
            setRotateValue(generateSecret());
        }
    }, [list.activeModal, list.modalData]);

    const resetCreate = () => { setCreateName(''); setCreateValue(''); setCreateType('text'); };

    const handleCreate = () => {
        if (!createName.trim() || !createValue.trim()) return;
        list.createMutation.mutate({
            name: createName.trim(),
            value: createValue,
            type: createType,
            project_id: projectId,
            ...(activeEnvId ? { environment_id: activeEnvId } : {}),
        }, { onSuccess: resetCreate });
    };

    // ── Selected items (bulk delete) ─────────────────────────────────────
    const [selectedItems, setSelectedItems] = React.useState<Set<number>>(new Set());
    const toggleSelected = (id: number) => setSelectedItems(prev => {
        const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next;
    });
    const clearSelected = () => setSelectedItems(new Set());

    if (list.error) {
        return (
            <Alert type="error" title="Failed to load secrets"
                message="There was an error loading secrets for this project.">
                <Button variant="outline" size="sm" onClick={() => list.refetch()}>Retry</Button>
            </Alert>
        );
    }

    return (
        <div>
            {/* Environment pills */}
            <EnvironmentPills
                environments={environments}
                activeEnvName={activeEnvName}
                onChange={handleEnvChange}
                isLoading={envsLoading}
            />

            {/* Toolbar */}
            <div className="flex flex-wrap items-center gap-3 mb-4">
                {/* Search */}
                <div className="relative flex-1 min-w-[200px]">
                    <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4"
                        style={{ color: 'var(--text-muted)' }} />
                    <input
                        type="text"
                        value={list.search}
                        onChange={e => list.setSearch(e.target.value)}
                        placeholder="Search secrets…"
                        className="w-full pl-9 pr-4 py-2 rounded-lg text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-surface)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                </div>

                {/* Type filter */}
                <div className="w-36">
                    <Select
                        value={list.typeFilter}
                        onChange={e => list.setTypeFilter(e.target.value as SecretType | 'all')}
                        options={SECRET_TYPES}
                    />
                </div>

                {/* Page size */}
                <div className="w-28">
                    <Select
                        value={String(list.pagination.pageSize)}
                        onChange={e => list.handlePageSizeChange(Number(e.target.value))}
                        options={PAGE_SIZE_OPTIONS}
                    />
                </div>

                {/* Bulk actions */}
                {selectedItems.size > 0 && (
                    <div className="flex items-center gap-2">
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {selectedItems.size} selected
                        </span>
                        <Button variant="ghost" size="sm" onClick={clearSelected}>Clear</Button>
                    </div>
                )}

                {/* New Secret */}
                <Button onClick={() => list.openModal('create-secret')} className="flex items-center ml-auto">
                    <PlusIcon className="h-4 w-4 mr-1" />New Secret
                </Button>
            </div>

            {/* Table */}
            <div className="rounded-lg border" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                {list.isLoading ? (
                    <div className="p-8"><Loading /></div>
                ) : list.secrets.length === 0 ? (
                    <div className="p-10 text-center">
                        <FunnelIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
                        <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            {list.search || list.typeFilter !== 'all' ? 'No secrets match your filters' : `No secrets in ${activeEnvName}`}
                        </p>
                        {!(list.search || list.typeFilter !== 'all') && (
                            <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                                Create your first secret in this environment.
                            </p>
                        )}
                        {!(list.search || list.typeFilter !== 'all') && (
                            <Button onClick={() => list.openModal('create-secret')}>
                                <PlusIcon className="h-4 w-4 mr-1" />New Secret
                            </Button>
                        )}
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y" style={{ borderColor: 'var(--border)' }}>
                            <thead style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                <tr>
                                    <th className="px-4 py-3 text-left w-10">
                                        <input type="checkbox"
                                            className="rounded-sm border-gray-300 text-blue-600"
                                            checked={list.secrets.length > 0 && list.secrets.every(s => selectedItems.has(s.id))}
                                            onChange={e => {
                                                if (e.target.checked) list.secrets.forEach(s => toggleSelected(s.id));
                                                else clearSelected();
                                            }}
                                        />
                                    </th>
                                    {['Name', 'Type', 'Environment', 'Sharing', 'Modified'].map(h => (
                                        <th key={h}
                                            className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider"
                                            style={{ color: 'var(--text-muted)' }}>
                                            {h}
                                        </th>
                                    ))}
                                    <th className="px-6 py-3 text-right text-xs font-medium uppercase tracking-wider min-w-[180px]"
                                        style={{ color: 'var(--text-muted)' }}>
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                                {list.secrets.map(secret => (
                                    <SecretTableRow
                                        key={secret.id}
                                        secret={secret}
                                        isSelected={selectedItems.has(secret.id)}
                                        onToggleSelect={toggleSelected}
                                        onView={setViewingSecret}
                                        onEdit={s => list.openModal('edit-secret', { secret: s })}
                                        onDelete={s => list.openModal('delete-secret', { secret: s })}
                                        onShare={s => list.openModal('share-secret', { secret: s })}
                                        onRotate={s => list.openModal('rotate-secret', { secret: s })}
                                        onCopy={reveal.handleCopySecretValue}
                                        copyingId={reveal.copyingSecretId}
                                        copiedId={reveal.copiedSecretId}
                                        copyErrorId={reveal.copyErrorId}
                                    />
                                ))}
                            </tbody>
                        </table>

                        {/* Pagination */}
                        {list.pagination.totalPages > 1 && (
                            <div className="px-4 py-3 border-t flex items-center justify-between"
                                style={{ borderColor: 'var(--border)' }}>
                                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                    {(list.pagination.page - 1) * list.pagination.pageSize + 1}–
                                    {Math.min(list.pagination.page * list.pagination.pageSize, list.pagination.total)}{' '}
                                    of {list.pagination.total}
                                </p>
                                <div className="flex items-center gap-2">
                                    <Button variant="outline" size="sm"
                                        onClick={() => list.handlePageChange(list.pagination.page - 1)}
                                        disabled={list.pagination.page === 1}>
                                        <ChevronLeftIcon className="h-4 w-4" />
                                    </Button>
                                    <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                        {list.pagination.page} / {list.pagination.totalPages}
                                    </span>
                                    <Button variant="outline" size="sm"
                                        onClick={() => list.handlePageChange(list.pagination.page + 1)}
                                        disabled={list.pagination.page === list.pagination.totalPages}>
                                        <ChevronRightIcon className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* Fetching indicator */}
            {list.isFetching && !list.isLoading && (
                <div className="flex items-center gap-2 mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                    <div className="animate-spin rounded-full h-3 w-3 border-b border-blue-500" />
                    Updating…
                </div>
            )}

            {/* ── Modals ── */}

            {/* View */}
            <Modal isOpen={viewingSecret !== null} onClose={() => setViewingSecret(null)} size="xl">
                {viewingSecret && (
                    <SecretDetailView
                        secret={viewingSecret}
                        onClose={() => setViewingSecret(null)}
                        onEdit={s => { setViewingSecret(null); list.openModal('edit-secret', { secret: s }); }}
                        onShare={s => { setViewingSecret(null); list.openModal('share-secret', { secret: s }); }}
                        onDelete={s => { setViewingSecret(null); list.openModal('delete-secret', { secret: s }); }}
                    />
                )}
            </Modal>

            {/* Create */}
            <Modal
                isOpen={list.activeModal === 'create-secret'}
                onClose={() => { list.closeModal(); resetCreate(); }}
                title="New Secret"
                size="md"
            >
                <form onSubmit={e => { e.preventDefault(); handleCreate(); }} className="space-y-4">
                    {list.createMutation.isError && (
                        <Alert type="error" title="Failed to create secret"
                            message={list.createMutation.error instanceof Error ? list.createMutation.error.message : 'Unexpected error'} />
                    )}

                    {/* Context badge */}
                    <div className="flex items-center gap-2 text-xs px-3 py-2 rounded-lg"
                        style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' }}>
                        <span className="font-medium">Environment:</span>
                        <span>{activeEnvName.charAt(0).toUpperCase() + activeEnvName.slice(1)}</span>
                    </div>

                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            Name <span style={{ color: 'var(--error)' }}>*</span>
                        </label>
                        <input type="text" required value={createName}
                            onChange={e => setCreateName(e.target.value)}
                            autoFocus
                            className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }}
                        />
                    </div>

                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label className="block text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
                                Value <span style={{ color: 'var(--error)' }}>*</span>
                            </label>
                            <button type="button" onClick={() => setCreateValue(generateSecret())}
                                className="text-xs font-medium" style={{ color: 'var(--accent-text)' }}>
                                ↻ Generate
                            </button>
                        </div>
                        <textarea required rows={3} value={createValue}
                            onChange={e => setCreateValue(e.target.value)}
                            className="w-full rounded-lg border px-3 py-2 text-sm font-mono outline-hidden resize-none focus:ring-2 focus:ring-blue-500"
                            style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }}
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Type</label>
                        <Select value={createType} onChange={e => setCreateType(e.target.value as SecretType)}
                            options={SECRET_TYPES.filter(t => t.value !== 'all') as { value: SecretType; label: string }[]} />
                    </div>

                    <div className="flex justify-end gap-2 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button type="button" variant="outline"
                            onClick={() => { list.closeModal(); resetCreate(); }}
                            disabled={list.createMutation.isPending}>
                            Cancel
                        </Button>
                        <Button type="submit" disabled={list.createMutation.isPending || !createName.trim() || !createValue.trim()}>
                            {list.createMutation.isPending ? 'Creating…' : 'Create Secret'}
                        </Button>
                    </div>
                </form>
            </Modal>

            {/* Edit */}
            <Modal isOpen={list.activeModal === 'edit-secret'} onClose={list.closeModal}
                title={`Edit Secret: ${list.modalData?.secret?.name ?? ''}`} size="md">
                <form onSubmit={e => {
                    e.preventDefault();
                    if (!list.modalData?.secret) return;
                    list.editMutation.mutate({ id: list.modalData.secret.id, name: editName, type: editType, value: editValue });
                }} className="space-y-4">
                    {list.editMutation.isError && (
                        <Alert type="error" title="Failed to update secret"
                            message={list.editMutation.error instanceof Error ? list.editMutation.error.message : 'Unexpected error'} />
                    )}
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Name</label>
                        <input type="text" required value={editName} onChange={e => setEditName(e.target.value)}
                            className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
                            style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }} />
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Type</label>
                        <Select value={editType} onChange={e => setEditType(e.target.value as SecretType)}
                            options={SECRET_TYPES.filter(t => t.value !== 'all') as { value: SecretType; label: string }[]} />
                    </div>
                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label className="block text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>New Value</label>
                            <button type="button" onClick={() => setEditValue(generateSecret())}
                                className="text-xs font-medium" style={{ color: 'var(--accent-text)' }}>↻ Generate</button>
                        </div>
                        <input type="text" value={editValue} onChange={e => setEditValue(e.target.value)}
                            placeholder="Leave blank to keep existing"
                            className="w-full rounded-lg border px-3 py-2 text-sm font-mono outline-hidden"
                            style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }} />
                    </div>
                    <div className="flex justify-end gap-2 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button type="button" variant="outline" onClick={list.closeModal} disabled={list.editMutation.isPending}>Cancel</Button>
                        <Button type="submit" disabled={list.editMutation.isPending}>
                            {list.editMutation.isPending ? 'Saving…' : 'Save Changes'}
                        </Button>
                    </div>
                </form>
            </Modal>

            {/* Delete */}
            <Modal isOpen={list.activeModal === 'delete-secret'} onClose={list.closeModal} title="Delete Secret" size="sm">
                <div className="space-y-4">
                    {list.deleteMutation.isError && (
                        <Alert type="error" title="Failed to delete secret"
                            message={list.deleteMutation.error instanceof Error ? list.deleteMutation.error.message : 'Unexpected error'} />
                    )}
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Delete <span className="font-semibold">{list.modalData?.secret?.name}</span>? It can be restored within 30 days.
                    </p>
                    <div className="flex justify-end gap-2 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button variant="outline" onClick={list.closeModal} disabled={list.deleteMutation.isPending}>Cancel</Button>
                        <Button variant="danger"
                            onClick={() => list.modalData?.secret && list.deleteMutation.mutate(list.modalData.secret.id)}
                            disabled={list.deleteMutation.isPending}>
                            {list.deleteMutation.isPending ? 'Deleting…' : 'Delete'}
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Share */}
            {list.activeModal === 'share-secret' && list.modalData?.secret && (
                <ShareSecretModal
                    secret={list.modalData.secret}
                    isOpen
                    onClose={list.closeModal}
                    onSuccess={() => { list.closeModal(); list.refetch(); }}
                />
            )}

            {/* Rotate */}
            <Modal isOpen={list.activeModal === 'rotate-secret'} onClose={list.closeModal}
                title={`Rotate: ${list.modalData?.secret?.name ?? ''}`} size="sm">
                <form onSubmit={e => {
                    e.preventDefault();
                    if (!list.modalData?.secret) return;
                    list.rotateMutation.mutate({ id: list.modalData.secret.id, newValue: rotateValue });
                }} className="space-y-4">
                    {list.rotateMutation.isError && (
                        <Alert type="error" title="Failed to rotate secret"
                            message={list.rotateMutation.error instanceof Error ? list.rotateMutation.error.message : 'Unexpected error'} />
                    )}
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        A new random value has been generated. Edit or regenerate, then click Rotate.
                    </p>
                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label className="block text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>New Value</label>
                            <button type="button" onClick={() => setRotateValue(generateSecret())}
                                className="text-xs font-medium" style={{ color: 'var(--accent-text)' }}>↻ Regenerate</button>
                        </div>
                        <input type="text" value={rotateValue} onChange={e => setRotateValue(e.target.value)}
                            className="w-full rounded-lg border px-3 py-2 text-sm font-mono outline-hidden"
                            style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }} />
                    </div>
                    <div className="flex justify-end gap-2 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button type="button" variant="outline" onClick={list.closeModal} disabled={list.rotateMutation.isPending}>Cancel</Button>
                        <Button type="submit" disabled={list.rotateMutation.isPending || !rotateValue.trim()}>
                            {list.rotateMutation.isPending ? 'Rotating…' : 'Rotate'}
                        </Button>
                    </div>
                </form>
            </Modal>
        </div>
    );
};
