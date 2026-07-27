import React from 'react';
import { useSearchParams } from 'react-router-dom';
import {
    MagnifyingGlassIcon,
    PlusIcon,
    FunnelIcon,
    ChevronLeftIcon,
    ChevronRightIcon,
    ShareIcon,
    TrashIcon,
} from '@heroicons/react/24/outline';
import { SecretPolicy, SecretType } from '../../types';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Select } from '../../components/ui/Select';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { apiErrorMessage } from '../../services/client';
import {
    SecretDetailView,
    useSecretsList,
    useSecretReveal,
    SecretTableRow,
    useBulkClassifySecrets,
    useSetAutoRotate,
    useSecretPolicy,
} from '../../features/secrets';
import { ShareSecretModal } from '../../features/sharing';
import { useProjects, useProjectEnvironments } from '../../features/projects';
import { isPatternSafe, testPatternSafely } from '../../utils/safeRegex';

const SECRET_TYPES: { value: SecretType | 'all'; label: string }[] = [
    { value: 'all', label: 'All Types' },
    { value: 'text', label: 'Text' },
    { value: 'password', label: 'Password' },
    { value: 'api_key', label: 'API Key' },
    { value: 'certificate', label: 'Certificate' },
    { value: 'json', label: 'JSON' },
];
const SORT_OPTIONS = [
    { value: 'name_asc', label: 'Name (A-Z)' },
    { value: 'name_desc', label: 'Name (Z-A)' },
    { value: 'modified_desc', label: 'Recently Modified' },
    { value: 'modified_asc', label: 'Oldest Modified' },
    { value: 'type_asc', label: 'Type (A-Z)' },
    { value: 'type_desc', label: 'Type (Z-A)' },
    { value: 'created_desc', label: 'Recently Created' },
    { value: 'created_asc', label: 'Oldest Created' },
    { value: 'expiry_asc', label: 'Expiring Soonest' },
    { value: 'expiry_desc', label: 'Expiring Latest' },
];
const PAGE_SIZE_OPTIONS = [
    { value: '10', label: '10 per page' },
    { value: '20', label: '20 per page' },
    { value: '50', label: '50 per page' },
    { value: '100', label: '100 per page' },
];

// secretNameError returns a client-side validation message, or '' when ok.
// The server re-validates regardless — this just gives faster feedback.
function secretNameError(namePolicy: SecretPolicy['name'] | undefined, name: string): string {
    if (!namePolicy?.enabled) return '';
    if (namePolicy.max_length && name.length > namePolicy.max_length) {
        return `Name exceeds the ${namePolicy.max_length}-character maximum.`;
    }
    if (namePolicy.pattern) {
        // testPatternSafely refuses to run patterns that look like
        // catastrophic-backtracking shapes (or oversized input) -- see
        // src/utils/safeRegex.ts for why a same-thread timeout can't
        // substitute for that check.
        const result = testPatternSafely(namePolicy.pattern, name);
        if (!result.skipped && !result.matches) {
            return `Name must match the pattern ${namePolicy.pattern}.`;
        }
    }
    return '';
}

// Generates a cryptographically random secret value (32 chars, URL-safe)
function generateSecret(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const arr = new Uint8Array(32);
    window.crypto.getRandomValues(arr);
    return Array.from(arr)
        .map((b) => chars[b % chars.length])
        .join('');
}

export const SecretsListPage: React.FC = () => {
    const list = useSecretsList();
    const bulkClassify = useBulkClassifySecrets();
    const reveal = useSecretReveal();
    const [searchParams] = useSearchParams();

    // Apply URL-driven sort on mount (e.g. ?sort=expiry_asc from dashboard)
    React.useEffect(() => {
        const sort = searchParams.get('sort');
        if (sort && sort !== list.sortBy) {
            list.setSortBy(sort);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
    const urlFilter = searchParams.get('filter'); // 'expiring' | null
    const displayedSecrets =
        urlFilter === 'expiring' ? list.secrets.filter((s: any) => s.Expiration != null) : list.secrets;
    const [viewingSecret, setViewingSecret] = React.useState<any>(null);
    const [createName, setCreateName] = React.useState('');
    const [createValue, setCreateValue] = React.useState('');
    const [createType, setCreateType] = React.useState<SecretType>('text');
    const [createError, setCreateError] = React.useState('');
    // Target project/environment for a new secret. The All-Secrets create form is
    // not scoped to a project, so the user must pick one — previously this was
    // hardcoded to project 1 / env 1, which errored or misfiled on any other DB.
    const [createProjectId, setCreateProjectId] = React.useState(0);
    const [createEnvId, setCreateEnvId] = React.useState(0);
    const { data: createProjects } = useProjects();

    // Active secret-name policy, for a create-time hint + client-side pre-validation.
    const { data: secretPolicy } = useSecretPolicy();
    const namePolicy = secretPolicy?.name;
    const nameHint = !namePolicy?.enabled
        ? ''
        : [
              namePolicy.pattern ? `must match ${namePolicy.pattern}` : '',
              namePolicy.max_length ? `max ${namePolicy.max_length} chars` : '',
          ]
              .filter(Boolean)
              .join('; ');
    // The naming-policy pattern is admin-configured but untrusted from the
    // browser's perspective -- a catastrophic-backtracking shape (e.g.
    // `(a+)+$`) would hang this tab. When the pattern looks unsafe, skip the
    // live client-side check (the server still enforces it on submit) and
    // say so.
    const namePatternUnsafe = !!namePolicy?.enabled && !!namePolicy.pattern && !isPatternSafe(namePolicy.pattern);
    const { data: createEnvironments } = useProjectEnvironments(createProjectId);
    // Default the project to the first available once projects load.
    React.useEffect(() => {
        const first = createProjects?.[0];
        if (createProjectId === 0 && first) {
            setCreateProjectId(first.id);
        }
    }, [createProjects, createProjectId]);
    // When the project changes (or its environments load), keep the selected
    // environment valid — default to the first env of the chosen project.
    React.useEffect(() => {
        if (!createEnvironments) return;
        const stillValid = createEnvironments.some((e) => e.id === createEnvId);
        if (!stillValid) {
            setCreateEnvId(createEnvironments[0]?.id ?? 0);
        }
    }, [createEnvironments, createEnvId]);
    const [editName, setEditName] = React.useState('');
    const [editType, setEditType] = React.useState<SecretType>('text');
    const [editValue, setEditValue] = React.useState('');
    const [rotateValue, setRotateValue] = React.useState('');

    // Automated-rotation modal form (ADR-046/047).
    const [arEnabled, setArEnabled] = React.useState(true);
    const [arLength, setArLength] = React.useState('');
    const [arCharset, setArCharset] = React.useState('');
    const [arBackend, setArBackend] = React.useState('');
    const [arRef, setArRef] = React.useState('');
    const autoRotate = useSetAutoRotate(list.modalData?.secret?.id ?? 0);

    React.useEffect(() => {
        if (list.activeModal === 'edit-secret' && list.modalData?.secret) {
            setEditName(list.modalData.secret.name);
            setEditType(list.modalData.secret.type as SecretType);
            setEditValue('');
        }
        if (list.activeModal === 'rotate-secret') {
            setRotateValue(generateSecret());
        }
        if (list.activeModal === 'auto-rotate') {
            setArEnabled(true);
            setArLength('');
            setArCharset('');
            setArBackend('');
            setArRef('');
        }
    }, [list.activeModal, list.modalData]);

    const handleRotate = (secret: any) => {
        list.openModal('rotate-secret', { secret });
    };

    const handleAutoRotate = (secret: any) => {
        list.openModal('auto-rotate', { secret });
    };

    const submitAutoRotate = (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        if ((arBackend === '') !== (arRef === '')) return; // both-or-neither (UI guard)
        autoRotate.mutate(
            {
                enabled: arEnabled,
                length: arLength ? Number(arLength) : 0,
                charset: arCharset,
                backend: arBackend.trim(),
                ref: arRef.trim(),
            },
            { onSuccess: () => list.closeModal() }
        );
    };

    if (list.error) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load secrets"
                    message="There was an error loading your secrets. Please try again."
                >
                    <Button variant="outline" size="sm" onClick={() => list.refetch()}>
                        Retry
                    </Button>
                </Alert>
            </div>
        );
    }

    const tableBodyContent = displayedSecrets.length === 0 ? (
        <div className="p-8 text-center">
            <FunnelIcon className="h-12 w-12 mx-auto text-base-muted  mb-4" />
            <h3 className="text-lg font-medium text-base-primary  mb-2">No secrets found</h3>
            <p className="text-base-muted  mb-4">
                {list.hasActiveFilters
                    ? 'Try adjusting your filters or search terms.'
                    : 'Get started by creating your first secret.'}
            </p>
            {!list.hasActiveFilters && (
                <Button onClick={() => list.openModal('create-secret')}>
                    <PlusIcon className="h-4 w-4 mr-2" />
                    Create Secret
                </Button>
            )}
        </div>
    ) : (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-base dark:divide-gray-700">
                <thead className="bg-subtle dark:bg-gray-900">
                    <tr>
                        <th className="px-4 py-3 text-left w-10">
                            <input
                                type="checkbox"
                                className="rounded-sm border-gray-300 text-blue-600 focus:ring-blue-500"
                                checked={
                                    displayedSecrets.length > 0 &&
                                    displayedSecrets.every((s) => list.selectedItems.has(s.id))
                                }
                                onChange={(e) => {
                                    if (e.target.checked)
                                        displayedSecrets.forEach((s) => list.toggleSelectedItem(s.id));
                                    else list.clearSelectedItems();
                                }}
                            />
                        </th>
                        {['Name', 'Type', 'Classification', 'Environment', 'Sharing', 'Modified'].map(
                            (h) => (
                                <th
                                    key={h}
                                    className="px-6 py-3 text-left text-xs font-medium text-base-muted  uppercase tracking-wider"
                                >
                                    {h}
                                </th>
                            )
                        )}
                        <th className="px-6 py-3 text-right text-xs font-medium text-base-muted  uppercase tracking-wider min-w-[180px]">
                            Actions
                        </th>
                    </tr>
                </thead>
                <tbody className="bg-surface divide-y divide-base dark:divide-gray-700">
                    {displayedSecrets.map((secret) => (
                        <SecretTableRow
                            key={secret.id}
                            secret={secret}
                            isSelected={list.selectedItems.has(secret.id)}
                            onToggleSelect={list.toggleSelectedItem}
                            onView={setViewingSecret}
                            onEdit={(s) => list.openModal('edit-secret', { secret: s })}
                            onDelete={(s) => list.openModal('delete-secret', { secret: s })}
                            onShare={(s) => list.openModal('share-secret', { secret: s })}
                            onRotate={handleRotate}
                            onAutoRotate={handleAutoRotate}
                            onCopy={reveal.handleCopySecretValue}
                            copyingId={reveal.copyingSecretId}
                            copiedId={reveal.copiedSecretId}
                            copyErrorId={reveal.copyErrorId}
                        />
                    ))}
                </tbody>
            </table>

            {list.pagination.totalPages > 1 && (
                <div className="px-4 py-3 border-t border-base  flex items-center justify-between">
                    <p className="text-sm text-base-secondary dark:text-base-muted">
                        Showing{' '}
                        <span className="font-medium">
                            {(list.pagination.page - 1) * list.pagination.pageSize + 1}
                        </span>{' '}
                        to{' '}
                        <span className="font-medium">
                            {Math.min(
                                list.pagination.page * list.pagination.pageSize,
                                list.pagination.total
                            )}
                        </span>{' '}
                        of <span className="font-medium">{list.pagination.total}</span> results
                    </p>
                    <div className="flex items-center space-x-2">
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => list.handlePageChange(list.pagination.page - 1)}
                            disabled={list.pagination.page === 1}
                        >
                            <ChevronLeftIcon className="h-4 w-4" />
                        </Button>
                        <span className="text-sm text-base-secondary dark:text-base-muted">
                            Page {list.pagination.page} of {list.pagination.totalPages}
                        </span>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => list.handlePageChange(list.pagination.page + 1)}
                            disabled={list.pagination.page === list.pagination.totalPages}
                        >
                            <ChevronRightIcon className="h-4 w-4" />
                        </Button>
                    </div>
                </div>
            )}
        </div>
    );

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold text-base-primary ">Secrets</h1>
                    <p className="mt-1 text-sm text-base-muted ">Manage your secrets and access controls</p>
                </div>
                <div className="flex items-center space-x-3">
                    {list.selectedItems.size > 0 && (
                        <div className="flex items-center space-x-2">
                            <span className="text-sm text-base-muted">{list.selectedItems.size} selected</span>
                            <Select
                                aria-label="Classify selected"
                                value=""
                                disabled={bulkClassify.isPending}
                                onChange={(e) => {
                                    const level = e.target.value;
                                    if (!level) return;
                                    const ids = Array.from(list.selectedItems);
                                    bulkClassify.mutate(
                                        { ids, classification: level === 'unclassified' ? '' : level },
                                        { onSuccess: () => list.clearSelectedItems() }
                                    );
                                }}
                                options={[
                                    { value: '', label: 'Classify as…' },
                                    { value: 'public', label: 'Public' },
                                    { value: 'internal', label: 'Internal' },
                                    { value: 'confidential', label: 'Confidential' },
                                    { value: 'restricted', label: 'Restricted' },
                                    { value: 'unclassified', label: 'Unclassified' },
                                ]}
                            />
                            <Button
                                variant="outline"
                                size="sm"
                                disabled
                                title="Share each secret individually — bulk sharing is not supported"
                            >
                                <ShareIcon className="h-4 w-4 mr-1" />
                                Share
                            </Button>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() =>
                                    list.openModal('bulk-delete-secrets', { secretIds: Array.from(list.selectedItems) })
                                }
                                disabled={list.selectedItems.size === 0}
                                className="text-red-600 hover:text-red-700"
                            >
                                <TrashIcon className="h-4 w-4 mr-1" />
                                Delete
                            </Button>
                            <Button variant="ghost" size="sm" onClick={() => list.clearSelectedItems()}>
                                Clear
                            </Button>
                        </div>
                    )}
                    <Button onClick={() => list.openModal('create-secret')} className="flex items-center">
                        <PlusIcon className="h-4 w-4 mr-2" />
                        New Secret
                    </Button>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-surface rounded-lg border border-base  p-4">
                <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
                        <div className="lg:col-span-2">
                            <Input
                                type="text"
                                placeholder="Search by name, type, or tags..."
                                value={list.searchInput}
                                onChange={(e) => list.setSearchInput(e.target.value)}
                                icon={MagnifyingGlassIcon}
                            />
                        </div>
                        <Select
                            value={list.filters.type}
                            onChange={(e) => list.handleFilterChange('type', e.target.value)}
                            options={SECRET_TYPES}
                        />
                        <Select
                            value={list.filters.classification || 'all'}
                            onChange={(e) =>
                                list.handleFilterChange(
                                    'classification',
                                    e.target.value === 'all' ? '' : e.target.value
                                )
                            }
                            options={[
                                { value: 'all', label: 'All Classifications' },
                                { value: 'unclassified', label: 'Unclassified' },
                                { value: 'public', label: 'Public' },
                                { value: 'internal', label: 'Internal' },
                                { value: 'confidential', label: 'Confidential' },
                                { value: 'restricted', label: 'Restricted' },
                            ]}
                        />
                        <Select
                            value={list.filters.environment || 'all'}
                            onChange={(e) =>
                                list.handleFilterChange('environment', e.target.value === 'all' ? '' : e.target.value)
                            }
                            options={[
                                { value: 'all', label: 'All Environments' },
                                ...list.environments.map((e) => ({
                                    value: e.name,
                                    label: e.name.charAt(0).toUpperCase() + e.name.slice(1),
                                })),
                            ]}
                        />
                        <Select
                            value={list.sortBy}
                            onChange={(e) => list.setSortBy(e.target.value)}
                            options={SORT_OPTIONS}
                            placeholder="Sort by"
                        />
                        <Select
                            value={String(list.pagination.pageSize)}
                            onChange={(e) => list.handlePageSizeChange(Number(e.target.value))}
                            options={PAGE_SIZE_OPTIONS}
                        />
                        <Button
                            variant="outline"
                            onClick={() => list.setShowAdvancedFilters(!list.showAdvancedFilters)}
                            className="w-full"
                        >
                            <FunnelIcon className="h-4 w-4 mr-2" />
                            {list.showAdvancedFilters ? 'Hide' : 'More'} Filters
                        </Button>
                    </div>
                    {list.showAdvancedFilters && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-4 border-t border-base ">
                            {/* Project filter — Phase 3: replace with project selector dropdown */}
                        </div>
                    )}
                    {/* Tag filter hidden — tags not yet implemented on secrets */}
                    {list.hasActiveFilters && (
                        <div className="flex items-center justify-end pt-4 border-t border-base ">
                            <Button variant="ghost" size="sm" onClick={list.handleClearFilters} className="text-xs">
                                Clear all
                            </Button>
                        </div>
                    )}
                    {list.isFetching && (
                        <div className="flex items-center justify-center py-2">
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                            <span className="ml-2 text-sm text-base-muted ">Updating results...</span>
                        </div>
                    )}
                </div>
            </div>

            {/* Expiring filter banner */}
            {urlFilter === 'expiring' && (
                <div
                    className="flex items-center justify-between px-4 py-2.5 rounded-lg border"
                    style={{
                        backgroundColor: 'rgba(217,119,6,0.06)',
                        borderColor: 'rgba(217,119,6,0.30)',
                        color: '#92400e',
                    }}
                >
                    <span className="text-sm font-medium" style={{ color: 'inherit' }}>
                        Showing secrets with expiration set
                    </span>
                    <button
                        type="button"
                        onClick={() => window.history.replaceState({}, '', window.location.pathname)}
                        className="text-sm font-medium underline underline-offset-2 hover:opacity-75 transition-opacity ml-4"
                        style={{ color: 'inherit' }}
                    >
                        ✕ Clear filter
                    </button>
                </div>
            )}

            {/* Table */}
            <div className="bg-surface rounded-lg border border-base ">
                {list.isLoading ? (
                    <div className="p-8">
                        <Loading />
                    </div>
                ) : tableBodyContent}
            </div>

            {/* Modals */}
            <Modal isOpen={viewingSecret !== null} onClose={() => setViewingSecret(null)} size="xl">
                {viewingSecret && (
                    <SecretDetailView
                        secret={viewingSecret}
                        onClose={() => setViewingSecret(null)}
                        onEdit={(s) => {
                            setViewingSecret(null);
                            list.openModal('edit-secret', { secret: s });
                        }}
                        onShare={(s) => {
                            setViewingSecret(null);
                            list.openModal('share-secret', { secret: s });
                        }}
                        onDelete={(s) => {
                            setViewingSecret(null);
                            list.openModal('delete-secret', { secret: s });
                        }}
                    />
                )}
            </Modal>

            <Modal
                isOpen={list.activeModal === 'edit-secret'}
                onClose={list.closeModal}
                title={`Edit Secret: ${list.modalData?.secret?.name ?? ''}`}
                size="md"
            >
                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        if (!list.modalData?.secret) return;
                        list.editMutation.mutate({
                            id: list.modalData.secret.id,
                            name: editName,
                            type: editType,
                            value: editValue,
                        });
                    }}
                    className="space-y-4"
                >
                    {list.editMutation.isError && (
                        <Alert
                            type="error"
                            title="Failed to update secret"
                            message={
                                list.editMutation.error instanceof Error
                                    ? list.editMutation.error.message
                                    : 'An unexpected error occurred'
                            }
                        />
                    )}
                    <div>
                        <label htmlFor="edit-secret-name" className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1">
                            Name
                        </label>
                        <input
                            id="edit-secret-name"
                            type="text"
                            required
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                            className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-surface  px-3 py-2 text-sm text-base-primary  focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                        />
                    </div>
                    <div>
                        <label htmlFor="edit-secret-type" className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1">
                            Type
                        </label>
                        <Select
                            id="edit-secret-type"
                            value={editType}
                            onChange={(e) => setEditType(e.target.value as SecretType)}
                            options={
                                SECRET_TYPES.filter((t) => t.value !== 'all') as { value: SecretType; label: string }[]
                            }
                        />
                    </div>
                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label htmlFor="edit-secret-value" className="block text-sm font-medium text-base-secondary">New Value</label>
                            <button
                                type="button"
                                onClick={() => setEditValue(generateSecret())}
                                className="text-xs font-medium transition-colors"
                                style={{ color: 'var(--accent-text)' }}
                            >
                                ↻ Generate
                            </button>
                        </div>
                        <input
                            id="edit-secret-value"
                            type="text"
                            value={editValue}
                            onChange={(e) => setEditValue(e.target.value)}
                            placeholder="Leave blank to keep existing value"
                            className="w-full rounded-md border px-3 py-2 text-sm font-mono focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border-strong)',
                            }}
                        />
                        <p className="mt-1 text-xs text-base-muted">Leave blank to keep the existing value.</p>
                    </div>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base ">
                        <Button
                            type="button"
                            variant="outline"
                            onClick={list.closeModal}
                            disabled={list.editMutation.isPending}
                        >
                            Cancel
                        </Button>
                        <Button type="submit" disabled={list.editMutation.isPending}>
                            {list.editMutation.isPending ? 'Saving…' : 'Save Changes'}
                        </Button>
                    </div>
                </form>
            </Modal>

            <Modal
                isOpen={list.activeModal === 'delete-secret'}
                onClose={list.closeModal}
                title="Delete Secret"
                size="sm"
            >
                <div className="space-y-4">
                    {list.deleteMutation.isError && (
                        <Alert
                            type="error"
                            title="Failed to delete secret"
                            message={
                                list.deleteMutation.error instanceof Error
                                    ? list.deleteMutation.error.message
                                    : 'An unexpected error occurred'
                            }
                        />
                    )}
                    <p className="text-sm text-base-secondary dark:text-base-muted">
                        Are you sure you want to delete{' '}
                        <span className="font-semibold">{list.modalData?.secret?.name}</span>? The secret will be
                        soft-deleted and can be restored within 30 days.
                    </p>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base ">
                        <Button variant="outline" onClick={list.closeModal} disabled={list.deleteMutation.isPending}>
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={() =>
                                list.modalData?.secret && list.deleteMutation.mutate(list.modalData.secret.id)
                            }
                            disabled={list.deleteMutation.isPending}
                        >
                            {list.deleteMutation.isPending ? 'Deleting…' : 'Delete'}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Modal
                isOpen={list.activeModal === 'create-secret'}
                onClose={() => {
                    list.closeModal();
                    setCreateName('');
                    setCreateValue('');
                    setCreateType('text');
                    setCreateError('');
                }}
                title="Create New Secret"
                size="md"
            >
                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        setCreateError('');
                        if (!createProjectId || !createEnvId) {
                            setCreateError('Select a project and environment for the new secret.');
                            return;
                        }
                        const nameErr = secretNameError(namePolicy, createName);
                        if (nameErr) {
                            setCreateError(nameErr);
                            return;
                        }
                        list.createMutation.mutate(
                            {
                                name: createName,
                                value: createValue,
                                type: createType,
                                project_id: createProjectId,
                                environment_id: createEnvId,
                            } as any,
                            {
                                onSuccess: () => {
                                    setCreateName('');
                                    setCreateValue('');
                                    setCreateType('text');
                                    setCreateError('');
                                },
                                onError: (err) => setCreateError(apiErrorMessage(err)),
                            }
                        );
                    }}
                    className="space-y-4"
                >
                    {createError && <Alert type="error" title="Failed to create secret" message={createError} />}
                    <div>
                        <label htmlFor="create-secret-name" className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1">
                            Name <span className="text-red-500">*</span>
                        </label>
                        <input
                            id="create-secret-name"
                            type="text"
                            required
                            value={createName}
                            onChange={(e) => setCreateName(e.target.value)}
                            className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-surface  px-3 py-2 text-sm text-base-primary  focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                        />
                        {nameHint && <p className="mt-1 text-xs text-base-muted">Naming policy: {nameHint}.</p>}
                        {namePatternUnsafe && (
                            <p className="mt-1 text-xs text-amber-600">
                                This naming pattern can&apos;t be safely checked in your browser and won&apos;t be
                                validated here; the server will still enforce it when you submit.
                            </p>
                        )}
                    </div>
                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label htmlFor="create-secret-value" className="block text-sm font-medium text-base-secondary">
                                Value <span className="text-red-500">*</span>
                            </label>
                            <button
                                type="button"
                                onClick={() => setCreateValue(generateSecret())}
                                className="text-xs font-medium transition-colors"
                                style={{ color: 'var(--accent-text)' }}
                            >
                                ↻ Generate
                            </button>
                        </div>
                        <textarea
                            id="create-secret-value"
                            required
                            rows={3}
                            value={createValue}
                            onChange={(e) => setCreateValue(e.target.value)}
                            className="w-full rounded-md border px-3 py-2 text-sm font-mono focus:outline-hidden focus:ring-2 focus:ring-blue-500 resize-none"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border-strong)',
                            }}
                        />
                    </div>
                    <div>
                        <label htmlFor="create-secret-type" className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1">
                            Type
                        </label>
                        <Select
                            id="create-secret-type"
                            value={createType}
                            onChange={(e) => setCreateType(e.target.value as SecretType)}
                            options={[
                                { value: 'text', label: 'Generic' },
                                { value: 'password', label: 'Password' },
                                { value: 'api_key', label: 'API Key' },
                                { value: 'certificate', label: 'Certificate' },
                                { value: 'json', label: 'JSON' },
                            ]}
                        />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label htmlFor="create-secret-project" className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1">
                                Project <span className="text-red-500">*</span>
                            </label>
                            <Select
                                id="create-secret-project"
                                value={String(createProjectId)}
                                onChange={(e) => setCreateProjectId(Number(e.target.value))}
                                options={(createProjects ?? []).map((p) => ({ value: String(p.id), label: p.name }))}
                            />
                        </div>
                        <div>
                            <label htmlFor="create-secret-environment" className="block text-sm font-medium text-base-secondary dark:text-base-muted mb-1">
                                Environment <span className="text-red-500">*</span>
                            </label>
                            <Select
                                id="create-secret-environment"
                                value={String(createEnvId)}
                                onChange={(e) => setCreateEnvId(Number(e.target.value))}
                                options={(createEnvironments ?? []).map((env) => ({
                                    value: String(env.id),
                                    label: env.name,
                                }))}
                            />
                        </div>
                    </div>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base ">
                        <Button
                            type="button"
                            variant="outline"
                            onClick={() => {
                                list.closeModal();
                                setCreateName('');
                                setCreateValue('');
                                setCreateType('text');
                                setCreateError('');
                            }}
                            disabled={list.createMutation.isPending}
                        >
                            Cancel
                        </Button>
                        <Button type="submit" disabled={list.createMutation.isPending}>
                            {list.createMutation.isPending ? 'Creating…' : 'Create Secret'}
                        </Button>
                    </div>
                </form>
            </Modal>

            {list.activeModal === 'share-secret' && list.modalData?.secret && (
                <ShareSecretModal
                    secret={list.modalData.secret}
                    isOpen
                    onClose={list.closeModal}
                    onSuccess={() => {
                        list.closeModal();
                        list.refetch();
                    }}
                />
            )}

            <Modal
                isOpen={list.activeModal === 'rotate-secret'}
                onClose={list.closeModal}
                title={`Rotate Secret: ${list.modalData?.secret?.name ?? ''}`}
                size="sm"
            >
                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        if (!list.modalData?.secret) return;
                        list.rotateMutation.mutate({ id: list.modalData.secret.id, newValue: rotateValue });
                    }}
                    className="space-y-4"
                >
                    {list.rotateMutation.isError && (
                        <Alert
                            type="error"
                            title="Failed to rotate secret"
                            message={apiErrorMessage(list.rotateMutation.error)}
                        />
                    )}
                    <p className="text-sm text-base-muted">
                        A new random value has been generated. Edit it or regenerate, then click Rotate to create a new
                        version.
                    </p>
                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label htmlFor="rotate-secret-value" className="block text-sm font-medium text-base-secondary">New Value</label>
                            <button
                                type="button"
                                onClick={() => setRotateValue(generateSecret())}
                                className="text-xs font-medium transition-colors"
                                style={{ color: 'var(--accent-text)' }}
                            >
                                ↻ Regenerate
                            </button>
                        </div>
                        <input
                            id="rotate-secret-value"
                            type="text"
                            value={rotateValue}
                            onChange={(e) => setRotateValue(e.target.value)}
                            className="w-full rounded-md border px-3 py-2 text-sm font-mono focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: 'var(--border-strong)',
                            }}
                        />
                    </div>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base">
                        <Button
                            type="button"
                            variant="outline"
                            onClick={list.closeModal}
                            disabled={list.rotateMutation.isPending}
                        >
                            Cancel
                        </Button>
                        <Button type="submit" disabled={list.rotateMutation.isPending || !rotateValue.trim()}>
                            {list.rotateMutation.isPending ? 'Rotating…' : 'Rotate'}
                        </Button>
                    </div>
                </form>
            </Modal>

            <Modal
                isOpen={list.activeModal === 'auto-rotate'}
                onClose={list.closeModal}
                title={`Automated Rotation: ${list.modalData?.secret?.name ?? ''}`}
                size="md"
            >
                <form onSubmit={submitAutoRotate} className="space-y-4">
                    {autoRotate.isError && (
                        <Alert
                            type="error"
                            title="Failed to update auto-rotation"
                            message={
                                autoRotate.error instanceof Error
                                    ? autoRotate.error.message
                                    : 'An unexpected error occurred'
                            }
                        />
                    )}
                    <p className="text-sm text-base-muted">
                        When enabled, Keyorix regenerates this secret on its rotation-policy schedule. Enable only for
                        values Keyorix owns — or set a backend to rotate the upstream credential in place.
                    </p>
                    <label className="flex items-center gap-2 text-sm text-base-secondary">
                        <input
                            type="checkbox"
                            checked={arEnabled}
                            onChange={(e) => setArEnabled(e.target.checked)}
                            aria-label="Enable auto-rotation"
                        />{' '}
                        Enable automated rotation
                    </label>
                    <div className="grid grid-cols-2 gap-3">
                        <Input
                            label="Value length"
                            type="number"
                            placeholder="default 32"
                            value={arLength}
                            onChange={(e) => setArLength(e.target.value)}
                        />
                        <div>
                            <label htmlFor="auto-rotate-charset" className="block text-sm font-medium text-base-secondary mb-1">Charset</label>
                            <Select
                                id="auto-rotate-charset"
                                value={arCharset}
                                onChange={(e) => setArCharset(e.target.value)}
                                options={[
                                    { value: '', label: 'Alphanumeric (default)' },
                                    { value: 'lower_alphanumeric', label: 'Lowercase + digits' },
                                    { value: 'hex', label: 'Hex' },
                                    { value: 'alphanumeric_symbols', label: 'Alphanumeric + symbols' },
                                ]}
                            />
                        </div>
                    </div>
                    <div className="pt-2 border-t border-base">
                        <p className="text-xs text-base-muted mb-2">
                            Optional — rotate an upstream credential (e.g. a DB role or cloud key) via a configured
                            backend.
                        </p>
                        <div className="grid grid-cols-2 gap-3">
                            <Input
                                label="Backend"
                                placeholder="e.g. prod-postgres"
                                value={arBackend}
                                onChange={(e) => setArBackend(e.target.value)}
                            />
                            <Input
                                label="Upstream ref"
                                placeholder="e.g. app_svc"
                                value={arRef}
                                onChange={(e) => setArRef(e.target.value)}
                            />
                        </div>
                        {(arBackend === '') !== (arRef === '') && (
                            <p className="text-xs text-red-600 mt-1">Backend and ref must be set together.</p>
                        )}
                    </div>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base">
                        <Button
                            type="button"
                            variant="outline"
                            onClick={list.closeModal}
                            disabled={autoRotate.isPending}
                        >
                            Cancel
                        </Button>
                        <Button type="submit" disabled={autoRotate.isPending || (arBackend === '') !== (arRef === '')}>
                            {autoRotate.isPending ? 'Saving…' : 'Save'}
                        </Button>
                    </div>
                </form>
            </Modal>

            <Modal
                isOpen={list.activeModal === 'bulk-delete-secrets'}
                onClose={list.closeModal}
                title="Delete Selected Secrets"
                size="sm"
            >
                <div className="space-y-4">
                    <p className="text-sm text-base-secondary dark:text-base-muted">
                        Are you sure you want to delete{' '}
                        <span className="font-semibold">{list.modalData?.secretIds?.length}</span> secret(s)? They will
                        be soft-deleted and can be restored within 30 days.
                    </p>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-base ">
                        <Button
                            variant="outline"
                            onClick={list.closeModal}
                            disabled={list.bulkDeleteMutation.isPending}
                        >
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={() =>
                                list.modalData?.secretIds && list.bulkDeleteMutation.mutate(list.modalData.secretIds)
                            }
                            disabled={list.bulkDeleteMutation.isPending}
                        >
                            {list.bulkDeleteMutation.isPending
                                ? 'Deleting…'
                                : `Delete ${list.modalData?.secretIds?.length ?? ''} Secret(s)`}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
