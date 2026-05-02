import React from 'react';
import {
    MagnifyingGlassIcon, PlusIcon, FunnelIcon,
    ChevronLeftIcon, ChevronRightIcon, TagIcon, XMarkIcon, ShareIcon, TrashIcon,
} from '@heroicons/react/24/outline';
import { SecretType, SecretFormData } from '../../types';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Select } from '../../components/ui/Select';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { SecretDetailView } from '../../components/secrets/SecretDetailView';
import { ShareSecretModal } from '../../components/sharing/ShareSecretModal';
import { useSecretsList } from '../../features/secrets/useSecretsList';
import { useSecretReveal } from '../../features/secrets/useSecretReveal';
import { SecretTableRow } from '../../features/secrets/SecretTableRow';

const SECRET_TYPES: { value: SecretType | 'all'; label: string }[] = [
    { value: 'all', label: 'All Types' }, { value: 'text', label: 'Text' },
    { value: 'password', label: 'Password' }, { value: 'api_key', label: 'API Key' },
    { value: 'certificate', label: 'Certificate' }, { value: 'json', label: 'JSON' },
];
const SORT_OPTIONS = [
    { value: 'name_asc', label: 'Name (A-Z)' }, { value: 'name_desc', label: 'Name (Z-A)' },
    { value: 'modified_desc', label: 'Recently Modified' }, { value: 'modified_asc', label: 'Oldest Modified' },
    { value: 'type_asc', label: 'Type (A-Z)' }, { value: 'type_desc', label: 'Type (Z-A)' },
    { value: 'created_desc', label: 'Recently Created' }, { value: 'created_asc', label: 'Oldest Created' },
];
const PAGE_SIZE_OPTIONS = [
    { value: '10', label: '10 per page' }, { value: '20', label: '20 per page' },
    { value: '50', label: '50 per page' }, { value: '100', label: '100 per page' },
];

export const SecretsListPage: React.FC = () => {
    const list = useSecretsList();
    const reveal = useSecretReveal();
    const [viewingSecret, setViewingSecret] = React.useState<any>(null);
    const [createName, setCreateName] = React.useState('');
    const [createValue, setCreateValue] = React.useState('');
    const [createType, setCreateType] = React.useState<SecretType>('text');
    const [createError, setCreateError] = React.useState('');
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
            setRotateValue('');
        }
    }, [list.activeModal, list.modalData]);

    const handleRotate = (secret: any) => {
        list.openModal('rotate-secret', { secret });
    };

    if (list.error) {
        return (
            <div className="p-6">
                <Alert type="error" title="Failed to load secrets" message="There was an error loading your secrets. Please try again."
                    action={<Button variant="outline" size="sm" onClick={() => list.refetch()}>Retry</Button>} />
            </div>
        );
    }

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Secrets</h1>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Manage your secrets and access controls</p>
                </div>
                <div className="flex items-center space-x-3">
                    {list.bulkActionMode && (
                        <div className="flex items-center space-x-2">
                            <span className="text-sm text-gray-500 dark:text-gray-400">{list.selectedItems.size} selected</span>
                            <Button variant="outline" size="sm" disabled title="Share each secret individually — bulk sharing is not supported">
                                <ShareIcon className="h-4 w-4 mr-1" />Share
                            </Button>
                            <Button variant="outline" size="sm" onClick={() => list.openModal('bulk-delete-secrets', { secretIds: Array.from(list.selectedItems) })} disabled={list.selectedItems.size === 0} className="text-red-600 hover:text-red-700">
                                <TrashIcon className="h-4 w-4 mr-1" />Delete
                            </Button>
                            <Button variant="outline" size="sm" onClick={() => { list.setBulkActionMode(false); list.clearSelectedItems(); }}>Cancel</Button>
                        </div>
                    )}
                    <Button variant="outline" size="sm" onClick={() => list.setBulkActionMode(!list.bulkActionMode)}>Select</Button>
                    <Button onClick={() => list.openModal('create-secret')} className="flex items-center">
                        <PlusIcon className="h-4 w-4 mr-2" />New Secret
                    </Button>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
                        <div className="lg:col-span-2">
                            <Input type="text" placeholder="Search by name, type, or tags..." value={list.searchInput}
                                onChange={(e) => list.setSearchInput(e.target.value)} icon={MagnifyingGlassIcon} />
                        </div>
                        <Select value={list.filters.type} onChange={(e) => list.handleFilterChange('type', e.target.value)} options={SECRET_TYPES} placeholder="All Types" />
                        <Select
                            value={list.filters.environment || 'all'}
                            onChange={(e) => list.handleFilterChange('environment', e.target.value === 'all' ? '' : e.target.value)}
                            options={[{ value: 'all', label: 'All Environments' }, ...list.environments.map(e => ({ value: e.name, label: e.name.charAt(0).toUpperCase() + e.name.slice(1) }))]}
                        />
                        <Select value={list.sortBy} onChange={(e) => list.setSortBy(e.target.value)} options={SORT_OPTIONS} placeholder="Sort by" />
                        <Select value={String(list.pagination.pageSize)} onChange={(e) => list.handlePageSizeChange(Number(e.target.value))} options={PAGE_SIZE_OPTIONS} placeholder="Page size" />
                        <Button variant="outline" onClick={() => list.setShowAdvancedFilters(!list.showAdvancedFilters)} className="w-full">
                            <FunnelIcon className="h-4 w-4 mr-2" />{list.showAdvancedFilters ? 'Hide' : 'More'} Filters
                        </Button>
                    </div>
                    {list.showAdvancedFilters && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                            <Input type="text" placeholder="Namespace" value={list.filters.namespace} onChange={(e) => list.handleFilterChange('namespace', e.target.value)} />
                            <Input type="text" placeholder="Zone" value={list.filters.zone} onChange={(e) => list.handleFilterChange('zone', e.target.value)} />
                        </div>
                    )}
                    <div className="space-y-2">
                        <div className="flex items-center space-x-2">
                            <TagIcon className="h-4 w-4 text-gray-500" />
                            <Input type="text" placeholder="Add tag filter (press Enter)" value={list.tagInput}
                                onChange={(e) => list.setTagInput(e.target.value)} onKeyPress={list.handleTagInputKeyPress} className="flex-1" />
                        </div>
                        {list.filters.tags.length > 0 && (
                            <div className="flex flex-wrap gap-2">
                                {list.filters.tags.map(tag => (
                                    <span key={tag} className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                        {tag}
                                        <button onClick={() => list.handleRemoveTag(tag)} className="ml-1 hover:text-blue-600">
                                            <XMarkIcon className="h-3 w-3" />
                                        </button>
                                    </span>
                                ))}
                            </div>
                        )}
                    </div>
                    {list.hasActiveFilters && (
                        <div className="flex items-center justify-end pt-4 border-t border-gray-200 dark:border-gray-700">
                            <Button variant="ghost" size="sm" onClick={list.handleClearFilters} className="text-xs">Clear all</Button>
                        </div>
                    )}
                    {list.isFetching && (
                        <div className="flex items-center justify-center py-2">
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                            <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">Updating results...</span>
                        </div>
                    )}
                </div>
            </div>

            {/* Table */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                {list.isLoading ? (
                    <div className="p-8"><Loading /></div>
                ) : list.secrets.length === 0 ? (
                    <div className="p-8 text-center">
                        <FunnelIcon className="h-12 w-12 mx-auto text-gray-400 dark:text-gray-500 mb-4" />
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No secrets found</h3>
                        <p className="text-gray-500 dark:text-gray-400 mb-4">
                            {list.hasActiveFilters ? 'Try adjusting your filters or search terms.' : 'Get started by creating your first secret.'}
                        </p>
                        {!list.hasActiveFilters && (
                            <Button onClick={() => list.openModal('create-secret')}>
                                <PlusIcon className="h-4 w-4 mr-2" />Create Secret
                            </Button>
                        )}
                    </div>
                ) : (
                    <div className="overflow-hidden">
                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-900">
                                <tr>
                                    {list.bulkActionMode && (
                                        <th className="px-6 py-3 text-left">
                                            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                                checked={list.secrets.length > 0 && list.secrets.every(s => list.selectedItems.has(s.id))}
                                                onChange={(e) => { if (e.target.checked) list.secrets.forEach(s => list.toggleSelectedItem(s.id)); else list.clearSelectedItems(); }} />
                                        </th>
                                    )}
                                    {['Name', 'Type', 'Environment', 'Sharing', 'Modified'].map(h => (
                                        <th key={h} className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">{h}</th>
                                    ))}
                                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                {list.secrets.map(secret => (
                                    <SecretTableRow key={secret.id} secret={secret}
                                        bulkActionMode={list.bulkActionMode}
                                        isSelected={list.selectedItems.has(secret.id)}
                                        onToggleSelect={list.toggleSelectedItem}
                                        onView={setViewingSecret}
                                        onEdit={s => list.openModal('edit-secret', { secret: s })}
                                        onDelete={s => list.openModal('delete-secret', { secret: s })}
                                        onShare={s => list.openModal('share-secret', { secret: s })}
                                        onRotate={handleRotate}
                                        onCopy={reveal.handleCopySecretValue}
                                        copyingId={reveal.copyingSecretId}
                                        copiedId={reveal.copiedSecretId}
                                        copyErrorId={reveal.copyErrorId}
                                    />
                                ))}
                            </tbody>
                        </table>

                        {list.pagination.totalPages > 1 && (
                            <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
                                <p className="text-sm text-gray-700 dark:text-gray-300">
                                    Showing <span className="font-medium">{(list.pagination.page - 1) * list.pagination.pageSize + 1}</span> to{' '}
                                    <span className="font-medium">{Math.min(list.pagination.page * list.pagination.pageSize, list.pagination.total)}</span> of{' '}
                                    <span className="font-medium">{list.pagination.total}</span> results
                                </p>
                                <div className="flex items-center space-x-2">
                                    <Button variant="outline" size="sm" onClick={() => list.handlePageChange(list.pagination.page - 1)} disabled={list.pagination.page === 1}>
                                        <ChevronLeftIcon className="h-4 w-4" />
                                    </Button>
                                    <span className="text-sm text-gray-700 dark:text-gray-300">Page {list.pagination.page} of {list.pagination.totalPages}</span>
                                    <Button variant="outline" size="sm" onClick={() => list.handlePageChange(list.pagination.page + 1)} disabled={list.pagination.page === list.pagination.totalPages}>
                                        <ChevronRightIcon className="h-4 w-4" />
                                    </Button>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* Modals */}
            <Modal isOpen={viewingSecret !== null} onClose={() => setViewingSecret(null)} size="xl">
                {viewingSecret && (
                    <SecretDetailView secret={viewingSecret} onClose={() => setViewingSecret(null)}
                        onEdit={s => { setViewingSecret(null); list.openModal('edit-secret', { secret: s }); }}
                        onShare={s => { setViewingSecret(null); list.openModal('share-secret', { secret: s }); }}
                        onDelete={s => { setViewingSecret(null); list.openModal('delete-secret', { secret: s }); }} />
                )}
            </Modal>

            <Modal isOpen={list.activeModal === 'edit-secret'} onClose={list.closeModal} title={`Edit Secret: ${list.modalData?.secret?.name ?? ''}`} size="md">
                <form onSubmit={(e) => { e.preventDefault(); if (!list.modalData?.secret) return; list.editMutation.mutate({ id: list.modalData.secret.id, name: editName, type: editType, value: editValue }); }} className="space-y-4">
                    {list.editMutation.error && <Alert type="error" title="Failed to update secret" message={list.editMutation.error instanceof Error ? list.editMutation.error.message : 'An unexpected error occurred'} />}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                        <input type="text" required value={editName} onChange={(e) => setEditName(e.target.value)} className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type</label>
                        <Select value={editType} onChange={(e) => setEditType(e.target.value as SecretType)} options={SECRET_TYPES.filter(t => t.value !== 'all') as { value: SecretType; label: string }[]} />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">New Value</label>
                        <input type="password" value={editValue} onChange={(e) => setEditValue(e.target.value)} placeholder="Leave blank to keep existing value" className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Leave blank to keep the existing value.</p>
                    </div>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <Button type="button" variant="outline" onClick={list.closeModal} disabled={list.editMutation.isLoading}>Cancel</Button>
                        <Button type="submit" disabled={list.editMutation.isLoading}>{list.editMutation.isLoading ? 'Saving…' : 'Save Changes'}</Button>
                    </div>
                </form>
            </Modal>

            <Modal isOpen={list.activeModal === 'delete-secret'} onClose={list.closeModal} title="Delete Secret" size="sm">
                <div className="space-y-4">
                    {list.deleteMutation.error && <Alert type="error" title="Failed to delete secret" message={list.deleteMutation.error instanceof Error ? list.deleteMutation.error.message : 'An unexpected error occurred'} />}
                    <p className="text-sm text-gray-700 dark:text-gray-300">
                        Are you sure you want to delete <span className="font-semibold">{list.modalData?.secret?.name}</span>? The secret will be soft-deleted and can be restored within 30 days.
                    </p>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <Button variant="outline" onClick={list.closeModal} disabled={list.deleteMutation.isLoading}>Cancel</Button>
                        <Button variant="danger" onClick={() => list.modalData?.secret && list.deleteMutation.mutate(list.modalData.secret.id)} disabled={list.deleteMutation.isLoading}>
                            {list.deleteMutation.isLoading ? 'Deleting…' : 'Delete'}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Modal isOpen={list.activeModal === 'create-secret'} onClose={() => { list.closeModal(); setCreateName(''); setCreateValue(''); setCreateType('text'); setCreateError(''); }} title="Create New Secret" size="md">
                <form onSubmit={(e) => { e.preventDefault(); setCreateError(''); list.createMutation.mutate({ name: createName, value: createValue, type: createType, namespace_id: 1, zone_id: 1, environment_id: 1 } as any); }} className="space-y-4">
                    {createError && <Alert type="error" title="Failed to create secret" message={createError} />}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name <span className="text-red-500">*</span></label>
                        <input type="text" required value={createName} onChange={(e) => setCreateName(e.target.value)} className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Value <span className="text-red-500">*</span></label>
                        <textarea required rows={4} value={createValue} onChange={(e) => setCreateValue(e.target.value)} className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type</label>
                        <Select value={createType} onChange={(e) => setCreateType(e.target.value as SecretType)} options={[{ value: 'text', label: 'Generic' }, { value: 'password', label: 'Password' }, { value: 'api_key', label: 'API Key' }, { value: 'certificate', label: 'Certificate' }, { value: 'json', label: 'JSON' }]} />
                    </div>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <Button type="button" variant="outline" onClick={() => { list.closeModal(); setCreateName(''); setCreateValue(''); setCreateType('text'); setCreateError(''); }} disabled={list.createMutation.isLoading}>Cancel</Button>
                        <Button type="submit" disabled={list.createMutation.isLoading}>{list.createMutation.isLoading ? 'Creating…' : 'Create Secret'}</Button>
                    </div>
                </form>
            </Modal>

            {list.activeModal === 'share-secret' && list.modalData?.secret && (
                <ShareSecretModal secret={list.modalData.secret} isOpen onClose={list.closeModal} onSuccess={() => { list.closeModal(); list.refetch(); }} />
            )}

            <Modal isOpen={list.activeModal === 'rotate-secret'} onClose={list.closeModal} title={`Rotate Secret: ${list.modalData?.secret?.name ?? ''}`} size="sm">
                <form onSubmit={(e) => { e.preventDefault(); if (!list.modalData?.secret) return; list.rotateMutation.mutate({ id: list.modalData.secret.id, newValue: rotateValue }); }} className="space-y-4">
                    {list.rotateMutation.error && <Alert type="error" title="Failed to rotate secret" message={list.rotateMutation.error instanceof Error ? list.rotateMutation.error.message : 'An unexpected error occurred'} />}
                    <p className="text-sm text-gray-500 dark:text-gray-400">Enter a new value to replace the current secret value. A new version will be created.</p>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">New Value <span className="text-red-500">*</span></label>
                        <input type="password" required value={rotateValue} onChange={(e) => setRotateValue(e.target.value)} className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <Button type="button" variant="outline" onClick={list.closeModal} disabled={list.rotateMutation.isLoading}>Cancel</Button>
                        <Button type="submit" disabled={list.rotateMutation.isLoading || !rotateValue.trim()}>{list.rotateMutation.isLoading ? 'Rotating…' : 'Rotate'}</Button>
                    </div>
                </form>
            </Modal>

            <Modal isOpen={list.activeModal === 'bulk-delete-secrets'} onClose={list.closeModal} title="Delete Selected Secrets" size="sm">
                <div className="space-y-4">
                    <p className="text-sm text-gray-700 dark:text-gray-300">
                        Are you sure you want to delete <span className="font-semibold">{list.modalData?.secretIds?.length}</span> secret(s)? They will be soft-deleted and can be restored within 30 days.
                    </p>
                    <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <Button variant="outline" onClick={list.closeModal} disabled={list.bulkDeleteMutation.isLoading}>Cancel</Button>
                        <Button variant="danger" onClick={() => list.modalData?.secretIds && list.bulkDeleteMutation.mutate(list.modalData.secretIds)} disabled={list.bulkDeleteMutation.isLoading}>
                            {list.bulkDeleteMutation.isLoading ? 'Deleting…' : `Delete ${list.modalData?.secretIds?.length ?? ''} Secret(s)`}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
