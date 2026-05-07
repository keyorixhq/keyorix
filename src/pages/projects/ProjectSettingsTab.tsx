import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient, useMutation } from '@tanstack/react-query';
import { TrashIcon, PlusIcon } from '@heroicons/react/24/outline';
import { useProject, useProjectEnvironments, PROJECT_KEYS } from '../../features/projects/api';
import { apiClient } from '../../services/client';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { ROUTES } from '../../constants';

interface ProjectSettingsTabProps {
    projectId: number;
}

/**
 * Phase 3F — Settings tab.
 * Covers: project name/description editing, environment management (add/delete), project deletion.
 */
export const ProjectSettingsTab: React.FC<ProjectSettingsTabProps> = ({ projectId }) => {
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { data: project, isLoading: projectLoading } = useProject(projectId);
    const { data: environments = [], isLoading: envsLoading } = useProjectEnvironments(projectId);

    // ── Project name/description ──────────────────────────────────────────
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [nameError, setNameError] = useState('');

    // Sync form once project loads
    React.useEffect(() => {
        if (project) { setName(project.name); setDescription(project.description ?? ''); }
    }, [project]);

    const updateMutation = useMutation({
        mutationFn: (body: { name: string; description?: string }) =>
            apiClient.put(`/api/v1/projects/${projectId}`, body),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.detail(projectId) });
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.list() });
        },
    });

    const handleSave = () => {
        if (!name.trim()) { setNameError('Name is required.'); return; }
        setNameError('');
        updateMutation.mutate({
            name: name.trim(),
            ...(description.trim() ? { description: description.trim() } : {}),
        });
    };

    // ── Environment management ────────────────────────────────────────────
    const [newEnvName, setNewEnvName] = useState('');
    const [addEnvError, setAddEnvError] = useState('');

    const addEnvMutation = useMutation({
        mutationFn: (envName: string) =>
            apiClient.post(`/api/v1/projects/${projectId}/environments`, { name: envName }),
        onSuccess: () => {
            setNewEnvName('');
            setAddEnvError('');
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.environments(projectId) });
        },
        onError: (err: any) => {
            setAddEnvError(err?.response?.data?.error ?? 'Failed to create environment.');
        },
    });

    const deleteEnvMutation = useMutation({
        mutationFn: (envId: number) => apiClient.delete(`/api/v1/environments/${envId}`),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.environments(projectId) }),
    });

    // ── Project deletion ──────────────────────────────────────────────────
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [deleteConfirm, setDeleteConfirm] = useState('');

    const deleteProjectMutation = useMutation({
        mutationFn: () => apiClient.delete(`/api/v1/projects/${projectId}`),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.list() });
            navigate(ROUTES.PROJECTS);
        },
    });

    if (projectLoading) {
        return (
            <div className="space-y-3 animate-pulse">
                {[1, 2].map(i => <div key={i} className="h-12 rounded-lg" style={{ backgroundColor: 'var(--bg-muted)' }} />)}
            </div>
        );
    }

    return (
        <div className="space-y-8 max-w-2xl">

            {/* ── General ── */}
            <section>
                <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>General</h2>
                <div className="rounded-lg border p-5 space-y-4"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    {updateMutation.isError && (
                        <Alert type="error" title="Failed to update" message="Could not save project settings." />
                    )}
                    {updateMutation.isSuccess && (
                        <Alert type="success" title="Saved" message="Project settings updated." />
                    )}
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            Project name <span style={{ color: 'var(--error)' }}>*</span>
                        </label>
                        <input type="text" value={name} onChange={e => setName(e.target.value)}
                            className="w-full rounded-lg border px-3 py-2 text-sm outline-none"
                            style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: nameError ? 'var(--error)' : 'var(--border)' }} />
                        {nameError && <p className="text-xs mt-1" style={{ color: 'var(--error)' }}>{nameError}</p>}
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Description</label>
                        <input type="text" value={description} onChange={e => setDescription(e.target.value)}
                            placeholder="Optional"
                            className="w-full rounded-lg border px-3 py-2 text-sm outline-none"
                            style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }} />
                    </div>
                    <div className="flex justify-end">
                        <Button onClick={handleSave} disabled={updateMutation.isPending}>
                            {updateMutation.isPending ? 'Saving…' : 'Save'}
                        </Button>
                    </div>
                </div>
            </section>

            {/* ── Environments ── */}
            <section>
                <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Environments</h2>
                <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                    Manage environments for this project. The three default environments cannot be deleted.
                </p>
                <div className="rounded-lg border"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    {envsLoading ? (
                        <div className="p-4 animate-pulse space-y-2">
                            {[1, 2, 3].map(i => <div key={i} className="h-8 rounded" style={{ backgroundColor: 'var(--bg-muted)' }} />)}
                        </div>
                    ) : (
                        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                            {environments.map(env => {
                                const isDefault = ['development', 'staging', 'production'].includes(env.name.toLowerCase());
                                return (
                                    <li key={env.id} className="flex items-center justify-between px-4 py-3">
                                        <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
                                            {env.name.charAt(0).toUpperCase() + env.name.slice(1)}
                                        </span>
                                        {isDefault ? (
                                            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>default</span>
                                        ) : (
                                            <button
                                                type="button"
                                                onClick={() => deleteEnvMutation.mutate(env.id)}
                                                disabled={deleteEnvMutation.isPending}
                                                className="p-1 rounded"
                                                style={{ color: 'var(--error)' }}
                                                title="Delete environment"
                                            >
                                                <TrashIcon className="h-4 w-4" />
                                            </button>
                                        )}
                                    </li>
                                );
                            })}
                        </ul>
                    )}

                    {/* Add environment */}
                    <div className="border-t px-4 py-3" style={{ borderColor: 'var(--border)' }}>
                        {addEnvError && <p className="text-xs mb-2" style={{ color: 'var(--error)' }}>{addEnvError}</p>}
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={newEnvName}
                                onChange={e => setNewEnvName(e.target.value)}
                                onKeyDown={e => { if (e.key === 'Enter' && newEnvName.trim()) addEnvMutation.mutate(newEnvName.trim()); }}
                                placeholder="New environment name…"
                                className="flex-1 rounded-lg border px-3 py-1.5 text-sm outline-none"
                                style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }}
                            />
                            <Button size="sm" onClick={() => newEnvName.trim() && addEnvMutation.mutate(newEnvName.trim())}
                                disabled={!newEnvName.trim() || addEnvMutation.isPending}>
                                <PlusIcon className="h-4 w-4 mr-1" />Add
                            </Button>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── Danger zone ── */}
            <section>
                <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--error)' }}>Danger Zone</h2>
                <div className="rounded-lg border p-5 flex items-center justify-between"
                    style={{ borderColor: 'var(--error)', backgroundColor: 'var(--error-subtle)' }}>
                    <div>
                        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Delete this project</p>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            Permanently deletes the project and all its secrets. This cannot be undone.
                        </p>
                    </div>
                    <Button variant="danger" onClick={() => setShowDeleteModal(true)}>Delete Project</Button>
                </div>
            </section>

            {/* Delete confirmation modal */}
            <Modal isOpen={showDeleteModal} onClose={() => { setShowDeleteModal(false); setDeleteConfirm(''); }}
                title="Delete Project" size="sm">
                <div className="space-y-4">
                    {deleteProjectMutation.isError && (
                        <Alert type="error" title="Failed to delete" message="Could not delete the project." />
                    )}
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        This will permanently delete <span className="font-semibold">{project?.name}</span> and all its secrets. Type the project name to confirm.
                    </p>
                    <input type="text" value={deleteConfirm} onChange={e => setDeleteConfirm(e.target.value)}
                        placeholder={project?.name}
                        className="w-full rounded-lg border px-3 py-2 text-sm outline-none"
                        style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }} />
                    <div className="flex justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button variant="outline" onClick={() => { setShowDeleteModal(false); setDeleteConfirm(''); }}>Cancel</Button>
                        <Button variant="danger"
                            disabled={deleteConfirm !== project?.name || deleteProjectMutation.isPending}
                            onClick={() => deleteProjectMutation.mutate()}>
                            {deleteProjectMutation.isPending ? 'Deleting…' : 'Delete'}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
