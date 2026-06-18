import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient, useMutation } from '@tanstack/react-query';
import { TrashIcon, PlusIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { useProject, useProjectEnvironments, useRestoreEnvironment, PROJECT_KEYS } from '../../features/projects/api';
import { apiClient } from '../../services/client';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { ROUTES } from '../../constants';

interface ProjectSettingsTabProps {
    projectId: number;
}

interface Env { id: number; name: string; deleted?: boolean; }

export const ProjectSettingsTab: React.FC<ProjectSettingsTabProps> = ({ projectId }) => {
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { data: project, isLoading: projectLoading } = useProject(projectId);
    // Include soft-deleted environments here so they can be restored.
    const { data: environments = [], isLoading: envsLoading } = useProjectEnvironments(projectId, true);
    const restoreEnvMutation = useRestoreEnvironment(projectId);

    // ── General ───────────────────────────────────────────────────────────
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [nameError, setNameError] = useState('');

    React.useEffect(() => {
        if (project) { setName(project.name); setDescription(project.description ?? ''); }
    }, [project]);

    const updateMutation = useMutation({
        mutationFn: (body: { name: string; description?: string }) =>
            apiClient.put(`/api/v1/projects/${projectId}`, body),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
        },
    });

    const handleSave = () => {
        if (!name.trim()) { setNameError('Name is required.'); return; }
        setNameError('');
        updateMutation.mutate({ name: name.trim(), ...(description.trim() ? { description: description.trim() } : {}) });
    };

    // ── Environments ──────────────────────────────────────────────────────
    const [newEnvName, setNewEnvName] = useState('');
    const [addEnvError, setAddEnvError] = useState('');
    const [envToDelete, setEnvToDelete] = useState<Env | null>(null);
    const [deleteEnvError, setDeleteEnvError] = useState('');

    const addEnvMutation = useMutation({
        mutationFn: (envName: string) =>
            apiClient.post(`/api/v1/projects/${projectId}/environments`, { name: envName }),
        onSuccess: () => {
            setNewEnvName(''); setAddEnvError('');
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
        },
        onError: (err: any) => {
            setAddEnvError(err?.response?.data?.error ?? err?.response?.data?.message ?? 'Failed to create environment.');
        },
    });

    const deleteEnvMutation = useMutation({
        mutationFn: (envId: number) => apiClient.delete(`/api/v1/environments/${envId}`),
        onSuccess: () => {
            setEnvToDelete(null); setDeleteEnvError('');
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
        onError: (err: any) => {
            setDeleteEnvError(
                err?.response?.data?.error ?? err?.response?.data?.message ?? 'Failed to delete environment.'
            );
        },
    });

    const closeDeleteEnvModal = () => {
        setEnvToDelete(null);
        setDeleteEnvError('');
        deleteEnvMutation.reset();
    };

    // ── Project deletion ──────────────────────────────────────────────────
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [deleteConfirm, setDeleteConfirm] = useState('');

    const deleteProjectMutation = useMutation({
        mutationFn: () => apiClient.delete(`/api/v1/projects/${projectId}`),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
            navigate(ROUTES.PROJECTS);
        },
    });

    // Incident-response: freeze / thaw every secret in the project (server #317).
    const [freezeMsg, setFreezeMsg] = useState('');
    const suspendAllMutation = useMutation({
        mutationFn: () => apiClient.post(`/api/v1/projects/${projectId}/secrets/suspend-all`, {}),
        onSuccess: (res: any) => {
            setFreezeMsg(`Froze ${res?.data?.data?.suspended ?? 0} secret(s) — value reads are blocked.`);
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
    });
    const resumeAllMutation = useMutation({
        mutationFn: () => apiClient.post(`/api/v1/projects/${projectId}/secrets/resume-all`, {}),
        onSuccess: (res: any) => {
            setFreezeMsg(`Resumed ${res?.data?.data?.resumed ?? 0} secret(s) — value reads are restored.`);
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
    });

    if (projectLoading) {
        return (
            <div className="space-y-3 animate-pulse">
                {[1, 2].map(i => (
                    <div key={i} className="h-12 rounded-lg" style={{ backgroundColor: 'var(--bg-muted)' }} />
                ))}
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
                            className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: nameError ? 'var(--error)' : 'var(--border)',
                            }} />
                        {nameError && <p className="text-xs mt-1" style={{ color: 'var(--error)' }}>{nameError}</p>}
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            Description
                        </label>
                        <input type="text" value={description} onChange={e => setDescription(e.target.value)}
                            placeholder="Optional"
                            className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
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
                    Environments group secrets by deployment stage. An environment with active secrets cannot be
                    deleted — move or delete its secrets first.
                </p>
                <div className="rounded-lg border"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>

                    {/* Environment list */}
                    {envsLoading ? (
                        <div className="p-4 animate-pulse space-y-2">
                            {[1, 2, 3].map(i => (
                                <div key={i} className="h-8 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                            ))}
                        </div>
                    ) : environments.length === 0 ? (
                        <div className="px-4 py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                            No environments yet. Add one below.
                        </div>
                    ) : (
                        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                            {(environments as Env[]).map(env => {
                                const isDefault = ['development', 'staging', 'production'].includes(
                                    env.name.toLowerCase()
                                );
                                return (
                                    <li key={env.id} className="flex items-center justify-between px-4 py-3 group"
                                        style={{ opacity: env.deleted ? 0.7 : 1 }}>
                                        <div className="flex items-center gap-2">
                                            <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
                                                {env.name.charAt(0).toUpperCase() + env.name.slice(1)}
                                            </span>
                                            {env.deleted ? (
                                                <span className="text-[10px] px-1.5 py-0.5 rounded-sm font-semibold uppercase tracking-wide"
                                                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}>
                                                    deleted
                                                </span>
                                            ) : isDefault && (
                                                <span className="text-xs px-1.5 py-0.5 rounded-sm"
                                                    style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-muted)' }}>
                                                    default
                                                </span>
                                            )}
                                        </div>
                                        {env.deleted ? (
                                            <button
                                                type="button"
                                                onClick={() => restoreEnvMutation.mutate(env.id)}
                                                disabled={restoreEnvMutation.isPending}
                                                className="flex items-center gap-1 p-1.5 rounded-sm text-sm transition-opacity disabled:opacity-50"
                                                style={{ color: 'var(--accent)' }}
                                                title="Restore environment"
                                            >
                                                <ArrowPathIcon className="h-4 w-4" />Restore
                                            </button>
                                        ) : (
                                            <button
                                                type="button"
                                                onClick={() => { setDeleteEnvError(''); setEnvToDelete(env); }}
                                                className="p-1.5 rounded-sm opacity-0 group-hover:opacity-100 transition-opacity hover:bg-red-50"
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
                        {addEnvError && (
                            <p className="text-xs mb-2" style={{ color: 'var(--error)' }}>{addEnvError}</p>
                        )}
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={newEnvName}
                                onChange={e => { setNewEnvName(e.target.value); setAddEnvError(''); }}
                                onKeyDown={e => {
                                    if (e.key === 'Enter' && newEnvName.trim())
                                        addEnvMutation.mutate(newEnvName.trim());
                                }}
                                placeholder="New environment name…"
                                className="flex-1 rounded-lg border px-3 py-1.5 text-sm outline-hidden focus:ring-2 focus:ring-blue-500"
                                style={{
                                    backgroundColor: 'var(--bg-app)',
                                    color: 'var(--text-primary)',
                                    borderColor: 'var(--border)',
                                }}
                            />
                            <Button
                                size="sm"
                                onClick={() => newEnvName.trim() && addEnvMutation.mutate(newEnvName.trim())}
                                disabled={!newEnvName.trim() || addEnvMutation.isPending}
                            >
                                <PlusIcon className="h-4 w-4 mr-1" />Add
                            </Button>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── Incident response ── */}
            <section>
                <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Incident response</h2>
                <div className="rounded-lg border p-5 space-y-3"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Freeze blocks value reads of every secret in this project (versions and shares are
                        preserved); resume restores them. Use during incident response.
                    </p>
                    {(suspendAllMutation.isError || resumeAllMutation.isError) && (
                        <Alert type="error" title="Error" message="The action failed. Please try again." />
                    )}
                    {freezeMsg && <Alert type="success" title="Done" message={freezeMsg} />}
                    <div className="flex gap-2">
                        <Button
                            variant="outline"
                            disabled={suspendAllMutation.isPending}
                            onClick={() => {
                                if (window.confirm('Freeze ALL secrets in this project? Value reads will be blocked until you resume them.')) {
                                    setFreezeMsg('');
                                    suspendAllMutation.mutate();
                                }
                            }}
                        >
                            {suspendAllMutation.isPending ? 'Freezing…' : 'Freeze all secrets'}
                        </Button>
                        <Button
                            variant="outline"
                            disabled={resumeAllMutation.isPending}
                            onClick={() => { setFreezeMsg(''); resumeAllMutation.mutate(); }}
                        >
                            {resumeAllMutation.isPending ? 'Resuming…' : 'Resume all'}
                        </Button>
                    </div>
                </div>
            </section>

            {/* ── Danger zone ── */}
            <section>
                <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--error)' }}>Danger Zone</h2>
                <div className="rounded-lg border p-5 flex items-center justify-between"
                    style={{ borderColor: 'var(--error)', backgroundColor: 'var(--error-subtle)' }}>
                    <div>
                        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                            Delete this project
                        </p>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            Permanently deletes the project and all its secrets. This cannot be undone.
                        </p>
                    </div>
                    <Button variant="danger" onClick={() => setShowDeleteModal(true)}>Delete Project</Button>
                </div>
            </section>

            {/* ── Delete environment modal ── */}
            <Modal
                isOpen={envToDelete !== null}
                onClose={closeDeleteEnvModal}
                title="Delete Environment"
                size="sm"
            >
                <div className="space-y-4">
                    {deleteEnvError ? (
                        <Alert type="error" title="Cannot delete environment" message={deleteEnvError} />
                    ) : (
                        <div className="space-y-2">
                            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                Delete environment{' '}
                                <span className="font-semibold">{envToDelete?.name}</span>?
                            </p>
                            {['development', 'staging', 'production'].includes(
                                envToDelete?.name?.toLowerCase() ?? ''
                            ) && (
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                    This is a default environment. It will be soft-deleted and can be
                                    recreated at any time.
                                </p>
                            )}
                        </div>
                    )}
                    <div className="flex justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button variant="outline" onClick={closeDeleteEnvModal}>
                            {deleteEnvError ? 'Close' : 'Cancel'}
                        </Button>
                        {!deleteEnvError && (
                            <Button
                                variant="danger"
                                disabled={deleteEnvMutation.isPending}
                                onClick={() => envToDelete && deleteEnvMutation.mutate(envToDelete.id)}
                            >
                                {deleteEnvMutation.isPending ? 'Deleting…' : 'Delete'}
                            </Button>
                        )}
                    </div>
                </div>
            </Modal>

            {/* ── Delete project modal ── */}
            <Modal
                isOpen={showDeleteModal}
                onClose={() => { setShowDeleteModal(false); setDeleteConfirm(''); }}
                title="Delete Project"
                size="sm"
            >
                <div className="space-y-4">
                    {deleteProjectMutation.isError && (
                        <Alert type="error" title="Failed to delete"
                            message={(deleteProjectMutation.error as any)?.response?.data?.error
                                ?? (deleteProjectMutation.error as any)?.message
                                ?? 'Could not delete the project.'} />
                    )}
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Delete project <span className="font-semibold">{project?.name}</span>?
                        The project, its environments, and all its secrets will be soft-deleted.
                        Type the project name to confirm.
                    </p>
                    <input
                        type="text"
                        value={deleteConfirm}
                        onChange={e => setDeleteConfirm(e.target.value)}
                        placeholder={project?.name}
                        className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
                        style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }}
                    />
                    <div className="flex justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button variant="outline" onClick={() => { setShowDeleteModal(false); setDeleteConfirm(''); }}>
                            Cancel
                        </Button>
                        <Button
                            variant="danger"
                            disabled={deleteConfirm !== project?.name || deleteProjectMutation.isPending}
                            onClick={() => deleteProjectMutation.mutate()}
                        >
                            {deleteProjectMutation.isPending ? 'Deleting…' : 'Delete'}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
