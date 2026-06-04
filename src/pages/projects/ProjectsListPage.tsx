import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { PlusIcon, FolderIcon, MagnifyingGlassIcon, TrashIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { useProjects, useCreateProject, useDeleteProject, useRestoreProject } from '../../features/projects/api';
import { ROUTES } from '../../constants';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import type { Project } from '../../services/projects';

// ── Create Project Modal ─────────────────────────────────────────────────────

interface CreateProjectModalProps {
    onClose: () => void;
}

const CreateProjectModal: React.FC<CreateProjectModalProps> = ({ onClose }) => {
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const createProject = useCreateProject();
    const navigate = useNavigate();

    const handleSubmit = async () => {
        if (!name.trim()) return;
        const payload = description.trim()
            ? { name: name.trim(), description: description.trim() }
            : { name: name.trim() };
        try {
            const project = await createProject.mutateAsync(payload);
            onClose();
            navigate(ROUTES.PROJECT_DETAIL(project.id));
        } catch {
            // error shown via authStore global handler
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
            <div className="w-full max-w-md rounded-xl p-6 shadow-2xl" style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>New Project</h2>

                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            Project name <span style={{ color: 'var(--error)' }}>*</span>
                        </label>
                        <input
                            type="text"
                            value={name}
                            onChange={e => setName(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
                            placeholder="e.g. backend-api"
                            autoFocus
                            className="w-full px-3 py-2 rounded-lg text-sm outline-hidden"
                            style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            Description
                        </label>
                        <input
                            type="text"
                            value={description}
                            onChange={e => setDescription(e.target.value)}
                            placeholder="Optional"
                            className="w-full px-3 py-2 rounded-lg text-sm outline-hidden"
                            style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                        />
                    </div>
                </div>

                <p className="text-xs mt-3" style={{ color: 'var(--text-muted)' }}>
                    Three environments (development, staging, production) will be created automatically.
                </p>

                <div className="flex justify-end gap-2 mt-6">
                    <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg"
                        style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-subtle)' }}>
                        Cancel
                    </button>
                    <button onClick={handleSubmit} disabled={!name.trim() || createProject.isPending}
                        className="px-4 py-2 text-sm rounded-lg font-medium disabled:opacity-50"
                        style={{ backgroundColor: 'var(--accent)', color: '#fff' }}>
                        {createProject.isPending ? 'Creating…' : 'Create Project'}
                    </button>
                </div>
            </div>
        </div>
    );
};

// ── Project Row ──────────────────────────────────────────────────────────────

interface ProjectRowProps {
    project: Project;
    onDeleteRequest: (project: Project) => void;
    onRestore: (project: Project) => void;
    restoring: boolean;
}

const ProjectRow: React.FC<ProjectRowProps> = ({ project, onDeleteRequest, onRestore, restoring }) => {
    const navigate = useNavigate();
    const deleted = project.deleted;
    return (
        <div
            onClick={() => { if (!deleted) navigate(ROUTES.PROJECT_DETAIL(project.id)); }}
            className={`flex items-center gap-4 px-4 py-3 rounded-lg transition-colors duration-100 group ${deleted ? '' : 'cursor-pointer'}`}
            style={{ border: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)', opacity: deleted ? 0.7 : 1 }}
            onMouseEnter={e => { if (!deleted) (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)'; }}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-surface)'}
        >
            <div className="shrink-0 h-9 w-9 rounded-lg flex items-center justify-center"
                style={{ backgroundColor: 'var(--accent-subtle)' }}>
                <FolderIcon className="h-5 w-5" style={{ color: 'var(--accent)' }} />
            </div>

            <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                    {project.name}
                    {deleted && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
                            style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}>
                            Deleted
                        </span>
                    )}
                </p>
                {project.description && (
                    <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                        {project.description}
                    </p>
                )}
            </div>

            <div className="hidden sm:flex items-center gap-4 text-xs shrink-0" style={{ color: 'var(--text-muted)' }}>
                <span>{project.secretCount ?? 0} secrets</span>
                <span>{project.environmentCount ?? 0} envs</span>
                {project.lastActivity && (
                    <span className="hidden md:block">
                        {new Date(project.lastActivity).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                    </span>
                )}
                {deleted ? (
                    <button
                        onClick={e => { e.stopPropagation(); onRestore(project); }}
                        disabled={restoring}
                        className="flex items-center gap-1 p-1.5 rounded-sm transition-colors disabled:opacity-50"
                        style={{ color: 'var(--accent)' }}
                        title="Restore project"
                    >
                        <ArrowPathIcon className="h-4 w-4" />
                        Restore
                    </button>
                ) : (
                    <button
                        onClick={e => { e.stopPropagation(); onDeleteRequest(project); }}
                        className="p-1.5 rounded-sm transition-colors hover:bg-red-50"
                        style={{ color: 'var(--error)' }}
                        title="Delete project"
                    >
                        <TrashIcon className="h-4 w-4" />
                    </button>
                )}
            </div>
        </div>
    );
};

// ── ProjectsListPage ─────────────────────────────────────────────────────────

export const ProjectsListPage: React.FC = () => {
    const [showDeleted, setShowDeleted] = useState(false);
    const { data: projects = [], isLoading, isError } = useProjects(showDeleted);
    const deleteProject = useDeleteProject();
    const restoreProject = useRestoreProject();
    const [search, setSearch] = useState('');
    const [searchParams] = useSearchParams();
    const [showCreate, setShowCreate] = useState(searchParams.get('new') === '1');
    const [projectToDelete, setProjectToDelete] = useState<Project | null>(null);
    const [deleteConfirm, setDeleteConfirm] = useState('');
    const [deleteError, setDeleteError] = useState('');

    const handleRestore = (project: Project) => {
        restoreProject.mutate(project.id);
    };

    const closeDeleteModal = () => {
        setProjectToDelete(null);
        setDeleteConfirm('');
        setDeleteError('');
        deleteProject.reset();
    };

    const handleDelete = () => {
        if (!projectToDelete) return;
        setDeleteError('');
        deleteProject.mutate(projectToDelete.id, {
            onSuccess: closeDeleteModal,
            onError: (err: any) => {
                setDeleteError(
                    err?.response?.data?.error ?? err?.response?.data?.message ?? 'Failed to delete project.'
                );
            },
        });
    };

    const filtered = search.trim()
        ? projects.filter(p => p.name.toLowerCase().includes(search.toLowerCase()) ||
            (p.description ?? '').toLowerCase().includes(search.toLowerCase()))
        : projects;

    const recent = [...projects]
        .filter(p => !p.deleted)
        .sort((a, b) => (b.updatedAt ?? '').localeCompare(a.updatedAt ?? ''))
        .slice(0, 5);

    const recentIds = new Set(recent.map(p => p.id));
    const nonRecent = filtered.filter(p => !recentIds.has(p.id));

    return (
        <div className="p-6 max-w-4xl mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>Projects</h1>
                    <p className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
                        Each project has its own environments and secrets.
                    </p>
                </div>
                <button
                    onClick={() => setShowCreate(true)}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium"
                    style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                >
                    <PlusIcon className="h-4 w-4" />
                    New Project
                </button>
            </div>

            {/* Search + show-deleted toggle */}
            <div className="flex items-center gap-3 mb-6">
                <div className="relative flex-1">
                    <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                    <input
                        type="text"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="Search projects…"
                        className="w-full pl-9 pr-4 py-2 rounded-lg text-sm outline-hidden"
                        style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                    />
                </div>
                <label className="flex items-center gap-2 text-sm shrink-0 cursor-pointer" style={{ color: 'var(--text-secondary)' }}>
                    <input
                        type="checkbox"
                        checked={showDeleted}
                        onChange={e => setShowDeleted(e.target.checked)}
                    />
                    Show deleted
                </label>
            </div>

            {isLoading && (
                <div className="text-center py-16">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-3" />
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Loading projects…</p>
                </div>
            )}

            {isError && !isLoading && (
                <div className="rounded-lg px-4 py-3 text-sm" style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}>
                    Failed to load projects. Check that the backend is running.
                </div>
            )}

            {!isLoading && !isError && (
                <>
                    {/* Recent — only when no search */}
                    {!search && recent.length > 0 && (
                        <section className="mb-8">
                            <h2 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                                Recent
                            </h2>
                            <div className="space-y-2">
                                {recent.map(p => (
                                    <ProjectRow key={p.id} project={p} onDeleteRequest={setProjectToDelete} onRestore={handleRestore} restoring={restoreProject.isPending} />
                                ))}
                            </div>
                        </section>
                    )}

                    {/* All projects — only those not already shown in Recent */}
                    {(!search ? nonRecent : filtered).length > 0 && (
                        <section>
                            {!search && (
                                <h2 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                                    All Projects
                                </h2>
                            )}
                            <div className="space-y-2">
                                {(!search ? nonRecent : filtered).map(p => (
                                    <ProjectRow key={p.id} project={p} onDeleteRequest={setProjectToDelete} onRestore={handleRestore} restoring={restoreProject.isPending} />
                                ))}
                            </div>
                        </section>
                    )}

                    {/* Empty state — only when nothing at all */}
                    {filtered.length === 0 && (
                        <div className="text-center py-16 rounded-xl" style={{ border: '1px dashed var(--border)' }}>
                            <FolderIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
                            {search ? (
                                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                    No projects match "<strong>{search}</strong>"
                                </p>
                            ) : (
                                <>
                                    <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                                        No projects yet
                                    </p>
                                    <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                                        Create your first project to start managing secrets.
                                    </p>
                                    <button
                                        onClick={() => setShowCreate(true)}
                                        className="px-4 py-2 rounded-lg text-sm font-medium"
                                        style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                                    >
                                        Create Project
                                    </button>
                                </>
                            )}
                        </div>
                    )}
                </>
            )}

            {showCreate && <CreateProjectModal onClose={() => setShowCreate(false)} />}

            {/* Delete confirmation modal */}
            <Modal isOpen={projectToDelete !== null} onClose={closeDeleteModal} title="Delete Project" size="sm">
                <div className="space-y-4">
                    {deleteError && (
                        <Alert type="error" title="Cannot delete project" message={deleteError} />
                    )}
                    {!deleteError && (
                        <>
                            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                Delete project <span className="font-semibold">{projectToDelete?.name}</span>?
                                All secrets and environments will be soft-deleted.
                                Type the project name to confirm.
                            </p>
                            <input
                                type="text"
                                value={deleteConfirm}
                                onChange={e => setDeleteConfirm(e.target.value)}
                                placeholder={projectToDelete?.name}
                                autoFocus
                                className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
                                style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }}
                            />
                        </>
                    )}
                    <div className="flex justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button variant="outline" onClick={closeDeleteModal}>
                            {deleteError ? 'Close' : 'Cancel'}
                        </Button>
                        {!deleteError && (
                            <Button
                                variant="danger"
                                disabled={deleteConfirm !== projectToDelete?.name || deleteProject.isPending}
                                onClick={handleDelete}
                            >
                                {deleteProject.isPending ? 'Deleting…' : 'Delete'}
                            </Button>
                        )}
                    </div>
                </div>
            </Modal>
        </div>
    );
};
