import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { PlusIcon, FolderIcon, MagnifyingGlassIcon, TrashIcon } from '@heroicons/react/24/outline';
import { useProjects, useCreateProject, useDeleteProject } from '../../features/projects/api';
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
                            className="w-full px-3 py-2 rounded-lg text-sm outline-none"
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
                            className="w-full px-3 py-2 rounded-lg text-sm outline-none"
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
}

const ProjectRow: React.FC<ProjectRowProps> = ({ project, onDeleteRequest }) => {
    const navigate = useNavigate();
    return (
        <div
            onClick={() => navigate(ROUTES.PROJECT_DETAIL(project.id))}
            className="flex items-center gap-4 px-4 py-3 rounded-lg transition-colors duration-100 group cursor-pointer"
            style={{ border: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)' }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-surface)'}
        >
            <div className="flex-shrink-0 h-9 w-9 rounded-lg flex items-center justify-center"
                style={{ backgroundColor: 'var(--accent-subtle)' }}>
                <FolderIcon className="h-5 w-5" style={{ color: 'var(--accent)' }} />
            </div>

            <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                    {project.name}
                </p>
                {project.description && (
                    <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                        {project.description}
                    </p>
                )}
            </div>

            <div className="hidden sm:flex items-center gap-4 text-xs flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
                <span>{project.secretCount ?? 0} secrets</span>
                <span>{project.environmentCount ?? 0} envs</span>
                {project.lastActivity && (
                    <span className="hidden md:block">
                        {new Date(project.lastActivity).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                    </span>
                )}
                <button
                    onClick={e => { e.stopPropagation(); onDeleteRequest(project); }}
                    className="p-1.5 rounded transition-colors hover:bg-red-50"
                    style={{ color: 'var(--error)' }}
                    title="Delete project"
                >
                    <TrashIcon className="h-4 w-4" />
                </button>
            </div>
        </div>
    );
};

// ── ProjectsListPage ─────────────────────────────────────────────────────────

export const ProjectsListPage: React.FC = () => {
    const { data: projects = [], isLoading, isError } = useProjects();
    const deleteProject = useDeleteProject();
    const [search, setSearch] = useState('');
    const [showCreate, setShowCreate] = useState(false);
    const [projectToDelete, setProjectToDelete] = useState<Project | null>(null);
    const [deleteConfirm, setDeleteConfirm] = useState('');
    const [deleteError, setDeleteError] = useState('');

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
        .sort((a, b) => (b.updatedAt ?? '').localeCompare(a.updatedAt ?? ''))
        .slice(0, 5);

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

            {/* Search */}
            <div className="relative mb-6">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                <input
                    type="text"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    placeholder="Search projects…"
                    className="w-full pl-9 pr-4 py-2 rounded-lg text-sm outline-none"
                    style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                />
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
                                    <ProjectRow key={p.id} project={p} onDeleteRequest={setProjectToDelete} />
                                ))}
                            </div>
                        </section>
                    )}

                    {/* All projects */}
                    <section>
                        {!search && (
                            <h2 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
                                All Projects
                            </h2>
                        )}

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

                        {filtered.length > 0 && (
                            <div className="space-y-2">
                                {filtered.map(p => (
                                    <ProjectRow key={p.id} project={p} onDeleteRequest={setProjectToDelete} />
                                ))}
                            </div>
                        )}
                    </section>
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
                                className="w-full rounded-lg border px-3 py-2 text-sm outline-none"
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
