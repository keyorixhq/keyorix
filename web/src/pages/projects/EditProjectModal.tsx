import React, { useState } from 'react';
import { Project, UpdateProjectPayload } from '../../services/projects';
import { useUpdateProject } from '../../features/projects/api';

// Mirrors the server-side `identifier` validation (server/validation/validator.go):
// letters, digits, spaces, dashes and underscores; 1–200 chars.
const NAME_RE = /^[a-zA-Z0-9 _-]+$/;

interface EditProjectModalProps {
    project: Project;
    onClose: () => void;
    onSaved?: (project: Project) => void;
}

export const EditProjectModal: React.FC<EditProjectModalProps> = ({ project, onClose, onSaved }) => {
    const [name, setName] = useState(project.name);
    const [description, setDescription] = useState(project.description ?? '');
    const [error, setError] = useState('');
    const updateProject = useUpdateProject();

    const handleSubmit = async () => {
        const trimmed = name.trim();
        if (!trimmed) {
            setError('Project name is required.');
            return;
        }
        if (trimmed.length > 200) {
            setError('Project name must be 200 characters or fewer.');
            return;
        }
        if (!NAME_RE.test(trimmed)) {
            setError('Use letters, numbers, spaces, dashes and underscores only.');
            return;
        }
        setError('');
        const payload: UpdateProjectPayload = { name: trimmed, description: description.trim() };
        try {
            const updated = await updateProject.mutateAsync({ id: project.id, payload });
            onClose();
            onSaved?.(updated);
        } catch (e) {
            const err = e as { response?: { data?: { message?: string } }; message?: string };
            setError(err?.response?.data?.message || err?.message || 'Failed to update project.');
        }
    };

    const unchanged =
        name.trim() === project.name && description.trim() === (project.description ?? '');

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center"
            style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
        >
            <div
                className="w-full max-w-md rounded-xl p-6 shadow-2xl"
                style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)' }}
            >
                <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
                    Edit project
                </h2>

                <div className="space-y-4">
                    <div>
                        <label
                            htmlFor="edit-project-name"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Project name <span style={{ color: 'var(--error)' }}>*</span>
                        </label>
                        <input
                            id="edit-project-name"
                            type="text"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                            autoFocus
                            className="w-full px-3 py-2 rounded-lg text-sm outline-hidden"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                border: '1px solid var(--border)',
                                color: 'var(--text-primary)',
                            }}
                        />
                    </div>
                    <div>
                        <label
                            htmlFor="edit-project-description"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Description
                        </label>
                        <input
                            id="edit-project-description"
                            type="text"
                            value={description}
                            onChange={(e) => setDescription(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                            placeholder="Optional"
                            className="w-full px-3 py-2 rounded-lg text-sm outline-hidden"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                border: '1px solid var(--border)',
                                color: 'var(--text-primary)',
                            }}
                        />
                    </div>
                </div>

                {error && (
                    <p className="text-xs mt-3" style={{ color: 'var(--error)' }}>
                        {error}
                    </p>
                )}

                <div className="flex justify-end gap-2 mt-6">
                    <button
                        type="button"
                        onClick={onClose}
                        className="px-4 py-2 text-sm rounded-lg"
                        style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-subtle)' }}
                    >
                        Cancel
                    </button>
                    <button
                        type="button"
                        onClick={handleSubmit}
                        disabled={!name.trim() || unchanged || updateProject.isPending}
                        className="px-4 py-2 text-sm rounded-lg font-medium disabled:opacity-50"
                        style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                    >
                        {updateProject.isPending ? 'Saving…' : 'Save changes'}
                    </button>
                </div>
            </div>
        </div>
    );
};
