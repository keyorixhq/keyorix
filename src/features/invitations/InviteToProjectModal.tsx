import React, { useState } from 'react';
import { Modal } from '../../components/ui/Modal';
import { PROJECT_ROLES } from '../../services/projects';
import { useCreateInvitation } from './api';
import { inviteErrorMessage } from './inviteErrorMessage';

interface InviteToProjectModalProps {
    isOpen: boolean;
    onClose: () => void;
    projectId: number;
    projectName: string;
}

// "project_developer" → "Developer"
const roleLabel = (role: string) => role.replace(/^project_/, '').replace(/^\w/, (c) => c.toUpperCase());

const EMAIL_RE = /^[^@\s]+@[^@\s.]+\.[^@\s]+$/;

/**
 * ADR-024 project-admin invitation dialog. Invites an email address (which may
 * not yet have an account) to *this* project with an intended role — the
 * project is pre-filled and fixed. The Global-Admin multi-project variant
 * (identity / system role / project assignments) is a separate global page.
 */
export const InviteToProjectModal: React.FC<InviteToProjectModalProps> = ({
    isOpen,
    onClose,
    projectId,
    projectName,
}) => {
    const [email, setEmail] = useState('');
    const [role, setRole] = useState<string>(PROJECT_ROLES[2]); // project_viewer
    const [error, setError] = useState('');
    const createInvitation = useCreateInvitation(projectId);

    const reset = () => {
        setEmail('');
        setRole(PROJECT_ROLES[2]);
        setError('');
    };

    const handleClose = () => {
        if (createInvitation.isPending) return;
        reset();
        onClose();
    };

    const handleSubmit = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        setError('');
        if (!EMAIL_RE.test(email.trim())) {
            setError('Enter a valid email address.');
            return;
        }
        createInvitation.mutate(
            { email: email.trim(), role },
            {
                onSuccess: () => {
                    reset();
                    onClose();
                },
                onError: (err: any) => setError(inviteErrorMessage(err, 'Failed to send invitation.')),
            }
        );
    };

    const inputStyle: React.CSSProperties = {
        backgroundColor: 'var(--bg-app)',
        border: '1px solid var(--border)',
        color: 'var(--text-primary)',
    };

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title={`Invite to ${projectName}`} size="sm">
            <form onSubmit={handleSubmit} className="space-y-4">
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    Invite someone by email to join this project. They'll receive the role below once they accept.
                </p>

                {error && (
                    <div
                        className="rounded-lg px-3 py-2 text-sm"
                        style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                    >
                        {error}
                    </div>
                )}

                <div>
                    <label
                        htmlFor="invite-email-input"
                        className="block text-xs font-medium mb-1"
                        style={{ color: 'var(--text-secondary)' }}
                    >
                        Email address
                    </label>
                    <input
                        id="invite-email-input"
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="person@example.com"
                        autoFocus
                        className="w-full rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={inputStyle}
                    />
                </div>

                <div>
                    <label
                        htmlFor="invite-role-select"
                        className="block text-xs font-medium mb-1"
                        style={{ color: 'var(--text-secondary)' }}
                    >
                        Project role
                    </label>
                    <select
                        id="invite-role-select"
                        value={role}
                        onChange={(e) => setRole(e.target.value)}
                        className="w-full rounded-lg px-3 py-1.5 text-sm outline-hidden"
                        style={inputStyle}
                    >
                        {PROJECT_ROLES.map((r) => (
                            <option key={r} value={r}>
                                {roleLabel(r)}
                            </option>
                        ))}
                    </select>
                </div>

                <div className="flex items-center justify-end gap-2 pt-2">
                    <button
                        type="button"
                        onClick={handleClose}
                        disabled={createInvitation.isPending}
                        className="px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                        style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={createInvitation.isPending || !email.trim()}
                        className="px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                        style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                    >
                        {createInvitation.isPending ? 'Sending…' : 'Send invite'}
                    </button>
                </div>
            </form>
        </Modal>
    );
};
