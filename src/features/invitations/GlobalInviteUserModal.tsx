import React, { useState } from 'react';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { Button } from '../../components/ui/Button';
import { ProjectAssignmentsPicker } from '../admin';
import { SYSTEM_ROLES } from '../../services/users';
import type { ProjectAssignment, SetupLinkResult } from '../../services/users';
import { useCreateGlobalInvitation } from './api';
import { inviteErrorMessage } from './inviteErrorMessage';

interface GlobalInviteUserModalProps {
    isOpen: boolean;
    onClose: () => void;
}

// "system_auditor" → "Auditor"
const systemRoleLabel = (role: string) => role.replace(/^system_/, '').replace(/^\w/, (c) => c.toUpperCase());

const EMAIL_RE = /^[^@\s]+@[^@\s.]+\.[^@\s]+$/;

/**
 * ADR-024 Global-Admin invitation dialog. Invites an email (which may not yet have
 * an account) with three sections — identity, an optional system role, and a set of
 * per-project assignments via the typeahead picker. The backend's atomic
 * POST /invitations snapshots all of it and applies every grant in one go when the
 * user accepts the setup link. The project-scoped variant (single project, fixed
 * role) lives on the project Members tab; this is the install-wide entry point.
 */
export const GlobalInviteUserModal: React.FC<GlobalInviteUserModalProps> = ({ isOpen, onClose }) => {
    const [email, setEmail] = useState('');
    const [systemRole, setSystemRole] = useState('');
    const [assignments, setAssignments] = useState<ProjectAssignment[]>([]);
    const [error, setError] = useState('');
    const [result, setResult] = useState<SetupLinkResult | null>(null);
    const [deliveryError, setDeliveryError] = useState('');
    const [copied, setCopied] = useState(false);

    const invite = useCreateGlobalInvitation();

    function reset() {
        setEmail('');
        setSystemRole('');
        setAssignments([]);
        setError('');
        setResult(null);
        setDeliveryError('');
        setCopied(false);
    }

    function handleClose() {
        if (invite.isPending) return;
        reset();
        onClose();
    }

    function handleCopy() {
        if (!result?.link_for_admin) return;
        navigator.clipboard?.writeText(result.link_for_admin);
        setCopied(true);
    }

    function handleSubmit() {
        setError('');
        if (!EMAIL_RE.test(email.trim())) {
            setError('Enter a valid email address.');
            return;
        }
        invite.mutate(
            {
                email: email.trim(),
                role: systemRole,
                assignments: assignments.map(({ project_id, role }) => ({ project_id, role })),
            },
            {
                onSuccess: (res) => {
                    if (res.setup_link) {
                        setResult(res.setup_link);
                    } else {
                        // The invite exists but the link couldn't be delivered (e.g. base_url
                        // unset). Surface it so the admin can fix config and resend.
                        setDeliveryError(res.delivery_error || 'The setup link could not be delivered.');
                    }
                },
                onError: (err: any) => setError(inviteErrorMessage(err, 'Failed to send invitation.')),
            }
        );
    }

    const sentEmail = email.trim();

    const fallbackContent = deliveryError ? (
        <div className="space-y-4">
            <Alert
                type="warning"
                message={`Invitation created for ${sentEmail}, but the setup link couldn't be delivered: ${deliveryError}`}
            />
            <p className="text-sm text-base-secondary">
                Fix the credential-delivery configuration (e.g. the server base URL), then resend the link from
                the user's detail page.
            </p>
            <div className="flex justify-end pt-2">
                <Button variant="default" onClick={handleClose}>
                    Done
                </Button>
            </div>
        </div>
    ) : (
        <div className="space-y-4">
            <p className="text-sm text-base-muted">
                Invite someone by email. They don't need an account yet — it's created when they accept the
                single-use setup link, with the system role and project assignments below applied in one step.
            </p>

            {error && <Alert type="error" message={error} />}

            <div>
                <label htmlFor="invite-email-input" className="block text-sm font-medium text-base-secondary mb-1">Email</label>
                <input
                    id="invite-email-input"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="jane@example.com"
                    autoFocus
                    className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                />
            </div>

            <div>
                <label htmlFor="invite-system-role-select" className="block text-sm font-medium text-base-secondary mb-1">
                    System role <span className="font-normal text-base-muted">(optional)</span>
                </label>
                <select
                    id="invite-system-role-select"
                    value={systemRole}
                    onChange={(e) => setSystemRole(e.target.value)}
                    className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 bg-surface"
                >
                    <option value="">Default (Viewer)</option>
                    {SYSTEM_ROLES.map((r) => (
                        <option key={r} value={r}>
                            {systemRoleLabel(r)}
                        </option>
                    ))}
                </select>
            </div>

            <ProjectAssignmentsPicker
                assignments={assignments}
                onChange={setAssignments}
                disabled={invite.isPending}
            />

            <div className="flex justify-end gap-3 pt-2">
                <Button variant="ghost" onClick={handleClose} disabled={invite.isPending}>
                    Cancel
                </Button>
                <Button variant="default" onClick={handleSubmit} disabled={invite.isPending || !email.trim()}>
                    {invite.isPending ? 'Sending…' : 'Send Invitation'}
                </Button>
            </div>
        </div>
    );

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title="Invite User" size="md">
            {result ? (
                <div className="space-y-4">
                    <Alert type="success" message={`Invitation created for ${sentEmail || result.email}.`} />
                    {result.link_for_admin ? (
                        <div className="space-y-2">
                            <p className="text-sm text-base-secondary">
                                Relay this single-use setup link to the user securely — it expires and can only be used
                                once. On accept, their system role and project assignments are applied automatically.
                            </p>
                            <div className="flex items-stretch gap-2">
                                <code className="flex-1 min-w-0 px-3 py-2 text-xs font-mono break-all rounded-lg border border-base bg-subtle text-base-secondary">
                                    {result.link_for_admin}
                                </code>
                                <Button variant="outline" onClick={handleCopy} className="shrink-0">
                                    {copied ? 'Copied' : 'Copy'}
                                </Button>
                            </div>
                        </div>
                    ) : (
                        <p className="text-sm text-base-secondary">
                            A setup link was sent to <span className="font-medium">{result.email}</span>
                            {result.channel ? <> via {result.channel}</> : null}. They'll set their own password on
                            first use, and their assignments apply on accept.
                        </p>
                    )}
                    <div className="flex justify-end pt-2">
                        <Button variant="default" onClick={handleClose}>
                            Done
                        </Button>
                    </div>
                </div>
            ) : fallbackContent}
        </Modal>
    );
};
