import { apiClient } from './client';
import type { SetupLinkResult } from './users';

// ADR-024 onboarding: project invitations (admin invites an email) and access
// requests (a user asks for a role; an admin approves/rejects). Both are
// project-scoped state machines served under /api/v1/projects/{id}/...
//
// The Go models carry no JSON tags, so the server emits PascalCase keys
// (ID, ProjectID, …). Normalizers below also tolerate snake_case/camelCase so
// the UI keeps working if tags are added later.

export interface ProjectInvitation {
    id: number;
    projectId: number;
    email: string;
    role: string;
    state: string; // pending | accepted | revoked | expired
    invitedBy: number;
    expiresAt?: string;
    createdAt?: string;
}

export interface AccessRequest {
    id: number;
    projectId: number;
    userId: number;
    suggestedRole: string;
    grantedRole: string;
    state: string; // pending | approved | rejected | withdrawn | expired
    reason: string;
    resolvedBy: number;
    expiresAt?: string;
    createdAt?: string;
}

const normalizeInvitation = (i: any): ProjectInvitation => ({
    id: i.ID ?? i.id,
    projectId: i.ProjectID ?? i.project_id ?? i.projectId,
    email: i.Email ?? i.email ?? '',
    role: i.Role ?? i.role ?? '',
    state: i.State ?? i.state ?? '',
    invitedBy: i.InvitedBy ?? i.invited_by ?? i.invitedBy ?? 0,
    expiresAt: i.ExpiresAt ?? i.expires_at ?? i.expiresAt ?? undefined,
    createdAt: i.CreatedAt ?? i.created_at ?? i.createdAt ?? undefined,
});

const normalizeAccessRequest = (r: any): AccessRequest => ({
    id: r.ID ?? r.id,
    projectId: r.ProjectID ?? r.project_id ?? r.projectId,
    userId: r.UserID ?? r.user_id ?? r.userId,
    suggestedRole: r.SuggestedRole ?? r.suggested_role ?? r.suggestedRole ?? '',
    grantedRole: r.GrantedRole ?? r.granted_role ?? r.grantedRole ?? '',
    state: r.State ?? r.state ?? '',
    reason: r.Reason ?? r.reason ?? '',
    resolvedBy: r.ResolvedBy ?? r.resolved_by ?? r.resolvedBy ?? 0,
    expiresAt: r.ExpiresAt ?? r.expires_at ?? r.expiresAt ?? undefined,
    createdAt: r.CreatedAt ?? r.created_at ?? r.createdAt ?? undefined,
});

// GlobalInviteResult is the POST /invitations response: the created invitation plus
// the setup-link delivery outcome (mirrors the ADR-028 credential-delivery shape).
export interface GlobalInviteResult {
    invitation: ProjectInvitation;
    setup_link?: SetupLinkResult;
    delivery_error?: string;
}

export const projectInvitationsApi = {
    // ── Invitations ──────────────────────────────────────────────────────────
    async listInvitations(projectId: number): Promise<ProjectInvitation[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/invitations`);
        const rows = response.data.data?.invitations ?? response.data.invitations ?? [];
        return rows.map(normalizeInvitation);
    },

    async createInvitation(projectId: number, email: string, role: string): Promise<ProjectInvitation> {
        const response = await apiClient.post(`/api/v1/projects/${projectId}/invitations`, { email, role });
        const inv = response.data.data?.invitation ?? response.data.data ?? response.data;
        return normalizeInvitation(inv);
    },

    async revokeInvitation(projectId: number, invitationId: number): Promise<void> {
        await apiClient.delete(`/api/v1/projects/${projectId}/invitations/${invitationId}`);
    },

    // Global (non-project-scoped) invitation (ADR-024): an optional system role plus
    // per-project assignments, applied atomically when the user accepts. Returns the
    // invitation plus the setup-link delivery outcome (link for out-of-band relay, or
    // a delivery_error if the link couldn't be sent but the invite was still created).
    async createGlobal(
        email: string,
        role: string,
        assignments: { project_id: number; role: string }[]
    ): Promise<GlobalInviteResult> {
        const response = await apiClient.post('/api/v1/invitations', {
            email,
            ...(role ? { role } : {}),
            ...(assignments.length ? { project_assignments: assignments } : {}),
        });
        const data = response.data?.data ?? response.data ?? {};
        return {
            invitation: normalizeInvitation(data.invitation ?? data),
            setup_link: data.setup_link,
            delivery_error: data.delivery_error,
        };
    },

    // ── Access requests ────────────────────────────────────────────────────────
    async listAccessRequests(projectId: number): Promise<AccessRequest[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/access-requests`);
        const rows = response.data.data?.access_requests ?? response.data.access_requests ?? [];
        return rows.map(normalizeAccessRequest);
    },

    // Resolve a pending request. The server grants grantedRole (falling back to
    // the suggested role) at the project scope on approve; reject records reason.
    async resolveAccessRequest(
        projectId: number,
        requestId: number,
        action: 'approve' | 'reject',
        grantedRole?: string,
        reason?: string
    ): Promise<void> {
        await apiClient.put(`/api/v1/projects/${projectId}/access-requests/${requestId}`, {
            action,
            granted_role: grantedRole ?? '',
            reason: reason ?? '',
        });
    },

    // Self-service: the requester cancels their own pending request.
    async withdrawAccessRequest(projectId: number, requestId: number): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/access-requests/${requestId}/withdraw`);
    },
};
