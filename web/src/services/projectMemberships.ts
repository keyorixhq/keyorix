import { apiClient } from './client';

// ADR-022 membership lifecycle: separate from the flat project_members grant
// (services/projects.ts's listMembers/addMember/etc). A ProjectMembership
// tracks onboarding state (invited → identity_verified → provisioned → active,
// revoked terminal) for members added via the ADR-024 invitation-accept flow.
// Under the default "allowlist" validation mode, a membership only grants its
// project role once it reaches `active` — until then, the person doesn't
// appear in the flat member list at all, which is why this is surfaced
// separately rather than merged into it.
//
// The Go model carries no JSON tags, so the server emits PascalCase keys
// (ID, ProjectID, …). The normalizer also tolerates snake_case/camelCase so
// the UI keeps working if tags are added later.

export type MembershipState = 'invited' | 'identity_verified' | 'provisioned' | 'active' | 'revoked';
export type MembershipAction = 'verify' | 'provision' | 'activate' | 'revoke';

export interface ProjectMembership {
    id: number;
    projectId: number;
    userId: number;
    role: string;
    state: MembershipState;
    invitedAt?: string;
    activatedAt?: string;
    revokedAt?: string;
}

const normalizeMembership = (m: any): ProjectMembership => ({
    id: m.ID ?? m.id,
    projectId: m.ProjectID ?? m.project_id ?? m.projectId,
    userId: m.UserID ?? m.user_id ?? m.userId,
    role: m.Role ?? m.role ?? '',
    state: m.State ?? m.state ?? 'invited',
    invitedAt: m.InvitedAt ?? m.invited_at ?? m.invitedAt ?? undefined,
    activatedAt: m.ActivatedAt ?? m.activated_at ?? m.activatedAt ?? undefined,
    revokedAt: m.RevokedAt ?? m.revoked_at ?? m.revokedAt ?? undefined,
});

export const projectMembershipsApi = {
    async list(projectId: number): Promise<ProjectMembership[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/memberships`);
        const rows = response.data.data?.memberships ?? response.data.memberships ?? [];
        return rows.map(normalizeMembership);
    },

    // Advances (or revokes) a membership one step. The server enforces the
    // linear invited → identity_verified → provisioned → active chain — this
    // can't skip states.
    async transition(projectId: number, membershipId: number, action: MembershipAction): Promise<ProjectMembership> {
        const response = await apiClient.put(`/api/v1/projects/${projectId}/memberships/${membershipId}`, {
            action,
        });
        const m = response.data.data?.membership ?? response.data.membership ?? response.data;
        return normalizeMembership(m);
    },
};
