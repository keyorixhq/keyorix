import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { projectInvitationsApi } from '../../services/projectInvitations';
import { PROJECT_KEYS } from '../projects/api';
import { SENSITIVE_GC_TIME } from '../../lib/queryClient';

// ADR-024 query keys, namespaced per project.
export const INVITATION_KEYS = {
    all: ['invitations'] as const,
    invitations: (projectId: number) => [...INVITATION_KEYS.all, 'list', projectId] as const,
    accessRequests: (projectId: number) => ['access-requests', 'list', projectId] as const,
};

// ── Invitations ──────────────────────────────────────────────────────────────

export function useProjectInvitations(projectId: number) {
    return useQuery({
        queryKey: INVITATION_KEYS.invitations(projectId),
        queryFn: () => projectInvitationsApi.listInvitations(projectId),
        enabled: !!projectId,
        staleTime: 30_000,
        retry: false, // a 403 for non-admins shouldn't thrash
    });
}

export function useCreateInvitation(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ email, role }: { email: string; role: string }) =>
            projectInvitationsApi.createInvitation(projectId, email, role),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: INVITATION_KEYS.invitations(projectId) }),
    });
}

// Global (non-project-scoped) invitation: system role + multi-project assignments,
// applied atomically on accept (ADR-024). Invalidates every project's invitation
// list since the invite isn't scoped to one project.
export function useCreateGlobalInvitation() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({
            email,
            role,
            assignments,
        }: {
            email: string;
            role: string;
            assignments: { project_id: number; role: string }[];
        }) => projectInvitationsApi.createGlobal(email, role, assignments),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: INVITATION_KEYS.all }),
        // G28: the response carries a one-time setup-link credential -- don't let
        // react-query's MutationCache retain it for the default 5 minutes.
        gcTime: SENSITIVE_GC_TIME,
    });
}

export function useRevokeInvitation(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (invitationId: number) => projectInvitationsApi.revokeInvitation(projectId, invitationId),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: INVITATION_KEYS.invitations(projectId) }),
    });
}

// ── Access requests ────────────────────────────────────────────────────────────

export function useProjectAccessRequests(projectId: number) {
    return useQuery({
        queryKey: INVITATION_KEYS.accessRequests(projectId),
        queryFn: () => projectInvitationsApi.listAccessRequests(projectId),
        enabled: !!projectId,
        staleTime: 30_000,
        retry: false,
    });
}

export function useResolveAccessRequest(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({
            requestId,
            action,
            grantedRole,
            reason,
        }: {
            requestId: number;
            action: 'approve' | 'reject';
            grantedRole?: string;
            reason?: string;
        }) => projectInvitationsApi.resolveAccessRequest(projectId, requestId, action, grantedRole, reason),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: INVITATION_KEYS.accessRequests(projectId) });
            // Approving grants a project role, so the member list changes too.
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.members(projectId) });
        },
    });
}
