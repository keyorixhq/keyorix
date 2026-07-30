import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { projectsApi, CreateProjectPayload, AccessReviewDecision } from '../../services/projects';
import { projectMembershipsApi, MembershipAction } from '../../services/projectMemberships';

export const PROJECT_KEYS = {
    all: ['projects'] as const,
    list: (includeDeleted = false) => [...PROJECT_KEYS.all, 'list', { includeDeleted }] as const,
    detail: (id: number) => [...PROJECT_KEYS.all, 'detail', id] as const,
    environments: (id: number, includeDeleted = false) =>
        [...PROJECT_KEYS.all, 'environments', id, { includeDeleted }] as const,
    members: (id: number) => [...PROJECT_KEYS.all, 'members', id] as const,
    drift: (id: number) => [...PROJECT_KEYS.all, 'drift', id] as const,
    rotationPlan: (id: number) => [...PROJECT_KEYS.all, 'rotation-plan', id] as const,
    accessReview: (id: number) => [...PROJECT_KEYS.all, 'access-review', id] as const,
};

export function useProjectDrift(projectId: number) {
    return useQuery({
        queryKey: PROJECT_KEYS.drift(projectId),
        queryFn: () => projectsApi.drift(projectId),
        enabled: !!projectId,
        staleTime: 60_000,
    });
}

export function useProjectRotationPlan(projectId: number) {
    return useQuery({
        queryKey: PROJECT_KEYS.rotationPlan(projectId),
        queryFn: () => projectsApi.rotationPlan(projectId),
        enabled: !!projectId,
        staleTime: 60_000,
    });
}

export function useProjects(includeDeleted = false) {
    return useQuery({
        queryKey: PROJECT_KEYS.list(includeDeleted),
        queryFn: () => projectsApi.list(includeDeleted),
        staleTime: 30_000,
    });
}

export function useProject(id: number) {
    return useQuery({
        queryKey: PROJECT_KEYS.detail(id),
        queryFn: () => projectsApi.get(id),
        enabled: !!id,
        staleTime: 30_000,
    });
}

export function useProjectEnvironments(projectId: number, includeDeleted = false) {
    return useQuery({
        queryKey: PROJECT_KEYS.environments(projectId, includeDeleted),
        queryFn: () => projectsApi.listEnvironments(projectId, includeDeleted),
        enabled: !!projectId,
        staleTime: 60_000,
    });
}

export function useCreateProject() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (payload: CreateProjectPayload) => projectsApi.create(payload),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.list() });
        },
    });
}

export function useDeleteProject() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (projectId: number) => projectsApi.delete(projectId),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
        },
    });
}

export function useRestoreProject() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (projectId: number) => projectsApi.restore(projectId),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
        },
    });
}

export function useRestoreEnvironment(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (environmentId: number) => projectsApi.restoreEnvironment(projectId, environmentId),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
        },
    });
}

export function useProjectMembers(projectId: number) {
    return useQuery({
        queryKey: PROJECT_KEYS.members(projectId),
        queryFn: () => projectsApi.listMembers(projectId),
        enabled: !!projectId,
        staleTime: 30_000,
    });
}

export function useAddProjectMember(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ userId, role }: { userId: number; role: string }) =>
            projectsApi.addMember(projectId, userId, role),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.members(projectId) }),
    });
}

export function useUpdateProjectMemberRole(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ userId, role }: { userId: number; role: string }) =>
            projectsApi.updateMemberRole(projectId, userId, role),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.members(projectId) }),
    });
}

export function useRemoveProjectMember(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (userId: number) => projectsApi.removeMember(projectId, userId),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.members(projectId) }),
    });
}

// ── Membership lifecycle (ADR-022) ──────────────────────────────────────────

export const MEMBERSHIP_KEYS = {
    list: (projectId: number) => ['project-memberships', 'list', projectId] as const,
};

export function useProjectMemberships(projectId: number) {
    return useQuery({
        queryKey: MEMBERSHIP_KEYS.list(projectId),
        queryFn: () => projectMembershipsApi.list(projectId),
        enabled: !!projectId,
        staleTime: 30_000,
        retry: false,
    });
}

export function useTransitionMembership(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ membershipId, action }: { membershipId: number; action: MembershipAction }) =>
            projectMembershipsApi.transition(projectId, membershipId, action),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: MEMBERSHIP_KEYS.list(projectId) });
            // Activating grants a role — the main member roster changes too.
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.members(projectId) });
        },
    });
}

export function useAccessReview(projectId: number) {
    return useQuery({
        queryKey: PROJECT_KEYS.accessReview(projectId),
        queryFn: () => projectsApi.accessReview(projectId),
        enabled: !!projectId,
        staleTime: 30_000,
    });
}

export function useAttestAccessReview(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (decision: AccessReviewDecision) => projectsApi.attestAccessReview(projectId, decision),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.accessReview(projectId) }),
    });
}

export function useRevokeAccessReview(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (decision: AccessReviewDecision) => projectsApi.revokeAccessReview(projectId, decision),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.accessReview(projectId) }),
    });
}

export function useAccessReviewCampaigns(projectId: number) {
    return useQuery({
        queryKey: [...PROJECT_KEYS.accessReview(projectId), 'campaigns'],
        queryFn: () => projectsApi.listCampaigns(projectId),
        enabled: !!projectId,
        staleTime: 30_000,
    });
}

export function useAccessReviewCampaign(projectId: number, campaignId: number | null) {
    return useQuery({
        queryKey: [...PROJECT_KEYS.accessReview(projectId), 'campaign', campaignId],
        queryFn: () => projectsApi.getCampaign(projectId, campaignId as number),
        enabled: !!projectId && !!campaignId,
        staleTime: 15_000,
    });
}

function invalidateCampaigns(queryClient: ReturnType<typeof useQueryClient>, projectId: number) {
    queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.accessReview(projectId) });
}

export function useOpenCampaign(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (name: string) => projectsApi.openCampaign(projectId, name),
        onSuccess: () => invalidateCampaigns(queryClient, projectId),
    });
}

export function useDecideCampaignItem(projectId: number, campaignId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (v: { itemId: number; action: 'attest' | 'revoke'; reason?: string }) =>
            projectsApi.decideCampaignItem(projectId, campaignId, v.itemId, v.action, v.reason),
        onSuccess: () => invalidateCampaigns(queryClient, projectId),
    });
}

export function useCloseCampaign(projectId: number) {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (v: { campaignId: number; force: boolean }) =>
            projectsApi.closeCampaign(projectId, v.campaignId, v.force),
        onSuccess: () => invalidateCampaigns(queryClient, projectId),
    });
}
