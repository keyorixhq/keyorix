import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/projects', () => ({
    projectsApi: {
        list: vi.fn(),
        restore: vi.fn(),
        restoreEnvironment: vi.fn(),
        get: vi.fn(),
        create: vi.fn(),
        delete: vi.fn(),
        listEnvironments: vi.fn(),
        listMembers: vi.fn(),
        addMember: vi.fn(),
        updateMemberRole: vi.fn(),
        removeMember: vi.fn(),
        drift: vi.fn(),
        rotationPlan: vi.fn(),
        accessReview: vi.fn(),
        attestAccessReview: vi.fn(),
        revokeAccessReview: vi.fn(),
        listCampaigns: vi.fn(),
        openCampaign: vi.fn(),
        getCampaign: vi.fn(),
        decideCampaignItem: vi.fn(),
        closeCampaign: vi.fn(),
    },
}));

vi.mock('../../../services/projectMemberships', () => ({
    projectMembershipsApi: {
        list: vi.fn(),
        transition: vi.fn(),
    },
}));

import { projectsApi } from '../../../services/projects';
import { projectMembershipsApi } from '../../../services/projectMemberships';
import {
    PROJECT_KEYS,
    MEMBERSHIP_KEYS,
    useProjectDrift,
    useProjectRotationPlan,
    useProjects,
    useProject,
    useProjectEnvironments,
    useCreateProject,
    useDeleteProject,
    useRestoreProject,
    useRestoreEnvironment,
    useProjectMembers,
    useAddProjectMember,
    useUpdateProjectMemberRole,
    useRemoveProjectMember,
    useProjectMemberships,
    useTransitionMembership,
    useAccessReview,
    useAttestAccessReview,
    useRevokeAccessReview,
    useAccessReviewCampaigns,
    useAccessReviewCampaign,
    useOpenCampaign,
    useDecideCampaignItem,
    useCloseCampaign,
} from '../api';

const mockProjects = projectsApi as unknown as Record<string, ReturnType<typeof vi.fn>>;
const mockMemberships = projectMembershipsApi as unknown as Record<string, ReturnType<typeof vi.fn>>;

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => {
    vi.clearAllMocks();
});

// ── PROJECT_KEYS / MEMBERSHIP_KEYS composition ──────────────────────────────

describe('PROJECT_KEYS', () => {
    it('builds keys with the expected shape', () => {
        expect(PROJECT_KEYS.all).toEqual(['projects']);
        expect(PROJECT_KEYS.list()).toEqual(['projects', 'list', { includeDeleted: false }]);
        expect(PROJECT_KEYS.list(true)).toEqual(['projects', 'list', { includeDeleted: true }]);
        expect(PROJECT_KEYS.detail(5)).toEqual(['projects', 'detail', 5]);
        expect(PROJECT_KEYS.environments(5)).toEqual(['projects', 'environments', 5, { includeDeleted: false }]);
        expect(PROJECT_KEYS.environments(5, true)).toEqual(['projects', 'environments', 5, { includeDeleted: true }]);
        expect(PROJECT_KEYS.members(5)).toEqual(['projects', 'members', 5]);
        expect(PROJECT_KEYS.drift(5)).toEqual(['projects', 'drift', 5]);
        expect(PROJECT_KEYS.rotationPlan(5)).toEqual(['projects', 'rotation-plan', 5]);
        expect(PROJECT_KEYS.accessReview(5)).toEqual(['projects', 'access-review', 5]);
    });
});

describe('MEMBERSHIP_KEYS', () => {
    it('builds the memberships list key', () => {
        expect(MEMBERSHIP_KEYS.list(5)).toEqual(['project-memberships', 'list', 5]);
    });
});

// ── plain queries ────────────────────────────────────────────────────────────

describe('useProjects', () => {
    it('fetches the list with includeDeleted defaulted to false', async () => {
        mockProjects.list!.mockResolvedValueOnce([{ id: 1 }]);
        const { result } = renderHook(() => useProjects(), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.list).toHaveBeenCalledWith(false);
        expect(result.current.data).toEqual([{ id: 1 }]);
    });

    it('forwards includeDeleted=true and uses a distinct query key', async () => {
        mockProjects.list!.mockResolvedValueOnce([{ id: 1 }, { id: 2, deleted: true }]);
        const { wrapper, queryClient } = createWrapper();
        const { result } = renderHook(() => useProjects(true), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.list).toHaveBeenCalledWith(true);
        expect(queryClient.getQueryData(PROJECT_KEYS.list(true))).toEqual([{ id: 1 }, { id: 2, deleted: true }]);
        expect(queryClient.getQueryData(PROJECT_KEYS.list(false))).toBeUndefined();
    });
});

describe('useProject', () => {
    it('fetches a project by id', async () => {
        mockProjects.get!.mockResolvedValueOnce({ id: 3, name: 'demo' });
        const { result } = renderHook(() => useProject(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.get).toHaveBeenCalledWith(3);
        expect(result.current.data).toEqual({ id: 3, name: 'demo' });
    });

    it('does not fetch when id is 0 (falsy)', async () => {
        renderHook(() => useProject(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.get).not.toHaveBeenCalled();
    });
});

describe('useProjectEnvironments', () => {
    it('fetches with includeDeleted defaulted to false', async () => {
        mockProjects.listEnvironments!.mockResolvedValueOnce([{ id: 1, name: 'prod' }]);
        const { result } = renderHook(() => useProjectEnvironments(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.listEnvironments).toHaveBeenCalledWith(3, false);
    });

    it('forwards an explicit includeDeleted=true', async () => {
        mockProjects.listEnvironments!.mockResolvedValueOnce([]);
        const { result } = renderHook(() => useProjectEnvironments(3, true), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.listEnvironments).toHaveBeenCalledWith(3, true);
    });

    it('does not fetch when projectId is 0', async () => {
        renderHook(() => useProjectEnvironments(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.listEnvironments).not.toHaveBeenCalled();
    });
});

describe('useProjectDrift', () => {
    it('fetches drift for a project', async () => {
        mockProjects.drift!.mockResolvedValueOnce({ projectId: 3, environments: [], driftedKeys: [] });
        const { result } = renderHook(() => useProjectDrift(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.drift).toHaveBeenCalledWith(3);
    });

    it('does not fetch when projectId is 0', async () => {
        renderHook(() => useProjectDrift(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.drift).not.toHaveBeenCalled();
    });
});

describe('useProjectRotationPlan', () => {
    it('fetches the rotation plan for a project', async () => {
        mockProjects.rotationPlan!.mockResolvedValueOnce({ projectId: 3, totalSecrets: 0, waves: [] });
        const { result } = renderHook(() => useProjectRotationPlan(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.rotationPlan).toHaveBeenCalledWith(3);
    });

    it('does not fetch when projectId is 0', async () => {
        renderHook(() => useProjectRotationPlan(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.rotationPlan).not.toHaveBeenCalled();
    });
});

describe('useProjectMembers', () => {
    it('fetches the members list', async () => {
        mockProjects.listMembers!.mockResolvedValueOnce([{ userId: 1 }]);
        const { result } = renderHook(() => useProjectMembers(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.listMembers).toHaveBeenCalledWith(3);
    });

    it('does not fetch when projectId is 0', async () => {
        renderHook(() => useProjectMembers(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.listMembers).not.toHaveBeenCalled();
    });
});

describe('useProjectMemberships', () => {
    it('fetches memberships for a project', async () => {
        mockMemberships.list!.mockResolvedValueOnce([{ id: 1, state: 'invited' }]);
        const { result } = renderHook(() => useProjectMemberships(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockMemberships.list).toHaveBeenCalledWith(3);
    });

    it('does not fetch when projectId is 0', async () => {
        renderHook(() => useProjectMemberships(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockMemberships.list).not.toHaveBeenCalled();
    });
});

describe('useAccessReview', () => {
    it('fetches the access review entries', async () => {
        mockProjects.accessReview!.mockResolvedValueOnce([{ principalId: 1 }]);
        const { result } = renderHook(() => useAccessReview(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.accessReview).toHaveBeenCalledWith(3);
    });

    it('does not fetch when projectId is 0', async () => {
        renderHook(() => useAccessReview(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.accessReview).not.toHaveBeenCalled();
    });
});

describe('useAccessReviewCampaigns', () => {
    it('fetches campaign summaries under an extended access-review key', async () => {
        mockProjects.listCampaigns!.mockResolvedValueOnce([]);
        const { wrapper, queryClient } = createWrapper();
        const { result } = renderHook(() => useAccessReviewCampaigns(3), { wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.listCampaigns).toHaveBeenCalledWith(3);
        expect(queryClient.getQueryData([...PROJECT_KEYS.accessReview(3), 'campaigns'])).toEqual([]);
    });

    it('does not fetch when projectId is 0', async () => {
        renderHook(() => useAccessReviewCampaigns(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.listCampaigns).not.toHaveBeenCalled();
    });
});

describe('useAccessReviewCampaign', () => {
    it('fetches a single campaign detail', async () => {
        mockProjects.getCampaign!.mockResolvedValueOnce({ campaign: { id: 7 }, items: [], progress: {} });
        const { result } = renderHook(() => useAccessReviewCampaign(3, 7), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockProjects.getCampaign).toHaveBeenCalledWith(3, 7);
    });

    it('does not fetch when campaignId is null', async () => {
        renderHook(() => useAccessReviewCampaign(3, null), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.getCampaign).not.toHaveBeenCalled();
    });

    it('does not fetch when projectId is 0', async () => {
        renderHook(() => useAccessReviewCampaign(0, 7), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockProjects.getCampaign).not.toHaveBeenCalled();
    });
});

// ── mutations with cache effects ────────────────────────────────────────────

describe('useCreateProject', () => {
    it('creates a project and invalidates every projects-scoped query', async () => {
        mockProjects.create!.mockResolvedValueOnce({ id: 9, name: 'new-project' });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useCreateProject(), { wrapper });

        act(() => {
            result.current.mutate({ name: 'new-project' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.create).toHaveBeenCalledWith({ name: 'new-project' });
        // Invalidating the broad PROJECT_KEYS.all prefix (rather than a concrete
        // list key) ensures every list view is refetched after create — both the
        // default non-deleted list and any deleted-inclusive list (useProjects(true)).
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.all });
    });
});

describe('useDeleteProject', () => {
    it('deletes a project and invalidates every projects-scoped query', async () => {
        mockProjects.delete!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useDeleteProject(), { wrapper });

        act(() => {
            result.current.mutate(3);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.delete).toHaveBeenCalledWith(3);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.all });
    });
});

describe('useRestoreProject', () => {
    it('restores a project and invalidates every projects-scoped query', async () => {
        mockProjects.restore!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRestoreProject(), { wrapper });

        act(() => {
            result.current.mutate(3);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.restore).toHaveBeenCalledWith(3);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.all });
    });
});

describe('useRestoreEnvironment', () => {
    it('restores an environment scoped to its project and invalidates every projects-scoped query', async () => {
        mockProjects.restoreEnvironment!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRestoreEnvironment(3), { wrapper });

        act(() => {
            result.current.mutate(11);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.restoreEnvironment).toHaveBeenCalledWith(3, 11);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.all });
    });
});

describe('useAddProjectMember', () => {
    it('adds a member and invalidates the members list for that project', async () => {
        mockProjects.addMember!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useAddProjectMember(3), { wrapper });

        act(() => {
            result.current.mutate({ userId: 5, role: 'project_developer' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.addMember).toHaveBeenCalledWith(3, 5, 'project_developer');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.members(3) });
    });
});

describe('useUpdateProjectMemberRole', () => {
    it('updates a member role and invalidates the members list for that project', async () => {
        mockProjects.updateMemberRole!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useUpdateProjectMemberRole(3), { wrapper });

        act(() => {
            result.current.mutate({ userId: 5, role: 'project_admin' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.updateMemberRole).toHaveBeenCalledWith(3, 5, 'project_admin');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.members(3) });
    });
});

describe('useRemoveProjectMember', () => {
    it('removes a member and invalidates the members list for that project', async () => {
        mockProjects.removeMember!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRemoveProjectMember(3), { wrapper });

        act(() => {
            result.current.mutate(5);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.removeMember).toHaveBeenCalledWith(3, 5);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.members(3) });
    });
});

describe('useTransitionMembership', () => {
    it('transitions a membership and invalidates both the memberships list and the flat members roster', async () => {
        mockMemberships.transition!.mockResolvedValueOnce({ id: 4, state: 'active' });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useTransitionMembership(3), { wrapper });

        act(() => {
            result.current.mutate({ membershipId: 4, action: 'activate' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockMemberships.transition).toHaveBeenCalledWith(3, 4, 'activate');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: MEMBERSHIP_KEYS.list(3) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.members(3) });
        expect(invalidateSpy).toHaveBeenCalledTimes(2);
    });
});

describe('useAttestAccessReview', () => {
    it('attests a decision and invalidates the access-review query', async () => {
        mockProjects.attestAccessReview!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useAttestAccessReview(3), { wrapper });
        const decision = { source: 'role', principalId: 1, roleId: 2, environmentId: 3, secretId: 4 };

        act(() => {
            result.current.mutate(decision);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.attestAccessReview).toHaveBeenCalledWith(3, decision);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.accessReview(3) });
    });
});

describe('useRevokeAccessReview', () => {
    it('revokes a decision and invalidates the access-review query', async () => {
        mockProjects.revokeAccessReview!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRevokeAccessReview(3), { wrapper });
        const decision = { source: 'direct_share', principalId: 1 };

        act(() => {
            result.current.mutate(decision);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.revokeAccessReview).toHaveBeenCalledWith(3, decision);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.accessReview(3) });
    });
});

describe('useOpenCampaign', () => {
    it('opens a campaign and invalidates the access-review key (covering campaign sub-queries too)', async () => {
        mockProjects.openCampaign!.mockResolvedValueOnce({ campaign: { id: 1 }, progress: {} });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useOpenCampaign(3), { wrapper });

        act(() => {
            result.current.mutate('Q1 recert');
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.openCampaign).toHaveBeenCalledWith(3, 'Q1 recert');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.accessReview(3) });
    });
});

describe('useDecideCampaignItem', () => {
    it('decides a campaign item with a reason and invalidates the access-review key', async () => {
        mockProjects.decideCampaignItem!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useDecideCampaignItem(3, 7), { wrapper });

        act(() => {
            result.current.mutate({ itemId: 1, action: 'attest', reason: 'confirmed by owner' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.decideCampaignItem).toHaveBeenCalledWith(3, 7, 1, 'attest', 'confirmed by owner');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.accessReview(3) });
    });

    it('decides a campaign item without a reason', async () => {
        mockProjects.decideCampaignItem!.mockResolvedValueOnce(undefined);
        const { result } = renderHook(() => useDecideCampaignItem(3, 7), { wrapper: createWrapper().wrapper });

        act(() => {
            result.current.mutate({ itemId: 2, action: 'revoke' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.decideCampaignItem).toHaveBeenCalledWith(3, 7, 2, 'revoke', undefined);
    });
});

describe('useCloseCampaign', () => {
    it('closes a campaign and invalidates the access-review key', async () => {
        mockProjects.closeCampaign!.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useCloseCampaign(3), { wrapper });

        act(() => {
            result.current.mutate({ campaignId: 7, force: true });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockProjects.closeCampaign).toHaveBeenCalledWith(3, 7, true);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.accessReview(3) });
    });
});
