import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/projectInvitations', () => ({
    projectInvitationsApi: {
        listInvitations: vi.fn(),
        createInvitation: vi.fn(),
        createGlobal: vi.fn(),
        revokeInvitation: vi.fn(),
        listAccessRequests: vi.fn(),
        resolveAccessRequest: vi.fn(),
    },
}));

import { projectInvitationsApi } from '../../../services/projectInvitations';
import { PROJECT_KEYS } from '../../projects/api';
import {
    INVITATION_KEYS,
    useProjectInvitations,
    useCreateInvitation,
    useCreateGlobalInvitation,
    useRevokeInvitation,
    useProjectAccessRequests,
    useResolveAccessRequest,
} from '../api';

const mock = projectInvitationsApi as unknown as {
    listInvitations: ReturnType<typeof vi.fn>;
    createInvitation: ReturnType<typeof vi.fn>;
    createGlobal: ReturnType<typeof vi.fn>;
    revokeInvitation: ReturnType<typeof vi.fn>;
    listAccessRequests: ReturnType<typeof vi.fn>;
    resolveAccessRequest: ReturnType<typeof vi.fn>;
};

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => vi.clearAllMocks());

describe('useProjectInvitations', () => {
    it('fetches invitations for a project', async () => {
        mock.listInvitations.mockResolvedValueOnce([{ id: 1 }]);
        const { result } = renderHook(() => useProjectInvitations(5), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.listInvitations).toHaveBeenCalledWith(5);
    });

    it('does not fetch when projectId is falsy', async () => {
        renderHook(() => useProjectInvitations(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.listInvitations).not.toHaveBeenCalled();
    });
});

describe('useCreateInvitation', () => {
    it('creates an invitation and invalidates that project’s invitations', async () => {
        mock.createInvitation.mockResolvedValueOnce({ id: 9 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useCreateInvitation(5), { wrapper });

        act(() => {
            result.current.mutate({ email: 'bob@example.com', role: 'editor' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.createInvitation).toHaveBeenCalledWith(5, 'bob@example.com', 'editor');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: INVITATION_KEYS.invitations(5) });
    });
});

describe('useCreateGlobalInvitation', () => {
    it('creates a global invitation and invalidates all invitations', async () => {
        mock.createGlobal.mockResolvedValueOnce({ id: 10 });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useCreateGlobalInvitation(), { wrapper });

        const assignments = [{ project_id: 1, role: 'viewer' }];
        act(() => {
            result.current.mutate({ email: 'carol@example.com', role: 'system_viewer', assignments });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.createGlobal).toHaveBeenCalledWith('carol@example.com', 'system_viewer', assignments);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: INVITATION_KEYS.all });
    });
});

describe('useRevokeInvitation', () => {
    it('revokes an invitation and invalidates that project’s invitations', async () => {
        mock.revokeInvitation.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRevokeInvitation(5), { wrapper });

        act(() => {
            result.current.mutate(9);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.revokeInvitation).toHaveBeenCalledWith(5, 9);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: INVITATION_KEYS.invitations(5) });
    });
});

describe('useProjectAccessRequests', () => {
    it('fetches access requests for a project', async () => {
        mock.listAccessRequests.mockResolvedValueOnce([{ id: 1 }]);
        const { result } = renderHook(() => useProjectAccessRequests(5), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mock.listAccessRequests).toHaveBeenCalledWith(5);
    });

    it('does not fetch when projectId is falsy', async () => {
        renderHook(() => useProjectAccessRequests(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mock.listAccessRequests).not.toHaveBeenCalled();
    });
});

describe('useResolveAccessRequest', () => {
    it('resolves a request and invalidates both access requests and project members', async () => {
        mock.resolveAccessRequest.mockResolvedValueOnce(undefined);
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useResolveAccessRequest(5), { wrapper });

        act(() => {
            result.current.mutate({ requestId: 3, action: 'approve', grantedRole: 'editor', reason: 'looks good' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.resolveAccessRequest).toHaveBeenCalledWith(5, 3, 'approve', 'editor', 'looks good');
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: INVITATION_KEYS.accessRequests(5) });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: PROJECT_KEYS.members(5) });
    });
});
