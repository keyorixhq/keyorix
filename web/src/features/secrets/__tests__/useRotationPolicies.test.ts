import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import {
    useRotationPolicies,
    useRotationPolicyEvaluations,
    useRotationStatus,
    useCreateRotationPolicy,
    useUpdateRotationPolicy,
    useDeleteRotationPolicy,
} from '../useRotationPolicies';

vi.mock('../../../services/client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../../../services/client';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

function ok<T>(data: T) {
    return { data: { data } };
}

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client: queryClient }, children);
    };
}

beforeEach(() => vi.clearAllMocks());

// ── useRotationPolicies ──────────────────────────────────────────────────────

describe('useRotationPolicies', () => {
    it('starts loading and transitions to success with normalized (Go PascalCase) policies', async () => {
        mock.get.mockResolvedValueOnce(
            ok({
                policies: [
                    {
                        ID: 1,
                        Name: 'db-rotation',
                        Description: 'Rotate DB creds',
                        Scope: 'project',
                        ProjectID: 5,
                        EnvironmentID: null,
                        IntervalDays: 30,
                        AlertDaysBefore: 7,
                        NotifyOnBreach: true,
                        IsActive: true,
                        CreatedBy: 'alice',
                        CreatedAt: '2026-01-01T00:00:00Z',
                        UpdatedAt: '2026-01-02T00:00:00Z',
                    },
                ],
            })
        );

        const { result } = renderHook(() => useRotationPolicies(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        expect(result.current.policies).toEqual([]);

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.policies).toEqual([
            {
                id: 1,
                name: 'db-rotation',
                description: 'Rotate DB creds',
                scope: 'project',
                project_id: 5,
                environment_id: null,
                interval_days: 30,
                alert_days_before: 7,
                notify_on_breach: true,
                is_active: true,
                created_by: 'alice',
                created_at: '2026-01-01T00:00:00Z',
                updated_at: '2026-01-02T00:00:00Z',
            },
        ]);
        expect(result.current.error).toBeNull();
    });

    it('normalizes already-snake_case payloads and applies field defaults when both casings are absent', async () => {
        mock.get.mockResolvedValueOnce(
            ok({
                policies: [
                    {
                        id: 2,
                        name: 'env-rotation',
                        scope: 'environment',
                        interval_days: 14,
                        alert_days_before: 3,
                        // description, notify_on_breach, is_active, project_id,
                        // environment_id, created_by, created_at, updated_at all omitted
                    },
                ],
            })
        );

        const { result } = renderHook(() => useRotationPolicies(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.policies).toEqual([
            {
                id: 2,
                name: 'env-rotation',
                description: '',
                scope: 'environment',
                project_id: null,
                environment_id: null,
                interval_days: 14,
                alert_days_before: 3,
                notify_on_breach: false,
                is_active: true,
                created_by: '',
                created_at: '',
                updated_at: '',
            },
        ]);
    });

    it('falls back to a bare array when the response has no {policies} wrapper', async () => {
        mock.get.mockResolvedValueOnce(
            ok([{ ID: 3, Name: 'bare-array', Scope: 'project', IntervalDays: 10, AlertDaysBefore: 2 }])
        );

        const { result } = renderHook(() => useRotationPolicies(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.policies).toHaveLength(1);
        expect(result.current.policies[0].id).toBe(3);
        expect(result.current.policies[0].name).toBe('bare-array');
    });

    it('defaults to an empty list when the response has neither a policies wrapper nor an array', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: undefined } });

        const { result } = renderHook(() => useRotationPolicies(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.policies).toEqual([]);
    });

    it('sends project_id and environment_id params only when provided (uses the correct query key)', async () => {
        mock.get.mockResolvedValueOnce(ok({ policies: [] }));

        const { result } = renderHook(() => useRotationPolicies({ projectId: 9, environmentId: 4 }), {
            wrapper: createWrapper(),
        });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(mock.get).toHaveBeenCalledWith('/api/v1/rotation-policies', {
            params: { project_id: 9, environment_id: 4 },
        });
    });

    it('omits both params when no filters are given', async () => {
        mock.get.mockResolvedValueOnce(ok({ policies: [] }));

        const { result } = renderHook(() => useRotationPolicies(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(mock.get).toHaveBeenCalledWith('/api/v1/rotation-policies', { params: {} });
    });

    it('surfaces a rejected request as an error and keeps policies as an empty array', async () => {
        mock.get.mockRejectedValueOnce(new Error('network down'));

        const { result } = renderHook(() => useRotationPolicies(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.error).not.toBeNull());

        expect(result.current.policies).toEqual([]);
        expect((result.current.error as Error).message).toBe('network down');
    });

    it('exposes a working refetch', async () => {
        mock.get
            .mockResolvedValueOnce(ok({ policies: [] }))
            .mockResolvedValueOnce(
                ok({ policies: [{ ID: 1, Name: 'x', Scope: 'project', IntervalDays: 1, AlertDaysBefore: 1 }] })
            );

        const { result } = renderHook(() => useRotationPolicies(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));
        expect(result.current.policies).toEqual([]);

        await result.current.refetch();

        await waitFor(() => expect(result.current.policies).toHaveLength(1));
        expect(mock.get).toHaveBeenCalledTimes(2);
    });
});

// ── useRotationPolicyEvaluations ─────────────────────────────────────────────

describe('useRotationPolicyEvaluations', () => {
    const evaluation = {
        policy_id: 1,
        policy_name: 'db-rotation',
        secret_id: 10,
        secret_name: 'db-password',
        last_rotated_at: null,
        days_overdue: 5,
        is_overdue: true,
        is_approaching: false,
    };

    it('unwraps the {evaluations} shape', async () => {
        mock.get.mockResolvedValueOnce(ok({ evaluations: [evaluation] }));

        const { result } = renderHook(() => useRotationPolicyEvaluations(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.evaluations).toEqual([evaluation]);
        expect(result.current.error).toBeNull();
    });

    it('falls back to a bare array when there is no {evaluations} wrapper', async () => {
        mock.get.mockResolvedValueOnce(ok([evaluation]));

        const { result } = renderHook(() => useRotationPolicyEvaluations(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.evaluations).toEqual([evaluation]);
    });

    it('defaults to an empty list when data is absent', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: undefined } });

        const { result } = renderHook(() => useRotationPolicyEvaluations(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.evaluations).toEqual([]);
    });

    it('passes project_id when given and omits it otherwise', async () => {
        mock.get.mockResolvedValueOnce(ok({ evaluations: [] }));
        const { result: withProject } = renderHook(() => useRotationPolicyEvaluations(7), {
            wrapper: createWrapper(),
        });
        await waitFor(() => expect(withProject.current.isLoading).toBe(false));
        expect(mock.get).toHaveBeenCalledWith('/api/v1/rotation-policies/evaluate', { params: { project_id: 7 } });

        mock.get.mockResolvedValueOnce(ok({ evaluations: [] }));
        const { result: withoutProject } = renderHook(() => useRotationPolicyEvaluations(), {
            wrapper: createWrapper(),
        });
        await waitFor(() => expect(withoutProject.current.isLoading).toBe(false));
        expect(mock.get).toHaveBeenCalledWith('/api/v1/rotation-policies/evaluate', { params: {} });
    });

    it('surfaces a rejected request as an error', async () => {
        mock.get.mockRejectedValueOnce(new Error('evaluate failed'));

        const { result } = renderHook(() => useRotationPolicyEvaluations(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.error).not.toBeNull());
        expect(result.current.evaluations).toEqual([]);
    });
});

// ── useRotationStatus ────────────────────────────────────────────────────────

describe('useRotationStatus', () => {
    const entry = {
        policy_id: 1,
        policy_name: 'db-rotation',
        interval_days: 30,
        alert_days_before: 7,
        secret_id: 10,
        secret_name: 'db-password',
        environment_id: 2,
        last_rotated_at: '2026-01-01T00:00:00Z',
        days_since_rotation: 40,
        days_overdue: 10,
        status: 'overdue' as const,
    };

    it('returns entries as-is (already snake_case, no normalization applied)', async () => {
        mock.get.mockResolvedValueOnce(ok([entry]));

        const { result } = renderHook(() => useRotationStatus(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.entries).toEqual([entry]);
        expect(result.current.error).toBeNull();
    });

    it('defaults to an empty list when data is absent', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: undefined } });

        const { result } = renderHook(() => useRotationStatus(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.entries).toEqual([]);
    });

    it('passes project_id when given and omits it otherwise', async () => {
        mock.get.mockResolvedValueOnce(ok([]));
        const { result: withProject } = renderHook(() => useRotationStatus(3), { wrapper: createWrapper() });
        await waitFor(() => expect(withProject.current.isLoading).toBe(false));
        expect(mock.get).toHaveBeenCalledWith('/api/v1/rotation-policies/status', { params: { project_id: 3 } });

        mock.get.mockResolvedValueOnce(ok([]));
        const { result: withoutProject } = renderHook(() => useRotationStatus(), { wrapper: createWrapper() });
        await waitFor(() => expect(withoutProject.current.isLoading).toBe(false));
        expect(mock.get).toHaveBeenCalledWith('/api/v1/rotation-policies/status', { params: {} });
    });

    it('surfaces a rejected request as an error', async () => {
        mock.get.mockRejectedValueOnce(new Error('status failed'));

        const { result } = renderHook(() => useRotationStatus(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.error).not.toBeNull());
        expect(result.current.entries).toEqual([]);
    });
});

// ── useCreateRotationPolicy ──────────────────────────────────────────────────

describe('useCreateRotationPolicy', () => {
    const payload = {
        name: 'new-policy',
        description: 'desc',
        scope: 'project' as const,
        project_id: 1,
        environment_id: null,
        interval_days: 30,
        alert_days_before: 5,
        notify_on_breach: true,
    };

    it('POSTs to the base endpoint and resolves with the created policy', async () => {
        const created = { id: 99, ...payload, is_active: true, created_by: 'bob', created_at: '', updated_at: '' };
        mock.post.mockResolvedValueOnce(ok(created));

        const { result } = renderHook(() => useCreateRotationPolicy(), { wrapper: createWrapper() });

        let mutationResult: unknown;
        await act(async () => {
            mutationResult = await result.current.mutateAsync(payload);
        });

        expect(mock.post).toHaveBeenCalledWith('/api/v1/rotation-policies', payload);
        expect(mutationResult).toEqual(created);
    });

    it('invalidates the rotation-policies query cache on success', async () => {
        mock.post.mockResolvedValueOnce(ok({ id: 1 }));
        mock.get.mockResolvedValue(ok({ policies: [] }));

        const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const wrapper = ({ children }: { children: React.ReactNode }) =>
            React.createElement(QueryClientProvider, { client: queryClient }, children);

        const { result } = renderHook(() => useCreateRotationPolicy(), { wrapper });

        await act(async () => {
            await result.current.mutateAsync(payload);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rotation-policies'] });
    });

    it('rejects and surfaces the mutation error when the request fails', async () => {
        mock.post.mockRejectedValueOnce(new Error('create failed'));

        const { result } = renderHook(() => useCreateRotationPolicy(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync(payload)).rejects.toThrow('create failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useUpdateRotationPolicy ──────────────────────────────────────────────────

describe('useUpdateRotationPolicy', () => {
    it('PUTs to /{id} with the id stripped from the body', async () => {
        mock.put.mockResolvedValueOnce(ok({ id: 5, name: 'renamed' }));

        const { result } = renderHook(() => useUpdateRotationPolicy(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync({ id: 5, name: 'renamed', interval_days: 60 });
        });

        expect(mock.put).toHaveBeenCalledWith('/api/v1/rotation-policies/5', {
            name: 'renamed',
            interval_days: 60,
        });
    });

    it('invalidates the rotation-policies query cache on success', async () => {
        mock.put.mockResolvedValueOnce(ok({ id: 5 }));

        const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const wrapper = ({ children }: { children: React.ReactNode }) =>
            React.createElement(QueryClientProvider, { client: queryClient }, children);

        const { result } = renderHook(() => useUpdateRotationPolicy(), { wrapper });

        await act(async () => {
            await result.current.mutateAsync({ id: 5, name: 'renamed' });
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rotation-policies'] });
    });

    it('rejects and surfaces the mutation error when the request fails', async () => {
        mock.put.mockRejectedValueOnce(new Error('update failed'));

        const { result } = renderHook(() => useUpdateRotationPolicy(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync({ id: 5, name: 'x' })).rejects.toThrow('update failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});

// ── useDeleteRotationPolicy ──────────────────────────────────────────────────

describe('useDeleteRotationPolicy', () => {
    it('DELETEs /{id}', async () => {
        mock.delete.mockResolvedValueOnce({ data: {} });

        const { result } = renderHook(() => useDeleteRotationPolicy(), { wrapper: createWrapper() });

        await act(async () => {
            await result.current.mutateAsync(12);
        });

        expect(mock.delete).toHaveBeenCalledWith('/api/v1/rotation-policies/12');
    });

    it('invalidates the rotation-policies query cache on success', async () => {
        mock.delete.mockResolvedValueOnce({ data: {} });

        const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const wrapper = ({ children }: { children: React.ReactNode }) =>
            React.createElement(QueryClientProvider, { client: queryClient }, children);

        const { result } = renderHook(() => useDeleteRotationPolicy(), { wrapper });

        await act(async () => {
            await result.current.mutateAsync(12);
        });

        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rotation-policies'] });
    });

    it('rejects and surfaces the mutation error when the request fails', async () => {
        mock.delete.mockRejectedValueOnce(new Error('delete failed'));

        const { result } = renderHook(() => useDeleteRotationPolicy(), { wrapper: createWrapper() });

        await expect(result.current.mutateAsync(12)).rejects.toThrow('delete failed');
        await waitFor(() => expect(result.current.isError).toBe(true));
    });
});
