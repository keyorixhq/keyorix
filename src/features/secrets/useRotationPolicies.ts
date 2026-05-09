import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../services/client';
import { RotationPolicy, RotationPolicyEvaluation, CreateRotationPolicyPayload } from '../../types';

const BASE = '/api/v1/rotation-policies';

// The RotationPolicy model has no json tags, so Go serializes it as PascalCase.
function normalizePolicy(p: Record<string, unknown>): RotationPolicy {
    return {
        id:               (p.ID   ?? p.id)               as number,
        name:             (p.Name ?? p.name)             as string,
        description:      (p.Description ?? p.description ?? '') as string,
        scope:            (p.Scope ?? p.scope)           as 'project' | 'environment',
        project_id:       (p.ProjectID ?? p.project_id ?? null) as number | null,
        environment_id:   (p.EnvironmentID ?? p.environment_id ?? null) as number | null,
        interval_days:    (p.IntervalDays ?? p.interval_days)   as number,
        alert_days_before:(p.AlertDaysBefore ?? p.alert_days_before) as number,
        notify_on_breach: (p.NotifyOnBreach ?? p.notify_on_breach ?? false) as boolean,
        is_active:        (p.IsActive ?? p.is_active ?? true) as boolean,
        created_by:       (p.CreatedBy ?? p.created_by ?? '') as string,
        created_at:       (p.CreatedAt ?? p.created_at ?? '') as string,
        updated_at:       (p.UpdatedAt ?? p.updated_at ?? '') as string,
    };
}

export function useRotationPolicies(filters?: { projectId?: number; environmentId?: number }) {
    const { data, isLoading, error, refetch } = useQuery({
        queryKey: ['rotation-policies', 'list', filters],
        queryFn: async () => {
            const params: Record<string, unknown> = {};
            if (filters?.projectId) params.project_id = filters.projectId;
            if (filters?.environmentId) params.environment_id = filters.environmentId;
            const response = await apiClient.get(BASE, { params });
            const raw: unknown[] = response.data.data?.policies ?? response.data.data ?? [];
            return raw.map(p => normalizePolicy(p as Record<string, unknown>));
        },
        staleTime: 2 * 60 * 1000,
    });
    return { policies: data ?? [], isLoading, error, refetch };
}

export function useRotationPolicyEvaluations(projectId?: number) {
    const { data, isLoading, error } = useQuery({
        queryKey: ['rotation-policies', 'evaluate', projectId],
        queryFn: async () => {
            const params: Record<string, unknown> = {};
            if (projectId) params.project_id = projectId;
            const response = await apiClient.get(`${BASE}/evaluate`, { params });
            const raw = response.data.data;
            return (raw?.evaluations ?? raw ?? []) as RotationPolicyEvaluation[];
        },
        staleTime: 2 * 60 * 1000,
    });
    return { evaluations: data ?? [], isLoading, error };
}

export function useCreateRotationPolicy() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (data: CreateRotationPolicyPayload) =>
            apiClient.post(BASE, data).then(r => r.data.data as RotationPolicy),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['rotation-policies'] });
        },
    });
}

export function useUpdateRotationPolicy() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: ({ id, ...data }: { id: number } & Partial<CreateRotationPolicyPayload>) =>
            apiClient.put(`${BASE}/${id}`, data).then(r => r.data.data as RotationPolicy),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['rotation-policies'] });
        },
    });
}

export function useDeleteRotationPolicy() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => apiClient.delete(`${BASE}/${id}`),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['rotation-policies'] });
        },
    });
}
