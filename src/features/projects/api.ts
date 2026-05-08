import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { projectsApi, CreateProjectPayload } from '../../services/projects';

export const PROJECT_KEYS = {
    all: ['projects'] as const,
    list: () => [...PROJECT_KEYS.all, 'list'] as const,
    detail: (id: number) => [...PROJECT_KEYS.all, 'detail', id] as const,
    environments: (id: number) => [...PROJECT_KEYS.all, 'environments', id] as const,
};

export function useProjects() {
    return useQuery({
        queryKey: PROJECT_KEYS.list(),
        queryFn: () => projectsApi.list(),
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

export function useProjectEnvironments(projectId: number) {
    return useQuery({
        queryKey: PROJECT_KEYS.environments(projectId),
        queryFn: () => projectsApi.listEnvironments(projectId),
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
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.list() });
        },
    });
}
