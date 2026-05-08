import { apiClient } from './client';

export interface Project {
    id: number;
    name: string;
    description?: string;
    secretCount?: number;
    environmentCount?: number;
    lastActivity?: string;
    createdAt?: string;
    updatedAt?: string;
}

export interface ProjectEnvironment {
    id: number;
    name: string;
    projectId: number;
}

export interface CreateProjectPayload {
    name: string;
    description?: string | undefined;
}

const normalize = (p: any): Project => ({
    id: p.ID ?? p.id,
    name: p.Name ?? p.name,
    description: p.Description ?? p.description ?? '',
    secretCount: p.SecretCount ?? p.secret_count ?? 0,
    environmentCount: p.EnvironmentCount ?? p.environment_count ?? 0,
    lastActivity: p.UpdatedAt ?? p.updated_at ?? '',
    createdAt: p.CreatedAt ?? p.created_at ?? '',
    updatedAt: p.UpdatedAt ?? p.updated_at ?? '',
});

const normalizeEnv = (e: any): ProjectEnvironment => ({
    id: e.ID ?? e.id,
    name: e.Name ?? e.name,
    projectId: e.ProjectID ?? e.project_id,
});

export const projectsApi = {
    async list(): Promise<Project[]> {
        const response = await apiClient.get('/api/v1/projects');
        const projects = response.data.data?.projects ?? response.data.projects ?? [];
        return projects.map(normalize);
    },

    async get(id: number): Promise<Project> {
        const response = await apiClient.get(`/api/v1/projects/${id}`);
        const p = response.data.data ?? response.data;
        return normalize(p);
    },

    async create(payload: CreateProjectPayload): Promise<Project> {
        const response = await apiClient.post('/api/v1/projects', payload);
        const p = response.data.data ?? response.data;
        return normalize(p);
    },

    async delete(projectId: number): Promise<void> {
        await apiClient.delete(`/api/v1/projects/${projectId}`);
    },

    async listEnvironments(projectId: number): Promise<ProjectEnvironment[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/environments`);
        const envs = response.data.data?.environments ?? response.data.environments ?? [];
        return envs.map(normalizeEnv);
    },
};
