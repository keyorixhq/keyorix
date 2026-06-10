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
    deleted?: boolean;
}

export interface ProjectEnvironment {
    id: number;
    name: string;
    projectId: number;
    deleted?: boolean;
}

export interface CreateProjectPayload {
    name: string;
    description?: string | undefined;
}

export interface ProjectMember {
    userId: number;
    username: string;
    displayName: string;
    email: string;
    roleId: number;
    roleName: string;
}

// Cross-environment drift detection (M2). A key is consistent, present in some
// environments but not others, or present everywhere with diverging settings.
export type DriftStatus = 'missing_in_some' | 'metadata_drift';

export interface DriftEnvironment {
    id: number;
    name: string;
}

export interface DriftKey {
    name: string;
    presentIn: number[];
    missingFrom: number[];
    status: DriftStatus;
    driftFields: string[];
}

export interface DriftSummary {
    environmentCount: number;
    totalKeys: number;
    consistentKeys: number;
    missingInSome: number;
    metadataDrift: number;
}

export interface ProjectDrift {
    projectId: number;
    environments: DriftEnvironment[];
    driftedKeys: DriftKey[];
    summary: DriftSummary;
}

const normalizeDrift = (d: any): ProjectDrift => ({
    projectId: d.project_id ?? d.projectId ?? 0,
    environments: (d.environments ?? []).map((e: any) => ({ id: e.id ?? e.ID, name: e.name ?? e.Name })),
    driftedKeys: (d.drifted_keys ?? d.driftedKeys ?? []).map((k: any) => ({
        name: k.name ?? '',
        presentIn: k.present_in ?? k.presentIn ?? [],
        missingFrom: k.missing_from ?? k.missingFrom ?? [],
        status: k.status,
        driftFields: k.drift_fields ?? k.driftFields ?? [],
    })),
    summary: {
        environmentCount: d.summary?.environment_count ?? 0,
        totalKeys: d.summary?.total_keys ?? 0,
        consistentKeys: d.summary?.consistent_keys ?? 0,
        missingInSome: d.summary?.missing_in_some ?? 0,
        metadataDrift: d.summary?.metadata_drift ?? 0,
    },
});

// ADR-021 project roles offered in the Members tab.
export const PROJECT_ROLES = ['project_admin', 'project_developer', 'project_viewer', 'project_auditor'] as const;

const normalizeMember = (m: any): ProjectMember => ({
    userId: m.user_id ?? m.userId,
    username: m.username ?? '',
    displayName: m.display_name ?? m.displayName ?? '',
    email: m.email ?? '',
    roleId: m.role_id ?? m.roleId ?? 0,
    roleName: m.role_name ?? m.roleName ?? '',
});

const normalize = (p: any): Project => ({
    id: p.ID ?? p.id,
    name: p.Name ?? p.name,
    description: p.Description ?? p.description ?? '',
    secretCount: p.SecretCount ?? p.secret_count ?? 0,
    environmentCount: p.EnvironmentCount ?? p.environment_count ?? 0,
    lastActivity: p.last_activity ?? p.LastActivity ?? p.UpdatedAt ?? p.updated_at ?? '',
    createdAt: p.CreatedAt ?? p.created_at ?? '',
    updatedAt: p.UpdatedAt ?? p.updated_at ?? '',
    deleted: p.deleted ?? false,
});

const normalizeEnv = (e: any): ProjectEnvironment => ({
    id: e.ID ?? e.id,
    name: e.Name ?? e.name,
    projectId: e.ProjectID ?? e.project_id,
    deleted: Boolean(e.DeletedAt ?? e.deleted_at),
});

export const projectsApi = {
    async list(includeDeleted = false): Promise<Project[]> {
        const response = await apiClient.get(
            `/api/v1/projects${includeDeleted ? '?include_deleted=true' : ''}`
        );
        const projects = response.data.data?.projects ?? response.data.projects ?? [];
        return projects.map(normalize);
    },

    async restore(projectId: number): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/restore`);
    },

    async restoreEnvironment(projectId: number, environmentId: number): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/environments/${environmentId}/restore`);
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

    async listEnvironments(projectId: number, includeDeleted = false): Promise<ProjectEnvironment[]> {
        const response = await apiClient.get(
            `/api/v1/projects/${projectId}/environments${includeDeleted ? '?include_deleted=true' : ''}`
        );
        const envs = response.data.data?.environments ?? response.data.environments ?? [];
        return envs.map(normalizeEnv);
    },

    async listMembers(projectId: number): Promise<ProjectMember[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/members`);
        const members = response.data.data?.members ?? response.data.members ?? [];
        return members.map(normalizeMember);
    },

    async addMember(projectId: number, userId: number, role: string): Promise<void> {
        await apiClient.post(`/api/v1/projects/${projectId}/members`, { user_id: userId, role });
    },

    async updateMemberRole(projectId: number, userId: number, role: string): Promise<void> {
        await apiClient.put(`/api/v1/projects/${projectId}/members/${userId}`, { role });
    },

    async removeMember(projectId: number, userId: number): Promise<void> {
        await apiClient.delete(`/api/v1/projects/${projectId}/members/${userId}`);
    },

    async drift(projectId: number): Promise<ProjectDrift> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/drift`);
        return normalizeDrift(response.data.data ?? response.data);
    },
};
