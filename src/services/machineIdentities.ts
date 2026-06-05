import { apiClient } from './client';

// ADR-023 machine identities: non-human project members (CI runners, k8s
// workloads, services, automation) segmented from human members in the Members
// view. Project-scoped under /api/v1/projects/{id}/machine-identities, with a
// 4-state lifecycle: pending → active → suspended ⇄ active (revoked terminal).
//
// The Go model carries no JSON tags, so the server emits PascalCase keys
// (ID, ProjectID, …). The normalizer also tolerates snake_case/camelCase so the
// UI keeps working if tags are added later.

export type MachineIdentityType = 'ci' | 'k8s' | 'service' | 'automation' | 'other';
export type MachineIdentityState = 'pending' | 'active' | 'suspended' | 'revoked';
export type MachineAction = 'activate' | 'suspend' | 'revoke';

export interface MachineIdentity {
    id: number;
    projectId: number;
    name: string;
    identityType: MachineIdentityType;
    state: MachineIdentityState;
    description: string;
    createdBy: number;
    createdAt?: string;
    updatedAt?: string;
    lastSeenAt?: string;
    revokedAt?: string;
}

export const MACHINE_IDENTITY_TYPES: MachineIdentityType[] = [
    'ci',
    'k8s',
    'service',
    'automation',
    'other',
];

const normalizeMachineIdentity = (m: any): MachineIdentity => ({
    id: m.ID ?? m.id,
    projectId: m.ProjectID ?? m.project_id ?? m.projectId,
    name: m.Name ?? m.name ?? '',
    identityType: (m.IdentityType ?? m.identity_type ?? m.identityType ?? 'other') as MachineIdentityType,
    state: (m.State ?? m.state ?? 'pending') as MachineIdentityState,
    description: m.Description ?? m.description ?? '',
    createdBy: m.CreatedBy ?? m.created_by ?? m.createdBy ?? 0,
    createdAt: m.CreatedAt ?? m.created_at ?? m.createdAt ?? undefined,
    updatedAt: m.UpdatedAt ?? m.updated_at ?? m.updatedAt ?? undefined,
    lastSeenAt: m.LastSeenAt ?? m.last_seen_at ?? m.lastSeenAt ?? undefined,
    revokedAt: m.RevokedAt ?? m.revoked_at ?? m.revokedAt ?? undefined,
});

export const machineIdentitiesApi = {
    async list(projectId: number): Promise<MachineIdentity[]> {
        const response = await apiClient.get(`/api/v1/projects/${projectId}/machine-identities`);
        const rows = response.data.data?.machine_identities ?? response.data.machine_identities ?? [];
        return rows.map(normalizeMachineIdentity);
    },

    async create(
        projectId: number,
        name: string,
        identityType: MachineIdentityType,
        description = ''
    ): Promise<MachineIdentity> {
        const response = await apiClient.post(`/api/v1/projects/${projectId}/machine-identities`, {
            name,
            identity_type: identityType,
            description,
        });
        const m = response.data.data?.machine_identity ?? response.data.data ?? response.data;
        return normalizeMachineIdentity(m);
    },

    // Advance the lifecycle. The server enforces the state machine (409 on an
    // illegal transition).
    async transition(
        projectId: number,
        machineId: number,
        action: MachineAction
    ): Promise<MachineIdentity> {
        const response = await apiClient.put(
            `/api/v1/projects/${projectId}/machine-identities/${machineId}`,
            { action }
        );
        const m = response.data.data?.machine_identity ?? response.data.data ?? response.data;
        return normalizeMachineIdentity(m);
    },
};
