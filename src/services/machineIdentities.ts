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
    classification: string;
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

// STALE_MACHINE_IDENTITY_DAYS mirrors the server's default stale window (#319).
export const STALE_MACHINE_IDENTITY_DAYS = 90;

// isStaleMachineIdentity reports whether an ACTIVE machine identity hasn't been seen
// within `days` (a never-seen one counts from its creation, so a brand-new identity
// isn't flagged until it has had the full window). A hint for revocation hygiene.
export function isStaleMachineIdentity(m: MachineIdentity, now: number = Date.now(), days = STALE_MACHINE_IDENTITY_DAYS): boolean {
    if (m.state !== 'active') return false;
    const ref = m.lastSeenAt ?? m.createdAt;
    if (!ref) return false;
    const t = new Date(ref).getTime();
    if (Number.isNaN(t)) return false;
    return now - t > days * 24 * 60 * 60 * 1000;
}

const normalizeMachineIdentity = (m: any): MachineIdentity => ({
    id: m.ID ?? m.id,
    projectId: m.ProjectID ?? m.project_id ?? m.projectId,
    name: m.Name ?? m.name ?? '',
    identityType: (m.IdentityType ?? m.identity_type ?? m.identityType ?? 'other') as MachineIdentityType,
    state: (m.State ?? m.state ?? 'pending') as MachineIdentityState,
    description: m.Description ?? m.description ?? '',
    createdBy: m.CreatedBy ?? m.created_by ?? m.createdBy ?? 0,
    classification: m.Classification ?? m.classification ?? '',
    createdAt: m.CreatedAt ?? m.created_at ?? m.createdAt ?? undefined,
    updatedAt: m.UpdatedAt ?? m.updated_at ?? m.updatedAt ?? undefined,
    lastSeenAt: m.LastSeenAt ?? m.last_seen_at ?? m.lastSeenAt ?? undefined,
    revokedAt: m.RevokedAt ?? m.revoked_at ?? m.revokedAt ?? undefined,
});

// ADR-030 machine-token credentials: opaque bearer tokens (kx_machine_…) a machine
// identity authenticates with. Only the hash is stored server-side; the raw token is
// returned ONCE on issue. Each carries its own data-classification (ISO A.5.12).
export interface MachineToken {
    id: number;
    name: string;
    prefix: string;
    lastUsedAt?: string;
    expiresAt?: string;
    revoked: boolean;
    classification: string;
    createdAt?: string;
}

// The one-time token returned on issue — shown once, never retrievable again.
export interface IssuedMachineToken {
    token: string;
    id: number;
    prefix: string;
    expiresAt?: string;
    classification: string;
}

const normalizeToken = (t: any): MachineToken => ({
    id: t.id ?? t.ID ?? 0,
    name: t.name ?? t.Name ?? '',
    prefix: t.prefix ?? t.TokenPrefix ?? '',
    lastUsedAt: t.last_used_at ?? t.LastUsedAt ?? undefined,
    expiresAt: t.expires_at ?? t.ExpiresAt ?? undefined,
    revoked: t.revoked ?? t.Revoked ?? false,
    classification: t.classification ?? t.Classification ?? '',
    createdAt: t.created_at ?? t.CreatedAt ?? undefined,
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

    // Set (or clear, with '') the machine identity's data-classification label
    // (ISO 27001 A.5.12).
    async classify(
        projectId: number,
        machineId: number,
        classification: string
    ): Promise<MachineIdentity> {
        const response = await apiClient.patch(
            `/api/v1/projects/${projectId}/machine-identities/${machineId}/classification`,
            { classification }
        );
        const m = response.data.data?.machine_identity ?? response.data.data ?? response.data;
        return normalizeMachineIdentity(m);
    },

    async listTokens(projectId: number, machineId: number): Promise<MachineToken[]> {
        const response = await apiClient.get(
            `/api/v1/projects/${projectId}/machine-identities/${machineId}/tokens`
        );
        const rows = response.data.data?.tokens ?? response.data.tokens ?? [];
        return rows.map(normalizeToken);
    },

    // Issue a token. The raw token is returned ONCE for out-of-band delivery.
    async issueToken(
        projectId: number,
        machineId: number,
        opts: { name: string; expiresInDays?: number; classification?: string }
    ): Promise<IssuedMachineToken> {
        const response = await apiClient.post(
            `/api/v1/projects/${projectId}/machine-identities/${machineId}/tokens`,
            {
                name: opts.name,
                expires_in_days: opts.expiresInDays ?? 0,
                classification: opts.classification ?? '',
            }
        );
        const t = response.data.data ?? response.data;
        return {
            token: t.token ?? '',
            id: t.id ?? t.ID ?? 0,
            prefix: t.prefix ?? '',
            expiresAt: t.expires_at ?? t.ExpiresAt ?? undefined,
            classification: t.classification ?? t.Classification ?? '',
        };
    },

    async revokeToken(projectId: number, machineId: number, tokenId: number): Promise<void> {
        await apiClient.delete(
            `/api/v1/projects/${projectId}/machine-identities/${machineId}/tokens/${tokenId}`
        );
    },

    // Set (or clear, with '') a token's data-classification label (ISO A.5.12).
    async classifyToken(
        projectId: number,
        machineId: number,
        tokenId: number,
        classification: string
    ): Promise<void> {
        await apiClient.patch(
            `/api/v1/projects/${projectId}/machine-identities/${machineId}/tokens/${tokenId}/classification`,
            { classification }
        );
    },
};
