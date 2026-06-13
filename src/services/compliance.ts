import { apiClient } from './client';

// The deployment controls-posture snapshot (ISO 27001 / SOC 2 / NIS2 / DORA),
// served by GET /api/v1/compliance/posture (gated by system.read).
export interface CompliancePosture {
    generatedAt: string;
    auditIntegrity: {
        chainVerified: boolean;
        chainedEvents: number;
        checkpointed: boolean;
        reason?: string;
    };
    accessGovernance: {
        projects: number;
        projectsWithOpenCampaign: number;
        projectsNeverReviewed: number;
        openCampaigns: number;
        pendingItems: number;
        dormantRoleGrants: number;
    };
    rotation: {
        coveredSecrets: number;
        overdue: number;
        dueSoon: number;
    };
    identity: {
        activeUsers: number;
        usersWithSecondFactor: number;
        secondFactorPercent: number;
    };
    emergencyAccess: {
        activeActivations: number;
        totalActivations: number;
    };
}

const num = (v: any): number => (typeof v === 'number' ? v : 0);

const normalize = (d: any): CompliancePosture => ({
    generatedAt: d.generated_at ?? d.generatedAt ?? '',
    auditIntegrity: {
        chainVerified: !!(d.audit_integrity?.chain_verified),
        chainedEvents: num(d.audit_integrity?.chained_events),
        checkpointed: !!(d.audit_integrity?.checkpointed),
        reason: d.audit_integrity?.reason ?? undefined,
    },
    accessGovernance: {
        projects: num(d.access_governance?.projects),
        projectsWithOpenCampaign: num(d.access_governance?.projects_with_open_campaign),
        projectsNeverReviewed: num(d.access_governance?.projects_never_reviewed),
        openCampaigns: num(d.access_governance?.open_campaigns),
        pendingItems: num(d.access_governance?.pending_items),
        dormantRoleGrants: num(d.access_governance?.dormant_role_grants),
    },
    rotation: {
        coveredSecrets: num(d.rotation?.covered_secrets),
        overdue: num(d.rotation?.overdue),
        dueSoon: num(d.rotation?.due_soon),
    },
    identity: {
        activeUsers: num(d.identity?.active_users),
        usersWithSecondFactor: num(d.identity?.users_with_second_factor),
        secondFactorPercent: num(d.identity?.second_factor_percent),
    },
    emergencyAccess: {
        activeActivations: num(d.emergency_access?.active_activations),
        totalActivations: num(d.emergency_access?.total_activations),
    },
});

export const complianceApi = {
    async getPosture(): Promise<CompliancePosture> {
        const response = await apiClient.get('/api/v1/compliance/posture');
        return normalize(response.data.data ?? response.data);
    },
};
