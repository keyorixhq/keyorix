import { apiClient } from './client';

// The locally-evaluated offline-license entitlement (ADR-065), served by
// GET /api/v1/license/status (gated by system.read). Read-only — there is no
// install/upload endpoint; a new license is installed via `keyorix license
// install` on the server host.
export type LicenseState = 'active' | 'expiring_soon' | 'expired' | 'invalid' | 'none';

export interface LicenseStatus {
    state: LicenseState;
    licensee: string;
    plan: string;
    features: string[];
    grants: boolean;
    expiresAt: string;
    maxSeats: number;
    reason: string;
}

const normalize = (d: any): LicenseStatus => ({
    state: (d.state as LicenseState) ?? 'none',
    licensee: d.licensee ?? '',
    plan: d.plan ?? '',
    features: Array.isArray(d.features) ? d.features : [],
    grants: !!d.grants,
    expiresAt: d.expires_at ?? d.expiresAt ?? '',
    maxSeats: typeof d.max_seats === 'number' ? d.max_seats : (d.maxSeats ?? 0),
    reason: d.reason ?? '',
});

export const licenseApi = {
    async getStatus(): Promise<LicenseStatus> {
        const response = await apiClient.get('/api/v1/license/status');
        return normalize(response.data.data ?? response.data);
    },
};
