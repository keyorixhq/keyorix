import axios from 'axios';
import { apiClient } from './client';

// One project's usage breakdown for a billing period, served by
// GET /api/v1/admin/billing/report (gated by system.read + the "billing"
// commercial license feature).
export interface BillingProjectStat {
    projectId: number;
    projectName: string;
    secretCount: number;
    secretReads: number;
    secretWrites: number;
    secretRotations: number;
    uniqueUsers: number;
    machineReads: number;
}

export interface BillingTotals {
    projects: number;
    secretCount: number;
    secretReads: number;
    secretWrites: number;
    secretRotations: number;
    uniqueUsers: number;
    machineReads: number;
}

export interface BillingReport {
    from: string;
    to: string;
    generatedAt: string;
    projects: BillingProjectStat[];
    totals: BillingTotals;
}

const num = (v: any): number => (typeof v === 'number' ? v : 0);

const normalizeProjectStat = (p: any): BillingProjectStat => ({
    projectId: num(p.project_id ?? p.projectId),
    projectName: p.project_name ?? p.projectName ?? '',
    secretCount: num(p.secret_count ?? p.secretCount),
    secretReads: num(p.secret_reads ?? p.secretReads),
    secretWrites: num(p.secret_writes ?? p.secretWrites),
    secretRotations: num(p.secret_rotations ?? p.secretRotations),
    uniqueUsers: num(p.unique_users ?? p.uniqueUsers),
    machineReads: num(p.machine_reads ?? p.machineReads),
});

const normalizeTotals = (t: any): BillingTotals => ({
    projects: num(t?.projects),
    secretCount: num(t?.secret_count ?? t?.secretCount),
    secretReads: num(t?.secret_reads ?? t?.secretReads),
    secretWrites: num(t?.secret_writes ?? t?.secretWrites),
    secretRotations: num(t?.secret_rotations ?? t?.secretRotations),
    uniqueUsers: num(t?.unique_users ?? t?.uniqueUsers),
    machineReads: num(t?.machine_reads ?? t?.machineReads),
});

const normalizeReport = (d: any): BillingReport => ({
    from: d.from ?? '',
    to: d.to ?? '',
    generatedAt: d.generated_at ?? d.generatedAt ?? '',
    projects: (d.projects ?? []).map(normalizeProjectStat),
    totals: normalizeTotals(d.totals),
});

// BillingLicenseRequiredError distinguishes "not licensed" from any other
// failure (a plain 403 insufficient-permission, a 500). Both the license gate
// and the permission gate return HTTP 403 with error:"Forbidden", so the only
// way to tell them apart is the message text the server deliberately chose
// ("... commercial license ...") — see server/http/handlers/admin_billing.go.
export class BillingLicenseRequiredError extends Error {}

export interface BillingReportParams {
    from: string; // RFC3339
    to: string; // RFC3339
    projectIds?: number[];
}

export const billingApi = {
    async getReport(params: BillingReportParams): Promise<BillingReport> {
        const query: Record<string, string> = { from: params.from, to: params.to };
        if (params.projectIds?.length) {
            query.project_id = params.projectIds.join(',');
        }
        try {
            const response = await apiClient.get('/api/v1/admin/billing/report', { params: query });
            return normalizeReport(response.data.data ?? response.data);
        } catch (err) {
            if (axios.isAxiosError(err) && err.response?.status === 403) {
                const message = (err.response.data as { message?: string } | undefined)?.message ?? '';
                if (message.toLowerCase().includes('license')) {
                    throw new BillingLicenseRequiredError(message);
                }
            }
            throw err;
        }
    },
};
