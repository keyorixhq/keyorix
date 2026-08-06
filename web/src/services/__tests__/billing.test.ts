import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { billingApi, BillingLicenseRequiredError } from '../billing';

const mock = apiClient as unknown as { get: ReturnType<typeof vi.fn> };

beforeEach(() => vi.clearAllMocks());

describe('billingApi.getReport', () => {
    it('normalizes a snake_case report payload and joins project_id filters', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                data: {
                    from: '2026-01-01T00:00:00Z',
                    to: '2026-02-01T00:00:00Z',
                    generated_at: '2026-02-01T00:00:00Z',
                    totals: {
                        projects: 1,
                        secret_count: 3,
                        secret_reads: 10,
                        secret_writes: 2,
                        secret_rotations: 1,
                        unique_users: 2,
                        machine_reads: 4,
                    },
                    projects: [
                        {
                            project_id: 5,
                            project_name: 'acme-prod',
                            secret_count: 3,
                            secret_reads: 10,
                            secret_writes: 2,
                            secret_rotations: 1,
                            unique_users: 2,
                            machine_reads: 4,
                        },
                    ],
                },
            },
        });

        const report = await billingApi.getReport({
            from: '2026-01-01T00:00:00Z',
            to: '2026-02-01T00:00:00Z',
            projectIds: [5, 6],
        });

        expect(mock.get).toHaveBeenCalledWith('/api/v1/admin/billing/report', {
            params: { from: '2026-01-01T00:00:00Z', to: '2026-02-01T00:00:00Z', project_id: '5,6' },
        });
        expect(report.totals.secretReads).toBe(10);
        expect(report.projects[0]).toEqual({
            projectId: 5,
            projectName: 'acme-prod',
            secretCount: 3,
            secretReads: 10,
            secretWrites: 2,
            secretRotations: 1,
            uniqueUsers: 2,
            machineReads: 4,
        });
    });

    it('omits project_id from the query when no filter is given', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { projects: [], totals: {} } } });

        await billingApi.getReport({ from: '2026-01-01T00:00:00Z', to: '2026-02-01T00:00:00Z' });

        expect(mock.get).toHaveBeenCalledWith('/api/v1/admin/billing/report', {
            params: { from: '2026-01-01T00:00:00Z', to: '2026-02-01T00:00:00Z' },
        });
    });

    it('throws BillingLicenseRequiredError on a 403 whose message mentions a license', async () => {
        mock.get.mockRejectedValueOnce({
            isAxiosError: true,
            response: {
                status: 403,
                data: { message: 'FinOps billing reports require a commercial license (feature: billing)' },
            },
        });

        await expect(
            billingApi.getReport({ from: '2026-01-01T00:00:00Z', to: '2026-02-01T00:00:00Z' })
        ).rejects.toBeInstanceOf(BillingLicenseRequiredError);
    });

    it('rethrows a plain permission 403 as-is (not a license error)', async () => {
        const err = {
            isAxiosError: true,
            response: { status: 403, data: { message: 'Insufficient permissions' } },
        };
        mock.get.mockRejectedValueOnce(err);

        await expect(
            billingApi.getReport({ from: '2026-01-01T00:00:00Z', to: '2026-02-01T00:00:00Z' })
        ).rejects.not.toBeInstanceOf(BillingLicenseRequiredError);
    });

    it('rethrows a non-403 error unchanged', async () => {
        const err = { isAxiosError: true, response: { status: 500, data: {} } };
        mock.get.mockRejectedValueOnce(err);

        await expect(billingApi.getReport({ from: '2026-01-01T00:00:00Z', to: '2026-02-01T00:00:00Z' })).rejects.toBe(
            err
        );
    });
});
