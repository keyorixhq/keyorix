import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { projectsApi } from '../projects';

const mocked = apiClient as unknown as { get: ReturnType<typeof vi.fn> };

beforeEach(() => {
    vi.clearAllMocks();
});

describe('projectsApi.drift', () => {
    it('unwraps {data} and normalizes snake_case drift report', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    project_id: 1,
                    environments: [
                        { id: 1, name: 'development' },
                        { id: 2, name: 'staging' },
                        { id: 3, name: 'production' },
                    ],
                    drifted_keys: [
                        {
                            name: 'STRIPE_KEY',
                            present_in: [1, 2],
                            missing_from: [3],
                            status: 'missing_in_some',
                            drift_fields: [],
                        },
                        {
                            name: 'JWT_SECRET',
                            present_in: [1, 2, 3],
                            missing_from: [],
                            status: 'metadata_drift',
                            drift_fields: ['type', 'max_reads'],
                        },
                    ],
                    summary: {
                        environment_count: 3,
                        total_keys: 3,
                        consistent_keys: 1,
                        missing_in_some: 1,
                        metadata_drift: 1,
                    },
                },
            },
        });

        const report = await projectsApi.drift(1);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/1/drift');
        expect(report.projectId).toBe(1);
        expect(report.environments).toHaveLength(3);
        expect(report.driftedKeys[0]).toEqual({
            name: 'STRIPE_KEY',
            presentIn: [1, 2],
            missingFrom: [3],
            status: 'missing_in_some',
            driftFields: [],
        });
        expect(report.driftedKeys[1].driftFields).toEqual(['type', 'max_reads']);
        expect(report.summary.consistentKeys).toBe(1);
        expect(report.summary.missingInSome).toBe(1);
        expect(report.summary.metadataDrift).toBe(1);
    });

    it('defaults missing fields safely', async () => {
        mocked.get.mockResolvedValue({ data: { data: { project_id: 5 } } });
        const report = await projectsApi.drift(5);
        expect(report.projectId).toBe(5);
        expect(report.environments).toEqual([]);
        expect(report.driftedKeys).toEqual([]);
        expect(report.summary.totalKeys).toBe(0);
    });

    it('defaults projectId to 0, and normalizes environments/drifted-key fields via their fallbacks when sparse', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    environments: [{ ID: 1, Name: 'production' }],
                    driftedKeys: [{ presentIn: [1], missingFrom: [] }],
                },
            },
        });

        const report = await projectsApi.drift(0);

        expect(report.projectId).toBe(0);
        expect(report.environments).toEqual([{ id: 1, name: 'production' }]);
        expect(report.driftedKeys).toEqual([
            { name: '', presentIn: [1], missingFrom: [], status: undefined, driftFields: [] },
        ]);
    });

    it('falls back to response.data when there is no data.data wrapper', async () => {
        mocked.get.mockResolvedValue({ data: { project_id: 6 } });
        const report = await projectsApi.drift(6);
        expect(report.projectId).toBe(6);
    });
});
