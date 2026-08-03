import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { complianceApi } from '../compliance';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => vi.clearAllMocks());

// ── getPosture ────────────────────────────────────────────────────────────────

describe('complianceApi.getPosture', () => {
    it('normalizes a full snake_case posture payload', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                data: {
                    generated_at: '2026-01-01T00:00:00Z',
                    audit_integrity: { chain_verified: true, chained_events: 10, checkpointed: true, reason: 'ok' },
                    access_governance: {
                        projects: 3,
                        projects_with_open_campaign: 1,
                        projects_never_reviewed: 0,
                        open_campaigns: 1,
                        pending_items: 2,
                        projects_overdue: 0,
                        dormant_role_grants: 0,
                        sod_violations: 0,
                    },
                    rotation: { covered_secrets: 5, overdue: 1, due_soon: 2 },
                    identity: { active_users: 8, users_with_second_factor: 6, second_factor_percent: 75 },
                    emergency_access: { active_activations: 0, total_activations: 1 },
                    classification: {
                        total_secrets: 20,
                        public: 1,
                        internal: 10,
                        confidential: 8,
                        restricted: 1,
                        unclassified: 0,
                    },
                    anomalies: { unacknowledged: 2, high_severity_open: 1 },
                    legal_hold: { active: true, reason: 'litigation', placed_at: '2026-01-01T00:00:00Z' },
                    retention: {
                        enabled: true,
                        anomaly_alerts_days: 90,
                        closed_access_reviews_days: 365,
                        break_glass_days: 30,
                        resolved_access_requests_days: 60,
                    },
                },
            },
        });

        const posture = await complianceApi.getPosture();

        expect(mock.get).toHaveBeenCalledWith('/api/v1/compliance/posture');
        expect(posture.generatedAt).toBe('2026-01-01T00:00:00Z');
        expect(posture.auditIntegrity).toEqual({
            chainVerified: true,
            chainedEvents: 10,
            checkpointed: true,
            reason: 'ok',
        });
        expect(posture.accessGovernance.openCampaigns).toBe(1);
        expect(posture.rotation).toEqual({ coveredSecrets: 5, overdue: 1, dueSoon: 2 });
        expect(posture.identity.secondFactorPercent).toBe(75);
        expect(posture.legalHold).toEqual({ active: true, reason: 'litigation', placedAt: '2026-01-01T00:00:00Z' });
        expect(posture.retention.anomalyAlertsDays).toBe(90);
    });

    it('falls back to response.data when there is no data.data wrapper', async () => {
        mock.get.mockResolvedValueOnce({ data: { generated_at: '2026-02-01T00:00:00Z' } });
        const posture = await complianceApi.getPosture();
        expect(posture.generatedAt).toBe('2026-02-01T00:00:00Z');
    });

    it('defaults every field on an empty payload', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: {} } });
        const posture = await complianceApi.getPosture();
        expect(posture.generatedAt).toBe('');
        expect(posture.auditIntegrity).toEqual({
            chainVerified: false,
            chainedEvents: 0,
            checkpointed: false,
            reason: undefined,
        });
        expect(posture.legalHold).toEqual({ active: false, reason: '', placedAt: undefined });
        expect(posture.retention.enabled).toBe(false);
    });
});

// ── getControls ──────────────────────────────────────────────────────────────

describe('complianceApi.getControls', () => {
    it('normalizes the control matrix and its frameworks', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                data: {
                    generated_at: '2026-01-01T00:00:00Z',
                    summary: { total: 2, pass: 1, gap: 1, not_configured: 0 },
                    controls: [
                        {
                            id: 'c1',
                            name: 'MFA enforced',
                            area: 'identity',
                            status: 'pass',
                            detail: 'ok',
                            frameworks: { iso_27001: ['A.9.4.2'], soc2: [], nis2: [], dora: [], ens: [] },
                        },
                    ],
                },
            },
        });

        const matrix = await complianceApi.getControls();

        expect(mock.get).toHaveBeenCalledWith('/api/v1/compliance/controls');
        expect(matrix.summary).toEqual({ total: 2, pass: 1, gap: 1, notConfigured: 0 });
        expect(matrix.controls).toHaveLength(1);
        expect(matrix.controls[0]).toMatchObject({ id: 'c1', status: 'pass' });
        expect(matrix.controls[0]?.frameworks.iso27001).toEqual(['A.9.4.2']);
    });

    it('defaults to an empty controls list when missing', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { summary: {} } } });
        const matrix = await complianceApi.getControls();
        expect(matrix.controls).toEqual([]);
    });

    it('defaults every control field, including per-framework arrays, when a control is sparse', async () => {
        mock.get.mockResolvedValueOnce({
            data: { data: { controls: [{ id: 'c2' }] } },
        });
        const matrix = await complianceApi.getControls();
        expect(matrix.controls[0]).toEqual({
            id: 'c2',
            name: '',
            area: '',
            status: 'not_configured',
            detail: '',
            frameworks: { iso27001: [], soc2: [], nis2: [], dora: [], ens: [] },
        });
    });

    it('falls back to response.data when there is no data.data wrapper', async () => {
        mock.get.mockResolvedValueOnce({ data: { generated_at: '2026-03-01T00:00:00Z', controls: [] } });
        const matrix = await complianceApi.getControls();
        expect(matrix.generatedAt).toBe('2026-03-01T00:00:00Z');
    });
});

// ── getRiskExceptions ────────────────────────────────────────────────────────

describe('complianceApi.getRiskExceptions', () => {
    it('reads exceptions from the data.data.exceptions wrapper', async () => {
        mock.get.mockResolvedValueOnce({
            data: { data: { exceptions: [{ id: 1, title: 'Legacy key', status: 'active' }] } },
        });
        const exceptions = await complianceApi.getRiskExceptions();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/risk-exceptions');
        expect(exceptions).toHaveLength(1);
        expect(exceptions[0]).toMatchObject({ id: 1, title: 'Legacy key', status: 'active' });
    });

    it('falls back to the data.exceptions wrapper', async () => {
        mock.get.mockResolvedValueOnce({ data: { exceptions: [{ id: 2, title: 'Old cert' }] } });
        const exceptions = await complianceApi.getRiskExceptions();
        expect(exceptions[0]?.id).toBe(2);
    });

    it('returns [] when neither wrapper is present', async () => {
        mock.get.mockResolvedValueOnce({ data: {} });
        await expect(complianceApi.getRiskExceptions()).resolves.toEqual([]);
    });

    it('defaults id and title when a sparse exception omits them', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { exceptions: [{ status: 'expired' }] } } });
        const exceptions = await complianceApi.getRiskExceptions();
        expect(exceptions[0]).toMatchObject({ id: 0, title: '', status: 'expired' });
    });
});

// ── getDigest ─────────────────────────────────────────────────────────────────

describe('complianceApi.getDigest', () => {
    it('returns the digest title and body', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { title: 'Weekly digest', body: 'All clear.' } } });
        const digest = await complianceApi.getDigest();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/compliance/digest');
        expect(digest).toEqual({ title: 'Weekly digest', body: 'All clear.' });
    });

    it('defaults to empty strings when fields are missing', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: {} } });
        await expect(complianceApi.getDigest()).resolves.toEqual({ title: '', body: '' });
    });

    it('falls back to response.data when there is no data.data wrapper', async () => {
        mock.get.mockResolvedValueOnce({ data: { title: 'Fallback digest', body: 'From bare data.' } });
        await expect(complianceApi.getDigest()).resolves.toEqual({ title: 'Fallback digest', body: 'From bare data.' });
    });
});

// ── createRiskException ──────────────────────────────────────────────────────

describe('complianceApi.createRiskException', () => {
    it('POSTs the risk exception with a snake_case expires_at field', async () => {
        mock.post.mockResolvedValueOnce({ data: {} });
        await complianceApi.createRiskException({
            title: 'Legacy key',
            category: 'other',
            reference: 'JIRA-1',
            justification: 'vendor constraint',
            expiresAt: '2026-06-01T00:00:00Z',
        });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/risk-exceptions', {
            title: 'Legacy key',
            category: 'other',
            reference: 'JIRA-1',
            justification: 'vendor constraint',
            expires_at: '2026-06-01T00:00:00Z',
        });
    });
});

// ── revokeRiskException ──────────────────────────────────────────────────────

describe('complianceApi.revokeRiskException', () => {
    it('DELETEs the exception by id', async () => {
        mock.delete.mockResolvedValueOnce({ data: {} });
        await complianceApi.revokeRiskException(9);
        expect(mock.delete).toHaveBeenCalledWith('/api/v1/risk-exceptions/9');
    });
});

// ── legal hold ────────────────────────────────────────────────────────────────

describe('complianceApi legal hold', () => {
    it('placeLegalHold POSTs the reason', async () => {
        mock.post.mockResolvedValueOnce({ data: {} });
        await complianceApi.placeLegalHold('litigation');
        expect(mock.post).toHaveBeenCalledWith('/api/v1/legal-hold', { reason: 'litigation' });
    });

    it('liftLegalHold DELETEs the hold', async () => {
        mock.delete.mockResolvedValueOnce({ data: {} });
        await complianceApi.liftLegalHold();
        expect(mock.delete).toHaveBeenCalledWith('/api/v1/legal-hold');
    });
});

// ── getSoDViolations ──────────────────────────────────────────────────────────

describe('complianceApi.getSoDViolations', () => {
    it('reads violations from the data.data.violations wrapper', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                data: {
                    violations: [
                        {
                            policy_name: 'Segregation',
                            username: 'bob',
                            permission_a: 'secrets.write',
                            permission_b: 'secrets.approve',
                        },
                    ],
                },
            },
        });
        const violations = await complianceApi.getSoDViolations();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/sod/violations');
        expect(violations[0]).toEqual({
            policyName: 'Segregation',
            username: 'bob',
            email: undefined,
            permissionA: 'secrets.write',
            permissionB: 'secrets.approve',
        });
    });

    it('falls back to the data.violations wrapper', async () => {
        mock.get.mockResolvedValueOnce({ data: { violations: [{ username: 'alice' }] } });
        const violations = await complianceApi.getSoDViolations();
        expect(violations[0]?.username).toBe('alice');
    });

    it('returns [] when neither wrapper is present', async () => {
        mock.get.mockResolvedValueOnce({ data: {} });
        await expect(complianceApi.getSoDViolations()).resolves.toEqual([]);
    });
});
