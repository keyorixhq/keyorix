import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { CompliancePage } from '../CompliancePage';
import { complianceApi } from '../../../services/compliance';

vi.mock('../../../services/compliance', () => ({
    complianceApi: {
        getPosture: vi.fn(),
        getControls: vi.fn(),
        getSoDViolations: vi.fn(),
        getDigest: vi.fn(),
        placeLegalHold: vi.fn(),
        liftLegalHold: vi.fn(),
        getRiskExceptions: vi.fn(),
        createRiskException: vi.fn(),
        revokeRiskException: vi.fn(),
    },
}));

vi.mock('../../../services/client', () => ({
    apiClient: { get: vi.fn() },
}));

// #4186: the tile showed "13 chained events" while `audit verify` said 259. It now
// names the head id and the last-checked time, and says how many events are newer.
const posture = (audit: Record<string, unknown>) => ({
    generatedAt: '2026-11-12T10:00:00Z',
    auditIntegrity: { chainVerified: true, chainedEvents: 13, checkpointed: true, ...audit },
    accessGovernance: {
        projects: 4,
        projectsWithOpenCampaign: 1,
        projectsNeverReviewed: 1,
        openCampaigns: 1,
        pendingItems: 3,
        projectsOverdue: 0,
        dormantRoleGrants: 0,
        sodViolations: 0,
    },
    rotation: { coveredSecrets: 10, overdue: 0, dueSoon: 0 },
    identity: { activeUsers: 5, usersWithSecondFactor: 5, secondFactorPercent: 100 },
    emergencyAccess: { activeActivations: 0, totalActivations: 0 },
    classification: { totalSecrets: 12, public: 0, internal: 0, confidential: 0, restricted: 0, unclassified: 12 },
    anomalies: { unacknowledged: 0, highSeverityOpen: 0 },
    legalHold: { active: false, reason: '' },
    retention: {
        enabled: false,
        anomalyAlertsDays: 0,
        closedAccessReviewsDays: 0,
        breakGlassDays: 0,
        resolvedAccessRequestsDays: 0,
    },
});

describe('CompliancePage audit chain tile', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        (complianceApi.getSoDViolations as any).mockResolvedValue([]);
        (complianceApi.getControls as any).mockResolvedValue({
            generatedAt: '2026-11-12T10:00:00Z',
            summary: { total: 0, pass: 0, gap: 0, notConfigured: 0 },
            controls: [],
        });
        (complianceApi.getRiskExceptions as any).mockResolvedValue([]);
        (complianceApi.getDigest as any).mockRejectedValue({ response: { status: 403 } });
    });

    it('shows the head id, the verified count, the check time and the unverified events', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(
            posture({
                headId: 13,
                lastCheckedAt: '2026-11-12T09:00:00Z',
                stale: true,
                latestEventId: 259,
                eventsSinceCheck: 246,
            })
        );
        render(<CompliancePage />);

        expect(await screen.findByText('#13')).toBeInTheDocument();
        expect(screen.getByText('Chain head, 13 events verified')).toBeInTheDocument();
        expect(screen.getByText('Chain last checked')).toBeInTheDocument();
        expect(screen.getByText('246')).toBeInTheDocument();
        expect(screen.getByText(/newest #259\), not yet verified/)).toBeInTheDocument();
        // An id difference: Postgres sequence gaps make it an upper bound (REVIEW-4192-DEEP-1 LOW).
        expect(screen.getByText(/^Up to this many events after the last check/)).toBeInTheDocument();
    });

    it('shows no "newer events" tile when the check is current', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(
            posture({ headId: 13, lastCheckedAt: '2026-11-12T09:59:30Z' })
        );
        render(<CompliancePage />);

        expect(await screen.findByText('#13')).toBeInTheDocument();
        expect(screen.queryByText(/not yet verified/)).not.toBeInTheDocument();
    });
});

// REVIEW-4192-DEEP-1 MEDIUM-1: head_id and events_since_check are also filled when the
// last check failed (broken), when the chain is sealed and when it is not proven. The
// tile must then not say the events were verified.
describe('CompliancePage audit chain tile when the chain is not verified', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        (complianceApi.getSoDViolations as any).mockResolvedValue([]);
        (complianceApi.getControls as any).mockResolvedValue({
            generatedAt: '2026-11-12T10:00:00Z',
            summary: { total: 0, pass: 0, gap: 0, notConfigured: 0 },
            controls: [],
        });
        (complianceApi.getRiskExceptions as any).mockResolvedValue([]);
        (complianceApi.getDigest as any).mockRejectedValue({ response: { status: 403 } });
    });

    const notVerified = (status: string) =>
        posture({
            chainVerified: false,
            verificationStatus: status,
            headId: 13,
            lastCheckedAt: '2026-11-12T09:00:00Z',
            stale: true,
            latestEventId: 259,
            eventsSinceCheck: 246,
        });

    it.each(['broken', 'sealed'])('a %s chain shows the head as not verified, in the bad tone', async (status) => {
        (complianceApi.getPosture as any).mockResolvedValue(notVerified(status));
        render(<CompliancePage />);

        const head = await screen.findByText('#13');
        expect(screen.queryByText(/events verified/)).not.toBeInTheDocument();
        expect(screen.getByText('Chain head at last check (not verified)')).toBeInTheDocument();
        expect(head.getAttribute('style')).toContain('var(--error)');
        expect(screen.getByText('246').getAttribute('style')).toContain('var(--error)');
    });

    it('a not-proven chain shows the head as not verified, in the warn tone', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...notVerified('not_proven'),
            auditIntegrity: { ...notVerified('not_proven').auditIntegrity, chainVerified: true },
        });
        render(<CompliancePage />);

        const head = await screen.findByText('#13');
        expect(screen.queryByText(/events verified/)).not.toBeInTheDocument();
        expect(screen.getByText('Chain head at last check (not verified)')).toBeInTheDocument();
        expect(head.getAttribute('style')).toContain('var(--warning)');
    });

    it('a valid chain keeps the verified wording and the neutral head tone', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(
            posture({ verificationStatus: 'valid', headId: 13, eventsSinceCheck: 246, latestEventId: 259 })
        );
        render(<CompliancePage />);

        const head = await screen.findByText('#13');
        expect(screen.getByText('Chain head, 13 events verified')).toBeInTheDocument();
        expect(head.getAttribute('style')).toContain('var(--text-primary)');
        expect(screen.getByText('246').getAttribute('style')).toContain('var(--warning)');
    });
});
