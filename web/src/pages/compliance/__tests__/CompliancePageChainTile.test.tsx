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
