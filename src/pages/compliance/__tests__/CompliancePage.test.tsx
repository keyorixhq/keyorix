import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { CompliancePage } from '../CompliancePage';
import { complianceApi } from '../../../services/compliance';

vi.mock('../../../services/compliance', () => ({
    complianceApi: {
        getPosture: vi.fn(), getControls: vi.fn(), getSoDViolations: vi.fn(),
        placeLegalHold: vi.fn(), liftLegalHold: vi.fn(),
        getRiskExceptions: vi.fn(), createRiskException: vi.fn(), revokeRiskException: vi.fn(),
    },
}));

const emptyMatrix = { generatedAt: '2026-06-14T10:00:00Z', summary: { total: 0, pass: 0, gap: 0, notConfigured: 0 }, controls: [] };

const posture = {
    generatedAt: '2026-06-14T10:00:00Z',
    auditIntegrity: { chainVerified: true, chainedEvents: 12, checkpointed: true },
    accessGovernance: { projects: 4, projectsWithOpenCampaign: 1, projectsNeverReviewed: 1, openCampaigns: 1, pendingItems: 3, projectsOverdue: 7, dormantRoleGrants: 2, sodViolations: 1 },
    rotation: { coveredSecrets: 10, overdue: 1, dueSoon: 2 },
    identity: { activeUsers: 5, usersWithSecondFactor: 4, secondFactorPercent: 80 },
    emergencyAccess: { activeActivations: 0, totalActivations: 1 },
    classification: { totalSecrets: 12, public: 1, internal: 4, confidential: 1, restricted: 6, unclassified: 0 },
    anomalies: { unacknowledged: 3, highSeverityOpen: 1 },
    legalHold: { active: false, reason: '' },
    retention: { enabled: true, anomalyAlertsDays: 90, closedAccessReviewsDays: 730, breakGlassDays: 365, resolvedAccessRequestsDays: 0 },
};

describe('CompliancePage posture panel', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        (complianceApi.getSoDViolations as any).mockResolvedValue([]);
        (complianceApi.getControls as any).mockResolvedValue(emptyMatrix);
        (complianceApi.getRiskExceptions as any).mockResolvedValue([]);
    });

    it('renders the live posture tiles when the report loads', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        render(<CompliancePage />);

        expect(await screen.findByText('Controls posture')).toBeInTheDocument();
        expect(screen.getByText('80%')).toBeInTheDocument();        // second-factor coverage
        expect(screen.getByText('3/4')).toBeInTheDocument();        // projects reviewed
        expect(screen.getByText('2')).toBeInTheDocument();          // dormant role grants
        expect(screen.getByText('0 / 12')).toBeInTheDocument();     // unclassified / total secrets
        expect(screen.getByText('3 (1 high)')).toBeInTheDocument(); // open anomalies (1 high-severity)
        expect(screen.getByText('7')).toBeInTheDocument();          // projects overdue for recert
        // Data-retention section: configured windows, "Keep" for a 0 window.
        expect(screen.getByText(/Data retention .* enforced/i)).toBeInTheDocument();
        expect(screen.getByText('90d')).toBeInTheDocument();        // anomaly-alerts window
        expect(screen.getByText('Keep')).toBeInTheDocument();       // resolved-requests window = 0
        // The static regulatory cards still render below.
        expect(screen.getByText('NIS2 Directive')).toBeInTheDocument();
    });

    it('lists separation-of-duties violations when present', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getSoDViolations as any).mockResolvedValue([
            { policyName: 'approve-vs-admin', username: 'alice', email: 'a@x.io', permissionA: 'roles.assign', permissionB: 'secrets.delete' },
        ]);
        render(<CompliancePage />);

        expect(await screen.findByText(/Separation-of-duties violations \(1\)/i)).toBeInTheDocument();
        expect(screen.getByText('alice (a@x.io)')).toBeInTheDocument();
        expect(screen.getByText('roles.assign + secrets.delete')).toBeInTheDocument();
    });

    it('shows a legal-hold banner when a hold is active', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({ ...posture, legalHold: { active: true, reason: 'litigation INC-7' } });
        render(<CompliancePage />);
        expect(await screen.findByText(/Legal hold active/i)).toBeInTheDocument();
        expect(screen.getByText(/litigation INC-7/)).toBeInTheDocument();
    });

    it('shows an admin-only note when the caller lacks system.read (403)', async () => {
        (complianceApi.getPosture as any).mockRejectedValue({ response: { status: 403 } });
        render(<CompliancePage />);
        expect(await screen.findByText(/available to administrators/i)).toBeInTheDocument();
    });

    it('renders the control matrix with status and framework refs', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getControls as any).mockResolvedValue({
            generatedAt: '2026-06-14T10:00:00Z',
            summary: { total: 2, pass: 1, gap: 1, notConfigured: 0 },
            controls: [
                { id: 'sep', name: 'Separation of duties', area: 'Access governance', status: 'gap', detail: '1 SoD violation', frameworks: { iso27001: ['A.5.3'], soc2: ['CC5.1'], nis2: [], dora: ['Art.5'] } },
                { id: 'mfa', name: 'Second-factor coverage', area: 'Identity', status: 'pass', detail: '100% covered', frameworks: { iso27001: ['A.5.17'], soc2: [], nis2: [], dora: [] } },
            ],
        });
        render(<CompliancePage />);

        expect(await screen.findByText(/Control matrix/i)).toBeInTheDocument();
        expect(screen.getByText('1 pass · 1 gap · 0 n/a')).toBeInTheDocument();
        expect(screen.getByText(/Separation of duties/)).toBeInTheDocument();
        expect(screen.getByText('ISO A.5.3 · SOC2 CC5.1 · DORA Art.5')).toBeInTheDocument();
    });

    it('lists active risk exceptions in the register', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getRiskExceptions as any).mockResolvedValue([
            { id: 1, title: 'accept SoD during cutover', category: 'sod', reference: 'alice', justification: 'temporary', status: 'active', expiresAt: '2026-12-31T00:00:00Z', createdBy: 9 },
        ]);
        render(<CompliancePage />);

        expect(await screen.findByText(/Risk register .* 1 active exception/i)).toBeInTheDocument();
        expect(screen.getByText('accept SoD during cutover')).toBeInTheDocument();
        expect(screen.getByText('temporary')).toBeInTheDocument();
    });
});
