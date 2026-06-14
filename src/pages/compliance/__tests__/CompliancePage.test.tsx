import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { CompliancePage } from '../CompliancePage';
import { complianceApi } from '../../../services/compliance';

vi.mock('../../../services/compliance', () => ({
    complianceApi: { getPosture: vi.fn(), getSoDViolations: vi.fn() },
}));

const posture = {
    generatedAt: '2026-06-14T10:00:00Z',
    auditIntegrity: { chainVerified: true, chainedEvents: 12, checkpointed: true },
    accessGovernance: { projects: 4, projectsWithOpenCampaign: 1, projectsNeverReviewed: 1, openCampaigns: 1, pendingItems: 3, dormantRoleGrants: 2, sodViolations: 1 },
    rotation: { coveredSecrets: 10, overdue: 1, dueSoon: 2 },
    identity: { activeUsers: 5, usersWithSecondFactor: 4, secondFactorPercent: 80 },
    emergencyAccess: { activeActivations: 0, totalActivations: 1 },
    classification: { totalSecrets: 12, public: 1, internal: 4, confidential: 1, restricted: 6, unclassified: 0 },
    anomalies: { unacknowledged: 3, highSeverityOpen: 1 },
};

describe('CompliancePage posture panel', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        (complianceApi.getSoDViolations as any).mockResolvedValue([]);
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

    it('shows an admin-only note when the caller lacks system.read (403)', async () => {
        (complianceApi.getPosture as any).mockRejectedValue({ response: { status: 403 } });
        render(<CompliancePage />);
        expect(await screen.findByText(/available to administrators/i)).toBeInTheDocument();
    });
});
