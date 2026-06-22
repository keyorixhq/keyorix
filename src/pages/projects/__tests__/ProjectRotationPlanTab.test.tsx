import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { ProjectRotationPlanTab } from '../ProjectRotationPlanTab';

const mockUseRotationPlan = vi.fn();

vi.mock('../../../features/projects/api', () => ({
    useProjectRotationPlan: (projectId: number) => mockUseRotationPlan(projectId),
}));

describe('ProjectRotationPlanTab', () => {
    it('renders waves, urgency badges, reasons, and the summary', () => {
        mockUseRotationPlan.mockReturnValue({
            isLoading: false,
            isError: false,
            data: {
                projectId: 1,
                totalSecrets: 3,
                overdueCount: 2,
                dueSoonCount: 1,
                waves: [
                    {
                        index: 0,
                        secrets: [
                            { secretId: 12, secretName: 'root-ca', status: 'overdue', daysOverdue: 110, riskScore: 78, riskBand: 'high', urgency: 1110, autoRotate: false, afterSecretIds: [], reasons: ['110 days overdue', 'high risk (score 78)'] },
                            { secretId: 13, secretName: 'metrics-key', status: 'due_soon', daysOverdue: -10, riskScore: 20, riskBand: 'low', urgency: 490, autoRotate: true, afterSecretIds: [], reasons: ['due in 10 days', 'self-rotating'] },
                        ],
                    },
                    {
                        index: 1,
                        secrets: [
                            { secretId: 11, secretName: 'app-token', status: 'overdue', daysOverdue: 30, riskScore: 40, riskBand: 'medium', urgency: 1030, autoRotate: false, afterSecretIds: [12], reasons: ['30 days overdue', 'rotate after root-ca'] },
                        ],
                    },
                ],
            },
        });

        render(<ProjectRotationPlanTab projectId={1} />);

        // Summary stats.
        expect(screen.getByText('To rotate')).toBeInTheDocument();
        // Both waves are labelled (1-indexed for humans).
        expect(screen.getByText('Wave 1')).toBeInTheDocument();
        expect(screen.getByText('Wave 2')).toBeInTheDocument();
        // Secrets and their status badges.
        expect(screen.getByText('root-ca')).toBeInTheDocument();
        expect(screen.getByText('110d overdue')).toBeInTheDocument();
        expect(screen.getByText('due in 10d')).toBeInTheDocument();
        // Reasons (including the dependency ordering) are shown.
        expect(screen.getByText(/rotate after root-ca/)).toBeInTheDocument();
        // Self-rotating marker (appears as the badge and in the reasons line).
        expect(screen.getAllByText(/self-rotating/).length).toBeGreaterThanOrEqual(1);
    });

    it('shows a clean state when nothing needs rotation', () => {
        mockUseRotationPlan.mockReturnValue({
            isLoading: false,
            isError: false,
            data: { projectId: 1, totalSecrets: 0, overdueCount: 0, dueSoonCount: 0, waves: [] },
        });

        render(<ProjectRotationPlanTab projectId={1} />);
        expect(screen.getByText(/Nothing to rotate/i)).toBeInTheDocument();
    });

    it('renders an error state', () => {
        mockUseRotationPlan.mockReturnValue({ isLoading: false, isError: true, data: undefined });
        render(<ProjectRotationPlanTab projectId={1} />);
        expect(screen.getByText(/Failed to load the rotation plan/i)).toBeInTheDocument();
    });
});
