import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { ProjectDriftTab } from '../ProjectDriftTab';

const mockUseProjectDrift = vi.fn();

vi.mock('../../../features/projects/api', () => ({
    useProjectDrift: (projectId: number) => mockUseProjectDrift(projectId),
}));

const threeEnvs = [
    { id: 1, name: 'development' },
    { id: 2, name: 'staging' },
    { id: 3, name: 'production' },
];

describe('ProjectDriftTab', () => {
    it('renders the summary and the drifted keys matrix', () => {
        mockUseProjectDrift.mockReturnValue({
            isLoading: false,
            isError: false,
            data: {
                projectId: 1,
                environments: threeEnvs,
                driftedKeys: [
                    { name: 'STRIPE_KEY', presentIn: [1, 2], missingFrom: [3], status: 'missing_in_some', driftFields: [] },
                    { name: 'JWT_SECRET', presentIn: [1, 2, 3], missingFrom: [], status: 'metadata_drift', driftFields: ['type', 'max_reads'] },
                ],
                summary: { environmentCount: 3, totalKeys: 3, consistentKeys: 1, missingInSome: 1, metadataDrift: 1 },
            },
        });

        render(<ProjectDriftTab projectId={1} />);

        expect(screen.getByText('STRIPE_KEY')).toBeInTheDocument();
        expect(screen.getByText('JWT_SECRET')).toBeInTheDocument();
        expect(screen.getByText('Missing')).toBeInTheDocument();
        // "Settings differ" appears both as a summary stat label and as the row badge.
        expect(screen.getAllByText('Settings differ').length).toBeGreaterThanOrEqual(2);
        // The diverging settings are named.
        expect(screen.getByText('type, max_reads')).toBeInTheDocument();
        // Environment columns are present.
        expect(screen.getByText('production')).toBeInTheDocument();
    });

    it('shows a clean state when there is no drift', () => {
        mockUseProjectDrift.mockReturnValue({
            isLoading: false,
            isError: false,
            data: {
                projectId: 1,
                environments: threeEnvs,
                driftedKeys: [],
                summary: { environmentCount: 3, totalKeys: 5, consistentKeys: 5, missingInSome: 0, metadataDrift: 0 },
            },
        });

        render(<ProjectDriftTab projectId={1} />);
        expect(screen.getByText(/No drift detected/i)).toBeInTheDocument();
    });

    it('prompts for a second environment when only one exists', () => {
        mockUseProjectDrift.mockReturnValue({
            isLoading: false,
            isError: false,
            data: {
                projectId: 1,
                environments: [{ id: 1, name: 'development' }],
                driftedKeys: [],
                summary: { environmentCount: 1, totalKeys: 2, consistentKeys: 2, missingInSome: 0, metadataDrift: 0 },
            },
        });

        render(<ProjectDriftTab projectId={1} />);
        expect(screen.getByText(/Need at least two environments/i)).toBeInTheDocument();
    });
});
