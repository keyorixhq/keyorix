import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { ProjectOverviewTab } from '../ProjectOverviewTab';

const mockUseProject = vi.fn();
const mockUseProjectMembers = vi.fn();
const mockUseProjectDrift = vi.fn();

vi.mock('../../../features/projects/api', () => ({
    useProject: (id: number) => mockUseProject(id),
    useProjectMembers: (id: number) => mockUseProjectMembers(id),
    useProjectDrift: (id: number) => mockUseProjectDrift(id),
}));

const project = {
    id: 1,
    name: 'my-project',
    description: 'A test project for secrets.',
    secretCount: 7,
    environmentCount: 4,
    createdAt: '2026-01-01T00:00:00Z',
};

const members = [
    { userId: 1, username: 'alice', displayName: 'Alice', email: 'alice@x.io', roleId: 1, roleName: 'project_admin' },
    { userId: 2, username: 'bob', displayName: 'Bob', email: 'bob@x.io', roleId: 2, roleName: 'project_developer' },
];

const threeEnvNoDrift = {
    projectId: 1,
    environments: [{ id: 1, name: 'dev' }, { id: 2, name: 'staging' }, { id: 3, name: 'prod' }],
    driftedKeys: [],
    summary: { environmentCount: 3, totalKeys: 7, consistentKeys: 7, missingInSome: 0, metadataDrift: 0 },
};

describe('ProjectOverviewTab', () => {
    it('renders stat cards, description, created date, and sync banner', () => {
        mockUseProject.mockReturnValue({ data: project, isLoading: false });
        mockUseProjectMembers.mockReturnValue({ data: members, isLoading: false });
        mockUseProjectDrift.mockReturnValue({ data: threeEnvNoDrift, isLoading: false });

        render(<ProjectOverviewTab projectId={1} />);

        // Description and date
        expect(screen.getByText('A test project for secrets.')).toBeInTheDocument();
        expect(screen.getByText(/2026/)).toBeInTheDocument();

        // Stat card labels
        expect(screen.getByText('Secrets')).toBeInTheDocument();
        expect(screen.getByText('Environments')).toBeInTheDocument();
        expect(screen.getByText('Members')).toBeInTheDocument();

        // Stat card values
        expect(screen.getByText('7')).toBeInTheDocument();   // secretCount
        expect(screen.getByText('4')).toBeInTheDocument();   // environmentCount
        expect(screen.getByText('2')).toBeInTheDocument();   // members.length

        // Sync banner — no drift
        expect(screen.getByText(/All 3 environments in sync/)).toBeInTheDocument();
    });

    it('shows a warning banner listing drifted keys', () => {
        mockUseProject.mockReturnValue({ data: project, isLoading: false });
        mockUseProjectMembers.mockReturnValue({ data: [], isLoading: false });
        mockUseProjectDrift.mockReturnValue({
            data: {
                ...threeEnvNoDrift,
                driftedKeys: [
                    { name: 'STRIPE_KEY', presentIn: [1], missingFrom: [2, 3], status: 'missing_in_some', driftFields: [] },
                    { name: 'JWT_SECRET', presentIn: [1, 2, 3], missingFrom: [], status: 'metadata_drift', driftFields: ['type'] },
                ],
            },
            isLoading: false,
        });

        render(<ProjectOverviewTab projectId={1} />);

        expect(screen.getByText(/2 keys out of sync/)).toBeInTheDocument();
        expect(screen.getByText(/STRIPE_KEY/)).toBeInTheDocument();
        expect(screen.getByText(/missing in some environments/)).toBeInTheDocument();
        expect(screen.getByText(/JWT_SECRET/)).toBeInTheDocument();
        expect(screen.getByText(/settings differ/)).toBeInTheDocument();
        expect(screen.getByRole('link', { name: /View Drift/i })).toBeInTheDocument();
    });

    it('truncates the drifted key list beyond 5 and shows an overflow count', () => {
        const manyKeys = Array.from({ length: 8 }, (_, i) => ({
            name: `KEY_${i}`,
            presentIn: [1],
            missingFrom: [2],
            status: 'missing_in_some' as const,
            driftFields: [],
        }));

        mockUseProject.mockReturnValue({ data: project, isLoading: false });
        mockUseProjectMembers.mockReturnValue({ data: [], isLoading: false });
        mockUseProjectDrift.mockReturnValue({
            data: { ...threeEnvNoDrift, driftedKeys: manyKeys },
            isLoading: false,
        });

        render(<ProjectOverviewTab projectId={1} />);

        expect(screen.getByText(/8 keys out of sync/)).toBeInTheDocument();
        expect(screen.getByText('+3 more…')).toBeInTheDocument();
    });

    it('prompts for a second environment when fewer than two exist', () => {
        mockUseProject.mockReturnValue({ data: project, isLoading: false });
        mockUseProjectMembers.mockReturnValue({ data: [], isLoading: false });
        mockUseProjectDrift.mockReturnValue({
            data: {
                projectId: 1,
                environments: [{ id: 1, name: 'dev' }],
                driftedKeys: [],
                summary: { environmentCount: 1, totalKeys: 7, consistentKeys: 7, missingInSome: 0, metadataDrift: 0 },
            },
            isLoading: false,
        });

        render(<ProjectOverviewTab projectId={1} />);

        expect(screen.getByText(/Add at least two environments/)).toBeInTheDocument();
    });

    it('renders loading skeletons while data is fetching', () => {
        mockUseProject.mockReturnValue({ data: undefined, isLoading: true });
        mockUseProjectMembers.mockReturnValue({ data: [], isLoading: true });
        mockUseProjectDrift.mockReturnValue({ data: undefined, isLoading: true });

        const { container } = render(<ProjectOverviewTab projectId={1} />);

        expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
    });
});
