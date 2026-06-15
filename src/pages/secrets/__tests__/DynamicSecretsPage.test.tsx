import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import DynamicSecretsPage from '../DynamicSecretsPage';

const classifyMutate = vi.fn();
let isAdmin = true;

vi.mock('../../../features/projects', () => ({
    useProjects: () => ({ data: [{ id: 1, name: 'platform' }] }),
    useProjectEnvironments: () => ({ data: [{ id: 2, name: 'prod' }] }),
}));

vi.mock('../../../features/auth', () => ({
    useAuth: () => ({ isAdmin }),
}));

vi.mock('../../../features/dynamic-secrets/api', () => ({
    useDynamicConfigs: () => ({
        data: [
            { id: 5, name: 'analytics-ro', backendType: 'postgres', defaultTtlSeconds: 3600, maxTtlSeconds: 0, classification: 'confidential' },
        ],
        isLoading: false,
        error: null,
    }),
    useCreateDynamicConfig: () => ({ mutate: vi.fn(), isPending: false }),
    useClassifyDynamicConfig: () => ({ mutate: classifyMutate, isPending: false }),
}));

// LeasesPanel isn't rendered until a config is expanded, but stub its hooks defensively.
vi.mock('../../../features/dynamic-secrets/LeasesPanel', () => ({
    LeasesPanel: () => null,
}));

beforeEach(() => {
    classifyMutate.mockClear();
    isAdmin = true;
});

describe('DynamicSecretsPage', () => {
    it('lists configs and, for admins, offers a classification picker + create', () => {
        render(<DynamicSecretsPage />);
        expect(screen.getByText('analytics-ro')).toBeInTheDocument();
        expect(screen.getByText(/postgres/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /new config/i })).toBeInTheDocument();

        const picker = screen.getByLabelText('Classification for analytics-ro') as HTMLSelectElement;
        expect(picker.value).toBe('confidential');
    });

    it('the create form adapts to cloud backends (JSON config; session policy / no template)', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));

        // Default DB backend → admin connection string + SQL creation template.
        expect(screen.getByLabelText('Admin connection string')).toBeInTheDocument();

        // aws-sts → cloud config JSON + STS session policy (template repurposed).
        fireEvent.change(screen.getByLabelText('Backend'), { target: { value: 'aws-sts' } });
        expect(screen.getByLabelText('Cloud config (JSON)')).toBeInTheDocument();
        expect(screen.queryByLabelText('Admin connection string')).not.toBeInTheDocument();
        expect(screen.getByLabelText(/STS session policy/)).toBeInTheDocument();

        // gcp → cloud config JSON, no creation template at all.
        fireEvent.change(screen.getByLabelText('Backend'), { target: { value: 'gcp' } });
        expect(screen.getByLabelText('Cloud config (JSON)')).toBeInTheDocument();
        expect(screen.queryByLabelText(/session policy|Creation template/)).not.toBeInTheDocument();
    });

    it('non-admins see a read-only classification badge and no create button', () => {
        isAdmin = false;
        render(<DynamicSecretsPage />);
        expect(screen.getByTestId('dsc-classification-badge')).toHaveTextContent('Confidential');
        expect(screen.queryByRole('button', { name: /new config/i })).not.toBeInTheDocument();
        expect(screen.queryByLabelText('Classification for analytics-ro')).not.toBeInTheDocument();
    });
});
