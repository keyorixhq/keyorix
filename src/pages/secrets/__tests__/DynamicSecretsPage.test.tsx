import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act } from '../../../test/test-utils';
import DynamicSecretsPage from '../DynamicSecretsPage';

const classifyMutate = vi.fn();
const createConfigMutate = vi.fn();
let isAdmin = true;

const baseConfig = {
    id: 5,
    name: 'analytics-ro',
    backendType: 'postgres',
    defaultTtlSeconds: 3600,
    maxTtlSeconds: 0,
    classification: 'confidential' as string | undefined,
};

let configsData: (typeof baseConfig)[] = [baseConfig];
let configsLoading = false;
let configsError: unknown = null;
let environmentsData: { id: number; name: string }[] = [{ id: 2, name: 'prod' }];

vi.mock('../../../features/projects', () => ({
    useProjects: () => ({ data: [{ id: 1, name: 'platform' }] }),
    useProjectEnvironments: () => ({ data: environmentsData }),
}));

vi.mock('../../../features/auth', () => ({
    useAuth: () => ({ isAdmin }),
}));

vi.mock('../../../features/dynamic-secrets/api', () => ({
    useDynamicConfigs: () => ({
        data: configsData,
        isLoading: configsLoading,
        error: configsError,
    }),
    useCreateDynamicConfig: () => ({ mutate: createConfigMutate, isPending: false }),
    useClassifyDynamicConfig: () => ({ mutate: classifyMutate, isPending: false }),
}));

// LeasesPanel has its own dedicated coverage; here it's stubbed to a marker element so
// page-level tests can assert *composition* (is it mounted, with which props) without
// depending on its internals.
const leasesPanelSpy = vi.fn((props: { configId: number; canManage: boolean }) => (
    <div data-testid="leases-panel-stub" data-config-id={props.configId} data-can-manage={String(props.canManage)} />
));
vi.mock('../../../features/dynamic-secrets/LeasesPanel', () => ({
    LeasesPanel: (props: { configId: number; canManage: boolean }) => leasesPanelSpy(props),
}));

beforeEach(() => {
    classifyMutate.mockClear();
    createConfigMutate.mockClear();
    leasesPanelSpy.mockClear();
    isAdmin = true;
    configsData = [baseConfig];
    configsLoading = false;
    configsError = null;
    environmentsData = [{ id: 2, name: 'prod' }];
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

    it('shows an empty-state message when there are no configs in scope', () => {
        configsData = [];
        render(<DynamicSecretsPage />);
        expect(screen.getByText('No dynamic-secret configs in this scope yet.')).toBeInTheDocument();
    });

    it('shows a spinner instead of the list while configs are loading', () => {
        configsLoading = true;
        render(<DynamicSecretsPage />);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
        expect(screen.queryByText('analytics-ro')).not.toBeInTheDocument();
    });

    it('shows an error alert instead of the list when the configs query fails', () => {
        configsError = new Error('network down');
        render(<DynamicSecretsPage />);
        expect(
            screen.getByText('Failed to load dynamic-secret configs (you may lack secrets.read on this scope).')
        ).toBeInTheDocument();
        expect(screen.queryByText('analytics-ro')).not.toBeInTheDocument();
    });

    it('appends the "max Ns" suffix only when a max TTL is configured', () => {
        configsData = [{ ...baseConfig, maxTtlSeconds: 7200 }];
        render(<DynamicSecretsPage />);
        expect(screen.getByText(/default 3600s · max 7200s/)).toBeInTheDocument();
    });

    it('expanding a config mounts the leases panel with its scope; collapsing unmounts it', () => {
        render(<DynamicSecretsPage />);
        const toggle = screen.getByRole('button', { name: 'Toggle leases for analytics-ro' });
        expect(screen.queryByTestId('leases-panel-stub')).not.toBeInTheDocument();

        fireEvent.click(toggle);
        const stub = screen.getByTestId('leases-panel-stub');
        expect(stub).toHaveAttribute('data-config-id', '5');
        expect(stub).toHaveAttribute('data-can-manage', 'true');

        fireEvent.click(toggle);
        expect(screen.queryByTestId('leases-panel-stub')).not.toBeInTheDocument();
    });

    it('treats a config with no classification as unclassified for the admin picker, defaulting the reclassify baseline too', () => {
        configsData = [{ ...baseConfig, classification: undefined }];
        render(<DynamicSecretsPage />);
        const picker = screen.getByLabelText('Classification for analytics-ro') as HTMLSelectElement;
        expect(picker.value).toBe('');

        // current classification falls back to '' (unclassified), so picking a real
        // level counts as a change and should reclassify.
        fireEvent.change(picker, { target: { value: 'public' } });
        expect(classifyMutate).toHaveBeenCalledWith({ id: 5, classification: 'public' });
    });

    it('treats a config with no classification as unclassified for the read-only badge', () => {
        isAdmin = false;
        configsData = [{ ...baseConfig, classification: undefined }];
        render(<DynamicSecretsPage />);
        expect(screen.getByTestId('dsc-classification-badge')).toHaveTextContent('Unclassified');
    });

    it('reclassifying to a new value calls classify.mutate; picking the same value is a no-op', () => {
        render(<DynamicSecretsPage />);
        const picker = screen.getByLabelText('Classification for analytics-ro');

        fireEvent.change(picker, { target: { value: 'confidential' } });
        expect(classifyMutate).not.toHaveBeenCalled();

        fireEvent.change(picker, { target: { value: 'restricted' } });
        expect(classifyMutate).toHaveBeenCalledWith({ id: 5, classification: 'restricted' });
    });

    it('has no environment options and does not crash when the scoped project has none configured', () => {
        environmentsData = [];
        render(<DynamicSecretsPage />);
        expect(screen.getByLabelText('Environment')).toBeInTheDocument();
        expect(screen.queryByText('prod')).not.toBeInTheDocument();
    });

    it('changing the project and environment selects updates the scoped selection', () => {
        render(<DynamicSecretsPage />);
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '1' } });
        fireEvent.change(screen.getByLabelText('Environment'), { target: { value: '2' } });
        expect((screen.getByLabelText('Project') as HTMLSelectElement).value).toBe('1');
        expect((screen.getByLabelText('Environment') as HTMLSelectElement).value).toBe('2');
    });

    it('cancelling the create-config modal closes it without creating anything', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));
        expect(screen.getByRole('heading', { name: 'New dynamic-secret config' })).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByRole('heading', { name: 'New dynamic-secret config' })).not.toBeInTheDocument();
        expect(createConfigMutate).not.toHaveBeenCalled();
    });

    it('shows a validation error and does not submit when required fields are missing (non-cloud backend)', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Create' }));

        expect(screen.getByText('Name and admin connection string are required.')).toBeInTheDocument();
        expect(createConfigMutate).not.toHaveBeenCalled();
    });

    it('shows the cloud-specific validation message when a cloud backend is missing required fields', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));
        fireEvent.change(screen.getByLabelText('Backend'), { target: { value: 'gcp' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create' }));

        expect(screen.getByText('Name and cloud config (JSON) are required.')).toBeInTheDocument();
        expect(createConfigMutate).not.toHaveBeenCalled();
    });

    it('submits the create form with the expected payload and closes the modal on success', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));

        fireEvent.change(screen.getByLabelText('Name'), { target: { value: '  analytics-readonly  ' } });
        fireEvent.change(screen.getByLabelText('Admin connection string'), {
            target: { value: 'postgres://admin:pw@host:5432/db' },
        });
        fireEvent.change(screen.getByLabelText(/Creation template/), {
            target: { value: 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";' },
        });
        fireEvent.change(screen.getByLabelText('Default TTL (seconds)'), { target: { value: '1800' } });
        fireEvent.change(screen.getByLabelText('Max TTL (seconds, 0 = no cap)'), { target: { value: '900' } });
        fireEvent.change(screen.getByLabelText('Classification'), { target: { value: 'internal' } });

        fireEvent.click(screen.getByRole('button', { name: 'Create' }));

        expect(createConfigMutate).toHaveBeenCalledWith(
            {
                name: 'analytics-readonly',
                projectId: 1,
                environmentId: 2,
                backendType: 'postgres',
                adminDsn: 'postgres://admin:pw@host:5432/db',
                creationTemplate: 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";',
                defaultTtlSeconds: 1800,
                maxTtlSeconds: 900,
                classification: 'internal',
            },
            expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) })
        );

        const onSuccess = createConfigMutate.mock.calls[0]![1].onSuccess;
        act(() => onSuccess());
        expect(screen.queryByRole('heading', { name: 'New dynamic-secret config' })).not.toBeInTheDocument();
    });

    it('typing into the cloud config JSON field updates its value', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));
        fireEvent.change(screen.getByLabelText('Backend'), { target: { value: 'aws-sts' } });

        const cloudConfig = screen.getByLabelText('Cloud config (JSON)') as HTMLTextAreaElement;
        fireEvent.change(cloudConfig, { target: { value: '{"json":"config"}' } });
        expect(cloudConfig.value).toBe('{"json":"config"}');
    });

    it('shows the API-provided message when the create mutation fails', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'x' } });
        fireEvent.change(screen.getByLabelText('Admin connection string'), { target: { value: 'postgres://x' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create' }));

        const onError = createConfigMutate.mock.calls[0]![1].onError;
        act(() => onError({ response: { data: { message: 'name already taken' } } }));
        expect(screen.getByText('name already taken')).toBeInTheDocument();
    });

    it('falls back to the response error field when no message is present', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'x' } });
        fireEvent.change(screen.getByLabelText('Admin connection string'), { target: { value: 'postgres://x' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create' }));

        const onError = createConfigMutate.mock.calls[0]![1].onError;
        act(() => onError({ response: { data: { error: 'quota exceeded' } } }));
        expect(screen.getByText('quota exceeded')).toBeInTheDocument();
    });

    it('falls back to a generic message when the API gives neither a message nor an error field', () => {
        render(<DynamicSecretsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new config/i }));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'x' } });
        fireEvent.change(screen.getByLabelText('Admin connection string'), { target: { value: 'postgres://x' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create' }));

        const onError = createConfigMutate.mock.calls[0]![1].onError;
        act(() => onError(new Error('network exploded')));
        expect(screen.getByText('Failed to create config.')).toBeInTheDocument();
    });
});
