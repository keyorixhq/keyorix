import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within, waitFor, act } from '../../../test/test-utils';
import { RotationPoliciesPage } from '../RotationPoliciesPage';

const { createMutate, updateMutate, deleteMutate, refetchMock, deleteResetMock } = vi.hoisted(() => ({
    createMutate: vi.fn(),
    updateMutate: vi.fn(),
    deleteMutate: vi.fn(),
    refetchMock: vi.fn(),
    deleteResetMock: vi.fn(),
}));

const { envListMock, projListMock } = vi.hoisted(() => ({
    envListMock: vi.fn(),
    projListMock: vi.fn(),
}));

const policiesState = vi.hoisted(() => ({
    policies: [] as any[],
    isLoading: false,
    error: null as unknown,
    evaluations: [] as any[],
    evalLoading: false,
    createMutation: { isPending: false },
    updateMutation: { isPending: false },
    deleteMutation: { isPending: false, isError: false, error: null as unknown },
}));

vi.mock('../../../features/secrets/useRotationPolicies', () => ({
    useRotationPolicies: () => ({
        policies: policiesState.policies,
        isLoading: policiesState.isLoading,
        error: policiesState.error,
        refetch: refetchMock,
    }),
    useRotationPolicyEvaluations: () => ({
        evaluations: policiesState.evaluations,
        isLoading: policiesState.evalLoading,
    }),
    useCreateRotationPolicy: () => ({ mutate: createMutate, ...policiesState.createMutation }),
    useUpdateRotationPolicy: () => ({ mutate: updateMutate, ...policiesState.updateMutation }),
    useDeleteRotationPolicy: () => ({ mutate: deleteMutate, reset: deleteResetMock, ...policiesState.deleteMutation }),
}));

vi.mock('../../../services/environments', () => ({
    environmentsApi: { list: () => envListMock() },
}));

vi.mock('../../../services/projects', () => ({
    projectsApi: { list: () => projListMock() },
}));

const envFixture = [{ id: 2, name: 'prod-env' }];
const projFixture = [{ id: 5, name: 'proj-x' }];

const policiesFixture = [
    {
        id: 1,
        name: 'DB Rotation Policy',
        description: 'Rotate prod db creds',
        scope: 'environment' as const,
        environment_id: 2,
        project_id: null,
        interval_days: 90,
        alert_days_before: 14,
        notify_on_breach: true,
        is_active: true,
        created_by: 'alice@co',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
    },
    {
        id: 2,
        name: 'API Token Policy',
        description: '',
        scope: 'project' as const,
        project_id: 5,
        environment_id: null,
        interval_days: 30,
        alert_days_before: 7,
        notify_on_breach: false,
        is_active: false,
        created_by: 'bob@co',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
    },
];

const evaluationsFixture = [
    {
        policy_id: 1,
        policy_name: 'DB Rotation Policy',
        secret_id: 10,
        secret_name: 'db-password',
        last_rotated_at: '2026-01-01T00:00:00Z',
        days_overdue: 5,
        is_overdue: true,
        is_approaching: false,
    },
    {
        policy_id: 2,
        policy_name: 'API Token Policy',
        secret_id: 11,
        secret_name: 'api-token',
        last_rotated_at: null,
        days_overdue: 2,
        is_overdue: false,
        is_approaching: true,
    },
    {
        policy_id: 1,
        policy_name: 'DB Rotation Policy',
        secret_id: 12,
        secret_name: 'healthy-secret',
        last_rotated_at: '2026-06-01T00:00:00Z',
        days_overdue: 0,
        is_overdue: false,
        is_approaching: false,
    },
];

function resetState() {
    policiesState.policies = [];
    policiesState.isLoading = false;
    policiesState.error = null;
    policiesState.evaluations = [];
    policiesState.evalLoading = false;
    policiesState.createMutation = { isPending: false };
    policiesState.updateMutation = { isPending: false };
    policiesState.deleteMutation = { isPending: false, isError: false, error: null };
}

beforeEach(() => {
    vi.clearAllMocks();
    resetState();
    envListMock.mockResolvedValue([]);
    projListMock.mockResolvedValue([]);
});

describe('RotationPoliciesPage — policies list', () => {
    it('shows a loading indicator while policies are loading', () => {
        policiesState.isLoading = true;
        render(<RotationPoliciesPage />);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('shows an empty state with a New Policy action when there are no policies', () => {
        render(<RotationPoliciesPage />);
        expect(screen.getByText('No rotation policies yet')).toBeInTheDocument();
        expect(screen.getAllByRole('button', { name: /New Policy/i }).length).toBeGreaterThanOrEqual(2);
    });

    it('shows an error state and retries', () => {
        policiesState.error = new Error('boom');
        render(<RotationPoliciesPage />);
        expect(screen.getByText('Failed to load rotation policies')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /retry/i }));
        expect(refetchMock).toHaveBeenCalled();
    });

    it('renders policy rows with scope, interval, alert, status and creator', async () => {
        envListMock.mockResolvedValue(envFixture);
        projListMock.mockResolvedValue(projFixture);
        policiesState.policies = policiesFixture;

        render(<RotationPoliciesPage />);

        await waitFor(() => expect(screen.getByText('Environment: prod-env')).toBeInTheDocument());
        expect(screen.getByText('Project: proj-x')).toBeInTheDocument();

        expect(screen.getByText('Every 90 days')).toBeInTheDocument();
        expect(screen.getByText('14 days before')).toBeInTheDocument();
        expect(screen.getByText('Every 30 days')).toBeInTheDocument();
        expect(screen.getByText('7 days before')).toBeInTheDocument();

        expect(screen.getByText('Active')).toBeInTheDocument();
        expect(screen.getByText('Inactive')).toBeInTheDocument();

        expect(screen.getByText('alice@co')).toBeInTheDocument();
        expect(screen.getByText('bob@co')).toBeInTheDocument();
    });

    it('falls back to a raw id when the environment/project name is not yet loaded', () => {
        // envListMock/projListMock resolve to [] by default, so envMap/projMap stay empty.
        policiesState.policies = policiesFixture;
        render(<RotationPoliciesPage />);
        expect(screen.getByText('Environment: #2')).toBeInTheDocument();
        expect(screen.getByText('Project: #5')).toBeInTheDocument();
    });
});

describe('RotationPoliciesPage — rotation status panel', () => {
    it('shows a loading indicator while evaluations are loading', () => {
        policiesState.evalLoading = true;
        render(<RotationPoliciesPage />);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('shows an all-clear message when there are no problem evaluations', () => {
        policiesState.evaluations = [];
        render(<RotationPoliciesPage />);
        expect(screen.getByText('All secrets are within rotation policy')).toBeInTheDocument();
        expect(screen.getByText('0 overdue')).toBeInTheDocument();
        expect(screen.getByText('0 approaching breach')).toBeInTheDocument();
        expect(screen.getByText('0 healthy')).toBeInTheDocument();
    });

    it('buckets evaluations into overdue/approaching/healthy and only lists problems', () => {
        policiesState.evaluations = evaluationsFixture;
        render(<RotationPoliciesPage />);

        expect(screen.getByText('1 overdue')).toBeInTheDocument();
        expect(screen.getByText('1 approaching breach')).toBeInTheDocument();
        expect(screen.getByText('1 healthy')).toBeInTheDocument();

        // Overdue + approaching secrets show up in the problem table.
        expect(screen.getByText('db-password')).toBeInTheDocument();
        expect(screen.getByText('Overdue')).toBeInTheDocument();
        expect(screen.getByText('5d')).toBeInTheDocument();
        expect(screen.getByText('api-token')).toBeInTheDocument();
        expect(screen.getByText('Due soon')).toBeInTheDocument();
        expect(screen.getByText('2d')).toBeInTheDocument();
        // No last-rotation date on the approaching secret renders as an em dash.
        expect(screen.getByText('—')).toBeInTheDocument();

        // The healthy secret is excluded from the problem table entirely.
        expect(screen.queryByText('healthy-secret')).not.toBeInTheDocument();
        expect(screen.queryByText('All secrets are within rotation policy')).not.toBeInTheDocument();
    });
});

describe('RotationPoliciesPage — create policy', () => {
    it('requires a name before submitting', () => {
        render(<RotationPoliciesPage />);
        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        // The <input> has an HTML5 `required` attribute, which jsdom enforces for a
        // genuinely empty value and would block the submit event before our handler
        // ever runs. Use a whitespace-only value to reach the JS-level trim() check.
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: '   ' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));
        expect(screen.getByText('Name is required.')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('requires an environment when scope is environment', () => {
        render(<RotationPoliciesPage />);
        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'New Policy Name' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));
        expect(screen.getByText('Environment is required.')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('requires a project when scope is project', () => {
        render(<RotationPoliciesPage />);
        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'New Policy Name' } });
        fireEvent.change(screen.getByLabelText(/^Scope/), { target: { value: 'project' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));
        expect(screen.getByText('Project is required.')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('rejects an alert window that is not less than the rotation interval', async () => {
        envListMock.mockResolvedValue(envFixture);
        render(<RotationPoliciesPage />);
        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'New Policy Name' } });
        await waitFor(() => expect(screen.getByText('prod-env')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText(/^Environment/), { target: { value: '2' } });
        fireEvent.change(screen.getByLabelText('Rotation interval'), { target: { value: '30' } });
        fireEvent.change(screen.getByLabelText('Alert before breach'), { target: { value: '30' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));
        expect(screen.getByText('Alert days must be less than the rotation interval.')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('submits an environment-scoped policy with the expected payload', async () => {
        envListMock.mockResolvedValue(envFixture);
        render(<RotationPoliciesPage />);

        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: '  New Policy  ' } });
        fireEvent.change(screen.getByLabelText('Description'), { target: { value: '  desc  ' } });
        await waitFor(() => expect(screen.getByText('prod-env')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText(/^Environment/), { target: { value: '2' } });
        fireEvent.click(screen.getByLabelText('Notify on breach'));
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));

        expect(createMutate).toHaveBeenCalledWith(
            {
                name: 'New Policy',
                description: 'desc',
                scope: 'environment',
                environment_id: 2,
                project_id: null,
                interval_days: 90,
                alert_days_before: 14,
                notify_on_breach: true,
            },
            expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) })
        );
    });

    it('submits a project-scoped policy with the expected payload', async () => {
        projListMock.mockResolvedValue(projFixture);
        render(<RotationPoliciesPage />);

        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Project Policy' } });
        fireEvent.change(screen.getByLabelText(/^Scope/), { target: { value: 'project' } });
        await waitFor(() => expect(screen.getByText('proj-x')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText(/^Project/), { target: { value: '5' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));

        expect(createMutate).toHaveBeenCalledWith(
            expect.objectContaining({
                name: 'Project Policy',
                scope: 'project',
                environment_id: null,
                project_id: 5,
            }),
            expect.anything()
        );
    });

    it('closes the modal and resets the form on successful creation', async () => {
        envListMock.mockResolvedValue(envFixture);
        createMutate.mockImplementation((_payload, opts) => opts.onSuccess());
        render(<RotationPoliciesPage />);

        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Discarded Name' } });
        await waitFor(() => expect(screen.getByText('prod-env')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText(/^Environment/), { target: { value: '2' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));

        expect(screen.queryByText('New Rotation Policy')).not.toBeInTheDocument();

        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        expect(screen.getByLabelText(/^Name/)).toHaveValue('');
    });

    it('shows the mutation error message when creation fails', async () => {
        envListMock.mockResolvedValue(envFixture);
        createMutate.mockImplementation((_payload, opts) => opts.onError(new Error('server exploded')));
        render(<RotationPoliciesPage />);

        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Name' } });
        await waitFor(() => expect(screen.getByText('prod-env')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText(/^Environment/), { target: { value: '2' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));

        expect(screen.getByText('server exploded')).toBeInTheDocument();
    });

    it('falls back to a generic error message when the mutation throws a non-Error value', async () => {
        envListMock.mockResolvedValue(envFixture);
        createMutate.mockImplementation((_payload, opts) => opts.onError('nope'));
        render(<RotationPoliciesPage />);

        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Name' } });
        await waitFor(() => expect(screen.getByText('prod-env')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText(/^Environment/), { target: { value: '2' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));

        expect(screen.getByText('Failed to create policy.')).toBeInTheDocument();
    });

    it('disables the form actions and shows a busy label while submitting', () => {
        policiesState.createMutation = { isPending: true };
        render(<RotationPoliciesPage />);
        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        expect(screen.getByRole('button', { name: 'Creating…' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    });

    // Documented bug (not fixed — out of scope for this coverage-only PR): the modal can be
    // closed early via the Cancel button any time the mutation isn't pending, including right
    // after a submit whose async response hasn't landed yet. If that in-flight mutation later
    // calls onError, handleSubmit's onError callback still runs and sets `fError`, but by then
    // `isModalOpen` is false so the Modal (and the Alert inside it) never renders — the failure
    // is silently swallowed and the user never sees it.
    it('silently swallows a create error that resolves after the modal has been closed', async () => {
        envListMock.mockResolvedValue(envFixture);
        let capturedOnError: ((err: unknown) => void) | undefined;
        createMutate.mockImplementation((_payload, opts) => {
            capturedOnError = opts.onError;
        });
        render(<RotationPoliciesPage />);

        fireEvent.click(screen.getAllByRole('button', { name: /New Policy/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Name' } });
        await waitFor(() => expect(screen.getByText('prod-env')).toBeInTheDocument());
        fireEvent.change(screen.getByLabelText(/^Environment/), { target: { value: '2' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Policy' }));
        expect(capturedOnError).toBeDefined();

        // User closes the modal before the (still in-flight) mutation settles.
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByText('New Rotation Policy')).not.toBeInTheDocument();

        // The mutation now fails, well after the modal is gone.
        capturedOnError?.(new Error('too late'));

        expect(screen.queryByText('too late')).not.toBeInTheDocument();
        expect(screen.queryByText('Validation error')).not.toBeInTheDocument();
    });
});

describe('RotationPoliciesPage — edit policy', () => {
    it('prefills the form from a project-scoped policy without a description', async () => {
        projListMock.mockResolvedValue(projFixture);
        const projectPolicyNoDesc = {
            id: 3,
            name: 'No-Desc Policy',
            description: undefined,
            scope: 'project' as const,
            project_id: 5,
            environment_id: null,
            interval_days: 60,
            alert_days_before: 7,
            notify_on_breach: false,
            is_active: true,
            created_by: 'carol@co',
            created_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-01T00:00:00Z',
        };
        policiesState.policies = [projectPolicyNoDesc as unknown as (typeof policiesFixture)[number]];
        render(<RotationPoliciesPage />);

        const row = screen.getByText('No-Desc Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));

        expect(screen.getByLabelText('Description')).toHaveValue('');
        expect(screen.getByLabelText(/^Scope/)).toHaveValue('project');
        await waitFor(() => expect(screen.getByLabelText(/^Project/)).toHaveValue('5'));
    });

    it('prefills the form from the selected policy', async () => {
        envListMock.mockResolvedValue(envFixture);
        policiesState.policies = policiesFixture;
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));

        expect(screen.getByText('Edit: DB Rotation Policy')).toBeInTheDocument();
        expect(screen.getByLabelText(/^Name/)).toHaveValue('DB Rotation Policy');
        expect(screen.getByLabelText('Description')).toHaveValue('Rotate prod db creds');
        expect(screen.getByLabelText(/^Scope/)).toHaveValue('environment');
        await waitFor(() => expect(screen.getByLabelText(/^Environment/)).toHaveValue('2'));
        expect(screen.getByLabelText('Rotation interval')).toHaveValue('90');
        expect(screen.getByLabelText('Alert before breach')).toHaveValue('14');
        expect(screen.getByLabelText('Notify on breach')).toBeChecked();
    });

    it('submits the update with the policy id and the edited fields', async () => {
        envListMock.mockResolvedValue(envFixture);
        policiesState.policies = policiesFixture;
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));

        await waitFor(() => expect(screen.getByLabelText(/^Environment/)).toHaveValue('2'));
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'DB Rotation Policy Updated' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(updateMutate).toHaveBeenCalledWith(
            {
                id: 1,
                name: 'DB Rotation Policy Updated',
                description: 'Rotate prod db creds',
                scope: 'environment',
                environment_id: 2,
                project_id: null,
                interval_days: 90,
                alert_days_before: 14,
                notify_on_breach: true,
            },
            expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) })
        );
    });

    it('shows a busy label while saving', () => {
        policiesState.policies = policiesFixture;
        policiesState.updateMutation = { isPending: true };
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));
        expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
    });

    it('shows the mutation error message when an update fails', async () => {
        envListMock.mockResolvedValue(envFixture);
        policiesState.policies = policiesFixture;
        updateMutate.mockImplementation((_payload, opts) => opts.onError(new Error('policy locked')));
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));
        await waitFor(() => expect(screen.getByLabelText(/^Environment/)).toHaveValue('2'));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(screen.getByText('policy locked')).toBeInTheDocument();
    });

    it('falls back to a generic error message when an update fails with a non-Error value', async () => {
        envListMock.mockResolvedValue(envFixture);
        policiesState.policies = policiesFixture;
        updateMutate.mockImplementation((_payload, opts) => opts.onError('nope'));
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));
        await waitFor(() => expect(screen.getByLabelText(/^Environment/)).toHaveValue('2'));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(screen.getByText('Failed to update policy.')).toBeInTheDocument();
    });
});

describe('RotationPoliciesPage — delete policy', () => {
    it('shows a confirmation with the policy name before deleting', () => {
        policiesState.policies = policiesFixture;
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Delete'));

        expect(screen.getByText('Delete Policy')).toBeInTheDocument();
        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText(/Are you sure you want to delete/)).toBeInTheDocument();
        expect(within(dialog).getByText('DB Rotation Policy')).toBeInTheDocument();
        expect(deleteMutate).not.toHaveBeenCalled();
    });

    it('deletes the policy on confirmation', () => {
        policiesState.policies = policiesFixture;
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Delete'));
        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        expect(deleteMutate).toHaveBeenCalledWith(1, expect.objectContaining({ onSuccess: expect.any(Function) }));
    });

    it('cancels without deleting and resets the mutation state', () => {
        policiesState.policies = policiesFixture;
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Delete'));
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        expect(deleteMutate).not.toHaveBeenCalled();
        expect(deleteResetMock).toHaveBeenCalled();
        expect(screen.queryByText('Delete Policy')).not.toBeInTheDocument();
    });

    it('shows the mutation error and keeps the confirmation open on failure', () => {
        policiesState.policies = policiesFixture;
        policiesState.deleteMutation = { isPending: false, isError: true, error: new Error('cannot delete') };
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Delete'));

        expect(screen.getByText('Failed to delete policy')).toBeInTheDocument();
        expect(screen.getByText('cannot delete')).toBeInTheDocument();
    });

    it('disables the confirmation actions while the delete is pending', () => {
        policiesState.policies = policiesFixture;
        policiesState.deleteMutation = { isPending: true, isError: false, error: null };
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Delete'));

        expect(screen.getByRole('button', { name: 'Deleting…' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    });

    it('closes and resets the mutation state via the modal close (X) button', () => {
        policiesState.policies = policiesFixture;
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Delete'));
        expect(screen.getByText('Delete Policy')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close' }));

        expect(deleteResetMock).toHaveBeenCalled();
        expect(screen.queryByText('Delete Policy')).not.toBeInTheDocument();
    });

    it('closes the confirmation once the delete mutation succeeds', () => {
        policiesState.policies = policiesFixture;
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Delete'));
        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        const onSuccess = deleteMutate.mock.calls[0]![1].onSuccess;
        act(() => onSuccess());

        expect(screen.queryByText('Delete Policy')).not.toBeInTheDocument();
    });

    it('falls back to a generic error message when deletion fails with a non-Error value', () => {
        policiesState.policies = policiesFixture;
        policiesState.deleteMutation = { isPending: false, isError: true, error: 'nope' };
        render(<RotationPoliciesPage />);

        const row = screen.getByText('DB Rotation Policy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Delete'));

        expect(screen.getByText('An unexpected error occurred')).toBeInTheDocument();
    });
});
