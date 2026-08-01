import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { OIDCFederationSection } from '../OIDCFederationSection';
import type { ServiceAccount } from '../../../types/serviceAccounts';

const { mockGet, mockPost, mockDelete } = vi.hoisted(() => ({
    mockGet: vi.fn(),
    mockPost: vi.fn(),
    mockDelete: vi.fn(),
}));

vi.mock('../../../services/client', () => ({
    apiClient: {
        get: (...args: unknown[]) => mockGet(...args),
        post: (...args: unknown[]) => mockPost(...args),
        delete: (...args: unknown[]) => mockDelete(...args),
    },
}));

const activeSA: ServiceAccount = {
    id: 1,
    name: 'ci-deploy',
    description: 'CI pipeline',
    client_id: 'client-abc',
    scopes: 'secrets:read',
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
};

const inactiveSA: ServiceAccount = {
    id: 2,
    name: 'retired-sa',
    description: '',
    client_id: 'client-old',
    scopes: 'secrets:read',
    is_active: false,
    created_at: '2026-01-01T00:00:00Z',
};

const serviceAccounts = [activeSA, inactiveSA];

const trustConfig = {
    id: 10,
    name: 'github-deploy',
    description: 'Prod deploy pipeline',
    issuer_url: 'https://token.actions.githubusercontent.com',
    audience: 'keyorix',
    subject_pattern: 'repo:acme/app:ref:refs/heads/main',
    service_account_id: 1,
    service_account_name: 'ci-deploy',
    created_at: '2026-01-15T00:00:00Z',
    created_by: 'alice',
};

function jsonError(status: number, message?: string) {
    return { response: { status, data: message ? { message } : {} } };
}

beforeEach(() => {
    mockGet.mockReset();
    mockPost.mockReset();
    mockDelete.mockReset();
    mockGet.mockResolvedValue({ data: { data: [] } });
});

describe('OIDCFederationSection — list states', () => {
    it('shows a loading spinner while the initial fetch is pending', () => {
        mockGet.mockReturnValue(new Promise(() => {})); // never resolves
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an empty state when there are no trust configs', async () => {
        mockGet.mockResolvedValue({ data: { data: [] } });
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        expect(await screen.findByText(/no trust configurations yet/i)).toBeInTheDocument();
    });

    it('renders trust config details once loaded', async () => {
        mockGet.mockResolvedValue({ data: { data: [trustConfig] } });
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);

        expect(await screen.findByText('github-deploy')).toBeInTheDocument();
        expect(screen.getByText('Prod deploy pipeline')).toBeInTheDocument();
        expect(screen.getByText('https://token.actions.githubusercontent.com')).toBeInTheDocument();
        expect(screen.getByText('repo:acme/app:ref:refs/heads/main')).toBeInTheDocument();
        expect(screen.getByText('ci-deploy')).toBeInTheDocument();
        // Locale-formatted via toLocaleDateString(undefined, {...}); jsdom's default
        // locale renders day-month-year, so assert loosely rather than pin exact order.
        expect(screen.getByText(/15.*2026/)).toBeInTheDocument();
    });

    it('shows a generic error state when the fetch fails without a 404/501', async () => {
        mockGet.mockRejectedValue(jsonError(500));
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        expect(await screen.findByText('Failed to load trust configurations')).toBeInTheDocument();
        expect(screen.getByText('Check server connectivity and try again.')).toBeInTheDocument();
    });

    it('surfaces the backend error message when present', async () => {
        mockGet.mockRejectedValue(jsonError(500, 'database unavailable'));
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        expect(await screen.findByText('database unavailable')).toBeInTheDocument();
    });

    it('shows a "not yet available" notice and disables Add on 404, without the generic error alert', async () => {
        mockGet.mockRejectedValue(jsonError(404));
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);

        expect(await screen.findByText(/oidc federation not yet available/i)).toBeInTheDocument();
        expect(screen.queryByText('Failed to load trust configurations')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /add trust config/i })).toBeDisabled();
    });

    it('treats a 501 the same as a 404 (backend not ready)', async () => {
        mockGet.mockRejectedValue(jsonError(501));
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        expect(await screen.findByText(/oidc federation not yet available/i)).toBeInTheDocument();
    });
});

describe('OIDCFederationSection — how-to guide', () => {
    it('toggles the GitHub Actions usage snippet', async () => {
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        await screen.findByText(/no trust configurations yet/i);

        const toggle = screen.getByRole('button', { name: /how to use oidc federation in github actions/i });
        expect(screen.queryByText(/id-token: write/)).not.toBeInTheDocument();

        fireEvent.click(toggle);
        expect(screen.getByText(/id-token: write/)).toBeInTheDocument();

        fireEvent.click(toggle);
        expect(screen.queryByText(/id-token: write/)).not.toBeInTheDocument();
    });
});

describe('OIDCFederationSection — add trust config', () => {
    beforeEach(async () => {
        mockGet.mockResolvedValue({ data: { data: [] } });
    });

    async function openAddModal() {
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        await screen.findByText(/no trust configurations yet/i);
        fireEvent.click(screen.getByRole('button', { name: /add trust config/i }));
        return within(screen.getByRole('dialog'));
    }

    it('defaults to the GitHub Actions preset', async () => {
        const dialog = await openAddModal();
        expect(dialog.getByLabelText(/issuer url/i)).toHaveValue('https://token.actions.githubusercontent.com');
        expect(dialog.getByLabelText(/audience/i)).toHaveValue('keyorix');
        expect(dialog.getByLabelText(/subject pattern/i)).toHaveValue('repo:owner/repo:ref:refs/heads/main');
    });

    it('switches issuer preset fields when a different preset is selected', async () => {
        const dialog = await openAddModal();
        fireEvent.click(dialog.getByRole('button', { name: 'GitLab CI' }));

        expect(dialog.getByLabelText(/issuer url/i)).toHaveValue('https://gitlab.com');
        expect(dialog.getByLabelText(/subject pattern/i)).toHaveValue(
            'project_path:group/project:ref_type:branch:ref:main'
        );

        fireEvent.click(dialog.getByRole('button', { name: 'Custom' }));
        expect(dialog.getByLabelText(/issuer url/i)).toHaveValue('');
        expect(dialog.getByLabelText(/subject pattern/i)).toHaveValue('');
    });

    it('only lists active service accounts in the bind dropdown', async () => {
        const dialog = await openAddModal();
        const select = dialog.getByLabelText(/bind to service account/i);
        expect(within(select).getByText('ci-deploy')).toBeInTheDocument();
        expect(within(select).queryByText('retired-sa')).not.toBeInTheDocument();
    });

    it('requires a name before submitting', async () => {
        const dialog = await openAddModal();
        fireEvent.click(dialog.getByRole('button', { name: 'Add Trust Configuration' }));

        expect(await dialog.findByText('Name is required.')).toBeInTheDocument();
        expect(mockPost).not.toHaveBeenCalled();
    });

    it('requires an issuer URL before submitting', async () => {
        const dialog = await openAddModal();
        fireEvent.change(dialog.getByLabelText(/^name/i), { target: { value: 'my-trust' } });
        fireEvent.change(dialog.getByLabelText(/issuer url/i), { target: { value: '' } });
        fireEvent.click(dialog.getByRole('button', { name: 'Add Trust Configuration' }));

        expect(await dialog.findByText('Issuer URL is required.')).toBeInTheDocument();
        expect(mockPost).not.toHaveBeenCalled();
    });

    it('requires a subject pattern before submitting', async () => {
        const dialog = await openAddModal();
        fireEvent.change(dialog.getByLabelText(/^name/i), { target: { value: 'my-trust' } });
        fireEvent.click(dialog.getByRole('button', { name: 'Custom' })); // empty issuer + subject
        fireEvent.change(dialog.getByLabelText(/issuer url/i), { target: { value: 'https://example.com' } });
        fireEvent.click(dialog.getByRole('button', { name: 'Add Trust Configuration' }));

        expect(await dialog.findByText('Subject pattern is required.')).toBeInTheDocument();
        expect(mockPost).not.toHaveBeenCalled();
    });

    it('requires a bound service account before submitting', async () => {
        const dialog = await openAddModal();
        fireEvent.change(dialog.getByLabelText(/^name/i), { target: { value: 'my-trust' } });
        fireEvent.click(dialog.getByRole('button', { name: 'Add Trust Configuration' }));

        expect(await dialog.findByText('Select a service account to bind.')).toBeInTheDocument();
        expect(mockPost).not.toHaveBeenCalled();
    });

    it('submits the trimmed payload and closes the modal on success', async () => {
        mockPost.mockResolvedValue({ data: { data: { ...trustConfig, id: 99 } } });
        const dialog = await openAddModal();

        fireEvent.change(dialog.getByLabelText(/^name/i), { target: { value: '  my-trust  ' } });
        fireEvent.change(dialog.getByLabelText(/description/i), { target: { value: '  optional note  ' } });
        fireEvent.change(dialog.getByLabelText(/^audience/i), { target: { value: '  keyorix  ' } });
        fireEvent.change(dialog.getByLabelText(/bind to service account/i), { target: { value: '1' } });
        fireEvent.click(dialog.getByRole('button', { name: 'Add Trust Configuration' }));

        await waitFor(() =>
            expect(mockPost).toHaveBeenCalledWith('/api/v1/oidc/trust', {
                name: 'my-trust',
                description: 'optional note',
                issuer_url: 'https://token.actions.githubusercontent.com',
                audience: 'keyorix',
                subject_pattern: 'repo:owner/repo:ref:refs/heads/main',
                service_account_id: 1,
            })
        );

        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    });

    it('shows the backend error message and keeps the modal open on failure', async () => {
        mockPost.mockRejectedValue(jsonError(409, 'A trust config with that name already exists.'));
        const dialog = await openAddModal();

        fireEvent.change(dialog.getByLabelText(/^name/i), { target: { value: 'my-trust' } });
        fireEvent.change(dialog.getByLabelText(/bind to service account/i), { target: { value: '1' } });
        fireEvent.click(dialog.getByRole('button', { name: 'Add Trust Configuration' }));

        expect(await dialog.findByText('A trust config with that name already exists.')).toBeInTheDocument();
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it('falls back to a generic error message when the backend gives none', async () => {
        mockPost.mockRejectedValue(new Error('network down'));
        const dialog = await openAddModal();

        fireEvent.change(dialog.getByLabelText(/^name/i), { target: { value: 'my-trust' } });
        fireEvent.change(dialog.getByLabelText(/bind to service account/i), { target: { value: '1' } });
        fireEvent.click(dialog.getByRole('button', { name: 'Add Trust Configuration' }));

        expect(await dialog.findByText('Failed to create trust configuration.')).toBeInTheDocument();
    });

    it('resets the form and clears prior errors each time the modal is reopened', async () => {
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        await screen.findByText(/no trust configurations yet/i);

        fireEvent.click(screen.getByRole('button', { name: /add trust config/i }));
        let dialog = within(screen.getByRole('dialog'));
        fireEvent.change(dialog.getByLabelText(/^name/i), { target: { value: 'temp-name' } });
        fireEvent.click(dialog.getByRole('button', { name: 'Add Trust Configuration' })); // triggers SA-required error
        expect(await dialog.findByText('Select a service account to bind.')).toBeInTheDocument();
        fireEvent.click(dialog.getByRole('button', { name: 'Cancel' }));

        fireEvent.click(screen.getByRole('button', { name: /add trust config/i }));
        dialog = within(screen.getByRole('dialog'));
        expect(dialog.getByLabelText(/^name/i)).toHaveValue('');
        expect(dialog.queryByText('Select a service account to bind.')).not.toBeInTheDocument();
    });
});

describe('OIDCFederationSection — delete trust config', () => {
    it('asks for confirmation, then cancels back to the delete icon without calling delete', async () => {
        mockGet.mockResolvedValue({ data: { data: [trustConfig] } });
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        await screen.findByText('github-deploy');

        fireEvent.click(screen.getByTitle('Delete trust config'));
        expect(screen.getByText('Delete?')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByText('Delete?')).not.toBeInTheDocument();
        expect(screen.getByTitle('Delete trust config')).toBeInTheDocument();
        expect(mockDelete).not.toHaveBeenCalled();
    });

    it('calls delete with the config id on confirm and removes it from the list', async () => {
        mockGet.mockResolvedValueOnce({ data: { data: [trustConfig] } });
        mockDelete.mockResolvedValue({});
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        await screen.findByText('github-deploy');

        // After the mutation invalidates the query, the refetch returns an empty list.
        mockGet.mockResolvedValueOnce({ data: { data: [] } });

        fireEvent.click(screen.getByTitle('Delete trust config'));
        fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

        await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('/api/v1/oidc/trust/10'));
        expect(await screen.findByText(/no trust configurations yet/i)).toBeInTheDocument();
    });

    it('keeps the confirmation open when the delete call fails', async () => {
        mockGet.mockResolvedValue({ data: { data: [trustConfig] } });
        mockDelete.mockRejectedValue(new Error('server error'));
        render(<OIDCFederationSection serviceAccounts={serviceAccounts} />);
        await screen.findByText('github-deploy');

        fireEvent.click(screen.getByTitle('Delete trust config'));
        fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

        await waitFor(() => expect(mockDelete).toHaveBeenCalled());
        // BUG (pre-existing, not fixed here — out of scope per coverage-only convention):
        // doDelete's catch block swallows the failure and leaves confirmDeleteId set, so the
        // "Delete?" prompt stays open with no error feedback to the user that the delete failed.
        expect(screen.getByText('Delete?')).toBeInTheDocument();
    });
});
