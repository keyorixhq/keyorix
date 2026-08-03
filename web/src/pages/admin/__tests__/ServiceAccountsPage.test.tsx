import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { ServiceAccountsPage } from '../ServiceAccountsPage';
import { useUIStore } from '../../../store/uiStore';

const useServiceAccounts = vi.fn();
const useServiceAccountTokens = vi.fn();
const createMutate = vi.fn();
const updateMutate = vi.fn();
const deactivateMutate = vi.fn();
const createTokenMutate = vi.fn();
const revokeTokenMutate = vi.fn();

const mutationState = {
    create: { isPending: false },
    update: { isPending: false },
    deactivate: { isPending: false },
    createToken: { isPending: false },
    revokeToken: { isPending: false },
};

vi.mock('../../../features/admin', () => ({
    useServiceAccounts: (...args: any[]) => useServiceAccounts(...args),
    useCreateServiceAccount: () => ({ mutate: createMutate, ...mutationState.create }),
    useUpdateServiceAccount: () => ({ mutate: updateMutate, ...mutationState.update }),
    useDeactivateServiceAccount: () => ({ mutate: deactivateMutate, ...mutationState.deactivate }),
    useServiceAccountTokens: (...args: any[]) => useServiceAccountTokens(...args),
    useCreateToken: () => ({ mutate: createTokenMutate, ...mutationState.createToken }),
    useRevokeToken: () => ({ mutate: revokeTokenMutate, ...mutationState.revokeToken }),
}));

vi.mock('../OIDCFederationSection', () => ({
    OIDCFederationSection: () => <div data-testid="oidc-section" />,
}));

const activeSA = {
    id: 1,
    name: 'ci-deploy',
    description: 'CI pipeline',
    client_id: 'client-abc-123456789',
    scopes: 'secrets:read,secrets:write',
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
};

const inactiveSA = {
    id: 2,
    name: 'old-integration',
    description: '',
    client_id: 'client-old',
    scopes: 'secrets:read',
    is_active: false,
    created_at: '2026-01-01T00:00:00Z',
};

beforeEach(() => {
    vi.clearAllMocks();
    mutationState.create = { isPending: false };
    mutationState.update = { isPending: false };
    mutationState.deactivate = { isPending: false };
    mutationState.createToken = { isPending: false };
    mutationState.revokeToken = { isPending: false };
    useServiceAccounts.mockReturnValue({ data: [activeSA, inactiveSA], isLoading: false, isError: false });
    useServiceAccountTokens.mockReturnValue({ data: [], isLoading: false });
});

describe('ServiceAccountsPage — list states', () => {
    it('shows a loading state', () => {
        useServiceAccounts.mockReturnValue({ data: [], isLoading: true, isError: false });
        render(<ServiceAccountsPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an empty state', () => {
        useServiceAccounts.mockReturnValue({ data: [], isLoading: false, isError: false });
        render(<ServiceAccountsPage />);
        expect(screen.getByText(/no service accounts yet/i)).toBeInTheDocument();
    });

    it('renders each service account row, truncating a long client id', () => {
        render(<ServiceAccountsPage />);
        expect(screen.getByText('ci-deploy')).toBeInTheDocument();
        expect(screen.getByText('client-abc-1…')).toBeInTheDocument();
        expect(screen.getByText('Active')).toBeInTheDocument();
        expect(screen.getByText('Inactive')).toBeInTheDocument();
        // Deactivate button only shows for the active account.
        expect(screen.getAllByTitle('Deactivate')).toHaveLength(1);
    });

    it('shows an error state when service accounts fail to load', () => {
        useServiceAccounts.mockReturnValue({ data: [], isLoading: false, isError: true });
        render(<ServiceAccountsPage />);
        expect(screen.getByText('Failed to load service accounts')).toBeInTheDocument();
        expect(screen.getByText('Check that the server is running and you have admin access.')).toBeInTheDocument();
    });
});

describe('ServiceAccountsPage — theme resolution', () => {
    const initialTheme = useUIStore.getState().theme;

    afterEach(() => {
        useUIStore.setState({ theme: initialTheme });
    });

    it('resolves light colors for the scope and status badges when the theme is light', () => {
        useUIStore.setState({ theme: 'light' });
        render(<ServiceAccountsPage />);
        expect(screen.getByText('ci-deploy')).toBeInTheDocument();
        expect(screen.getAllByText('secrets:read').length).toBeGreaterThan(0);
        expect(screen.getByText('Active')).toBeInTheDocument();
        expect(screen.getByText('Inactive')).toBeInTheDocument();
    });

    it('resolves a system theme as light when matchMedia does not match', () => {
        useUIStore.setState({ theme: 'system' });
        render(<ServiceAccountsPage />);
        expect(screen.getByText('ci-deploy')).toBeInTheDocument();
        expect(window.matchMedia).toHaveBeenCalledWith('(prefers-color-scheme: dark)');
    });

    it('resolves a system theme as dark when matchMedia matches', () => {
        useUIStore.setState({ theme: 'system' });
        vi.mocked(window.matchMedia).mockReturnValueOnce({
            matches: true,
            media: '(prefers-color-scheme: dark)',
            onchange: null,
            addListener: vi.fn(),
            removeListener: vi.fn(),
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
            dispatchEvent: vi.fn(),
        } as unknown as MediaQueryList);
        render(<ServiceAccountsPage />);
        expect(screen.getByText('ci-deploy')).toBeInTheDocument();
    });
});

describe('ServiceAccountsPage — tabs', () => {
    it('switches to the OIDC Federation tab', () => {
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: 'OIDC Federation' }));
        expect(screen.getByTestId('oidc-section')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /new service account/i })).not.toBeInTheDocument();
    });
});

describe('ServiceAccountsPage — create', () => {
    it('validates name and scope before submitting', async () => {
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));

        expect(await screen.findByText('Name is required')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();

        fireEvent.change(screen.getByLabelText('Name', { exact: false }), { target: { value: 'new-sa' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));
        expect(await screen.findByText('At least one scope is required')).toBeInTheDocument();
    });

    it('creates a service account and shows the one-time credentials', async () => {
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({
                service_account: { client_id: 'new-client-id', name: 'new-sa' },
                client_secret: 'new-client-secret',
            })
        );
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));

        fireEvent.change(screen.getByLabelText('Name', { exact: false }), { target: { value: 'new-sa' } });
        fireEvent.click(screen.getByLabelText(/secrets:read — Read secrets/));
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));

        await waitFor(() =>
            expect(createMutate).toHaveBeenCalledWith(
                { name: 'new-sa', description: '', scopes: 'secrets:read' },
                expect.anything()
            )
        );
        expect(screen.getByText('new-client-id')).toBeInTheDocument();
        expect(screen.getByText('new-client-secret')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: "I've saved these credentials" }));
        expect(screen.queryByText('new-client-id')).not.toBeInTheDocument();
    });

    it('copies the client id and client secret, and shows "Copied!" for each', async () => {
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({
                service_account: { client_id: 'new-client-id', name: 'new-sa' },
                client_secret: 'new-client-secret',
            })
        );
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));
        fireEvent.change(screen.getByLabelText('Name', { exact: false }), { target: { value: 'new-sa' } });
        fireEvent.click(screen.getByLabelText(/secrets:read — Read secrets/));
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));

        const dialog = await screen.findByRole('dialog');
        fireEvent.click(within(dialog).getByTitle('Copy Client ID'));
        await waitFor(() => expect(within(dialog).getByText('Copied!')).toBeInTheDocument());

        // copiedField tracks a single field at a time, so copying the secret next
        // clears the client-id indicator and shows the secret's instead.
        fireEvent.click(within(dialog).getByTitle('Copy Client Secret'));
        await waitFor(() => expect(within(dialog).getAllByText('Copied!')).toHaveLength(1));
    });

    it('closes the credentials modal via the dialog close button', async () => {
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({
                service_account: { client_id: 'new-client-id', name: 'new-sa' },
                client_secret: 'new-client-secret',
            })
        );
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));
        fireEvent.change(screen.getByLabelText('Name', { exact: false }), { target: { value: 'new-sa' } });
        fireEvent.click(screen.getByLabelText(/secrets:read — Read secrets/));
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));

        await screen.findByText('new-client-id');
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByText('new-client-id')).not.toBeInTheDocument();
    });

    it('renders the credentials modal in light-theme colors', async () => {
        useUIStore.setState({ theme: 'light' });
        createMutate.mockImplementation((_body, opts) =>
            opts.onSuccess({
                service_account: { client_id: 'new-client-id', name: 'new-sa' },
                client_secret: 'new-client-secret',
            })
        );
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));
        fireEvent.change(screen.getByLabelText('Name', { exact: false }), { target: { value: 'new-sa' } });
        fireEvent.click(screen.getByLabelText(/secrets:read — Read secrets/));
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));

        expect(await screen.findByText('new-client-id')).toBeInTheDocument();
        useUIStore.setState({ theme: 'dark' });
    });

    it('lets the description be typed directly', async () => {
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'a new SA' } });
        expect(within(dialog).getByLabelText('Description')).toHaveValue('a new SA');
    });

    it('shows a Creating… label and disables the buttons while the create mutation is pending', () => {
        mutationState.create = { isPending: true };
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));

        const createButton = screen.getByRole('button', { name: 'Creating…' });
        expect(createButton).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    });

    it('shows the API error message when create fails', async () => {
        createMutate.mockImplementation((_body, opts) =>
            opts.onError({ response: { data: { error: 'Name already taken' } } })
        );
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));
        fireEvent.change(screen.getByLabelText('Name', { exact: false }), { target: { value: 'new-sa' } });
        fireEvent.click(screen.getByLabelText(/secrets:read — Read secrets/));
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));

        expect(await screen.findByText('Name already taken')).toBeInTheDocument();
    });

    it('falls back to err.message, then a generic message, when create fails without a response error', async () => {
        createMutate.mockImplementationOnce((_body, opts) => opts.onError({ message: 'Network Error' }));
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByRole('button', { name: /new service account/i }));
        fireEvent.change(screen.getByLabelText('Name', { exact: false }), { target: { value: 'new-sa' } });
        fireEvent.click(screen.getByLabelText(/secrets:read — Read secrets/));
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));
        expect(await screen.findByText('Network Error')).toBeInTheDocument();

        createMutate.mockImplementationOnce((_body, opts) => opts.onError({}));
        fireEvent.click(screen.getByRole('button', { name: 'Create Service Account' }));
        expect(await screen.findByText('Failed to create service account')).toBeInTheDocument();
    });
});

describe('ServiceAccountsPage — edit', () => {
    it('opens pre-filled with the parsed scopes and saves', async () => {
        render(<ServiceAccountsPage />);
        const row = screen.getByText('ci-deploy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));

        const nameInput = screen.getByLabelText('Name', { exact: false }) as HTMLInputElement;
        expect(nameInput.value).toBe('ci-deploy');
        const readScope = screen.getByRole('checkbox', { name: /secrets:read — Read secrets/ }) as HTMLInputElement;
        const writeScope = screen.getByRole('checkbox', {
            name: /secrets:write — Create and update secrets/,
        }) as HTMLInputElement;
        expect(readScope.checked).toBe(true);
        expect(writeScope.checked).toBe(true);

        fireEvent.click(writeScope); // uncheck
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        await waitFor(() =>
            expect(updateMutate).toHaveBeenCalledWith(
                { id: 1, body: { name: 'ci-deploy', description: 'CI pipeline', scopes: 'secrets:read' } },
                expect.anything()
            )
        );
    });

    it('lets the name and description be edited directly', () => {
        render(<ServiceAccountsPage />);
        const row = screen.getByText('ci-deploy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Name', { exact: false }), {
            target: { value: 'ci-deploy-renamed' },
        });
        fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'renamed pipeline' } });

        expect(within(dialog).getByLabelText('Name', { exact: false })).toHaveValue('ci-deploy-renamed');
        expect(within(dialog).getByLabelText('Description')).toHaveValue('renamed pipeline');
    });

    it('requires a name before saving', async () => {
        render(<ServiceAccountsPage />);
        const row = screen.getByText('ci-deploy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Name', { exact: false }), { target: { value: '   ' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Save Changes' }));

        expect(await within(dialog).findByText('Name is required')).toBeInTheDocument();
        expect(updateMutate).not.toHaveBeenCalled();
    });

    it('requires at least one scope before saving', async () => {
        render(<ServiceAccountsPage />);
        const row = screen.getByText('ci-deploy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));

        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /secrets:read — Read secrets/ }));
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /secrets:write — Create and update secrets/ }));
        fireEvent.click(within(dialog).getByRole('button', { name: 'Save Changes' }));

        expect(await within(dialog).findByText('At least one scope is required')).toBeInTheDocument();
        expect(updateMutate).not.toHaveBeenCalled();
    });

    it('shows a Saving… label and disables the buttons while the update mutation is pending', () => {
        mutationState.update = { isPending: true };
        render(<ServiceAccountsPage />);
        const row = screen.getByText('ci-deploy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));

        const dialog = screen.getByRole('dialog');
        const saveButton = within(dialog).getByRole('button', { name: 'Saving…' });
        expect(saveButton).toBeDisabled();
        expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled();
    });

    it('shows the API error message when update fails', async () => {
        updateMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { error: 'Name already taken' } } })
        );
        render(<ServiceAccountsPage />);
        const row = screen.getByText('ci-deploy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(await screen.findByText('Name already taken')).toBeInTheDocument();
    });

    it('falls back to err.message, then a generic message, when update fails without a response error', async () => {
        updateMutate.mockImplementationOnce((_vars, opts) => opts.onError({ message: 'Network Error' }));
        render(<ServiceAccountsPage />);
        const row = screen.getByText('ci-deploy').closest('tr')!;
        fireEvent.click(within(row).getByTitle('Edit'));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
        expect(await screen.findByText('Network Error')).toBeInTheDocument();

        updateMutate.mockImplementationOnce((_vars, opts) => opts.onError({}));
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
        expect(await screen.findByText('Failed to update service account')).toBeInTheDocument();
    });
});

describe('ServiceAccountsPage — deactivate', () => {
    it('confirms and deactivates', async () => {
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByTitle('Deactivate'));
        expect(screen.getByText(/all tokens issued to this/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));

        await waitFor(() => expect(deactivateMutate).toHaveBeenCalledWith(1, expect.anything()));
    });

    it('shows a Deactivating… label and disables the buttons while the mutation is pending', () => {
        mutationState.deactivate = { isPending: true };
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByTitle('Deactivate'));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByRole('button', { name: 'Deactivating…' })).toBeDisabled();
        expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled();
    });

    it('shows a dismissible page error with the API message when deactivation fails', async () => {
        deactivateMutate.mockImplementation((_id, opts) =>
            opts.onError({ response: { data: { error: 'Still has active tokens' } } })
        );
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByTitle('Deactivate'));
        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));

        expect(await screen.findByText('Still has active tokens')).toBeInTheDocument();

        // Close the confirmation dialog first — Radix marks the background as
        // aria-hidden while it's open, which hides the page error banner's
        // dismiss button from accessible-role queries.
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByText('Still has active tokens')).not.toBeInTheDocument();
    });

    it('falls back to err.message, then a generic message, when deactivation fails without a response error', async () => {
        deactivateMutate.mockImplementationOnce((_id, opts) => opts.onError({ message: 'Network Error' }));
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByTitle('Deactivate'));
        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));
        expect(await screen.findByText('Network Error')).toBeInTheDocument();

        deactivateMutate.mockImplementationOnce((_id, opts) => opts.onError({}));
        fireEvent.click(screen.getByTitle('Deactivate'));
        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));
        expect(await screen.findByText('Failed to deactivate service account')).toBeInTheDocument();
    });
});

describe('ServiceAccountsPage — tokens', () => {
    it('shows an empty state and creates a new token', async () => {
        createTokenMutate.mockImplementation((_vars, opts) => opts.onSuccess({ access_token: 'tok_abc123' }));
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);

        expect(await screen.findByText(/no tokens yet/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /new token/i }));
        fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'CI token' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));

        await waitFor(() =>
            expect(createTokenMutate).toHaveBeenCalledWith(
                { serviceAccountId: 1, body: { description: 'CI token' } },
                expect.anything()
            )
        );
        expect(screen.getByText('tok_abc123')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: "I've saved this token" }));
        expect(screen.queryByText('tok_abc123')).not.toBeInTheDocument();
    });

    it('lists existing tokens and revokes one after arming and confirming', async () => {
        useServiceAccountTokens.mockReturnValue({
            data: [{ id: 9, created_at: '2026-01-01T00:00:00Z', expires_at: null, revoked: false }],
            isLoading: false,
        });
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);

        const dialog = screen.getByRole('dialog');
        expect(await within(dialog).findByText('Active')).toBeInTheDocument();
        // First click arms the revoke ("Revoke?" + confirm/cancel appear); second confirms.
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        expect(within(dialog).getByText('Revoke?')).toBeInTheDocument();
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));

        await waitFor(() => expect(revokeTokenMutate).toHaveBeenCalledWith({ tokenId: 9 }, expect.anything()));
    });

    it('shows a loading spinner while tokens are loading', () => {
        useServiceAccountTokens.mockReturnValue({ data: [], isLoading: true });
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);

        const dialog = screen.getByRole('dialog');
        expect(dialog.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows a formatted expiry date for a token that has one', async () => {
        useServiceAccountTokens.mockReturnValue({
            data: [{ id: 9, created_at: '2026-01-01T00:00:00Z', expires_at: '2099-06-01T00:00:00Z', revoked: false }],
            isLoading: false,
        });
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);

        const dialog = screen.getByRole('dialog');
        await within(dialog).findByText('Active');
        expect(within(dialog).queryByText('—')).not.toBeInTheDocument();
    });

    it('cancels an armed revoke without calling the mutation', async () => {
        useServiceAccountTokens.mockReturnValue({
            data: [{ id: 9, created_at: '2026-01-01T00:00:00Z', expires_at: null, revoked: false }],
            isLoading: false,
        });
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);

        const dialog = screen.getByRole('dialog');
        await within(dialog).findByText('Active');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        expect(within(dialog).getByText('Revoke?')).toBeInTheDocument();

        fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
        expect(within(dialog).queryByText('Revoke?')).not.toBeInTheDocument();
        expect(revokeTokenMutate).not.toHaveBeenCalled();
    });

    it('resets the pending revoke id on a successful revoke', async () => {
        revokeTokenMutate.mockImplementation((_vars, opts) => opts.onSuccess());
        useServiceAccountTokens.mockReturnValue({
            data: [{ id: 9, created_at: '2026-01-01T00:00:00Z', expires_at: null, revoked: false }],
            isLoading: false,
        });
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);

        const dialog = screen.getByRole('dialog');
        await within(dialog).findByText('Active');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));

        await waitFor(() => expect(within(dialog).queryByText('Revoke?')).not.toBeInTheDocument());
    });

    it('shows the API error message when revoking a token fails', async () => {
        revokeTokenMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { error: 'Token already revoked' } } })
        );
        useServiceAccountTokens.mockReturnValue({
            data: [{ id: 9, created_at: '2026-01-01T00:00:00Z', expires_at: null, revoked: false }],
            isLoading: false,
        });
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);

        const dialog = screen.getByRole('dialog');
        await within(dialog).findByText('Active');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));

        expect(await screen.findByText('Token already revoked')).toBeInTheDocument();
    });

    it('falls back to err.message, then a generic message, when revoking a token fails without a response error', async () => {
        useServiceAccountTokens.mockReturnValue({
            data: [{ id: 9, created_at: '2026-01-01T00:00:00Z', expires_at: null, revoked: false }],
            isLoading: false,
        });
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);

        const dialog = screen.getByRole('dialog');
        await within(dialog).findByText('Active');

        // Arm the revoke action once; the error handler doesn't clear the pending
        // id, so it stays armed and every subsequent click below re-confirms.
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));

        revokeTokenMutate.mockImplementationOnce((_vars, opts) => opts.onError({ message: 'Network Error' }));
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        expect(await screen.findByText('Network Error')).toBeInTheDocument();

        revokeTokenMutate.mockImplementationOnce((_vars, opts) => opts.onError({}));
        fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
        expect(await screen.findByText('Failed to revoke token')).toBeInTheDocument();
    });

    it('includes an expires_at date in the token body when one is set', async () => {
        createTokenMutate.mockImplementation((_vars, opts) => opts.onSuccess({ access_token: 'tok_exp123' }));
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);
        fireEvent.click(screen.getByRole('button', { name: /new token/i }));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText(/expires at/i), { target: { value: '2099-01-01' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Create Token' }));

        await waitFor(() =>
            expect(createTokenMutate).toHaveBeenCalledWith(
                { serviceAccountId: 1, body: { expires_at: '2099-01-01' } },
                expect.anything()
            )
        );
    });

    it('cancels the new-token form without submitting', () => {
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);
        fireEvent.click(screen.getByRole('button', { name: /new token/i }));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'discarded' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

        expect(within(dialog).queryByLabelText('Description')).not.toBeInTheDocument();
        expect(createTokenMutate).not.toHaveBeenCalled();
    });

    it('shows a Creating… label and disables the button while the create-token mutation is pending', () => {
        mutationState.createToken = { isPending: true };
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);
        fireEvent.click(screen.getByRole('button', { name: /new token/i }));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByRole('button', { name: 'Creating…' })).toBeDisabled();
    });

    it('shows the API error message when creating a token fails', async () => {
        createTokenMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { error: 'Too many active tokens' } } })
        );
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);
        fireEvent.click(screen.getByRole('button', { name: /new token/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));

        expect(await screen.findByText('Too many active tokens')).toBeInTheDocument();
    });

    it('falls back to err.message, then a generic message, when creating a token fails without a response error', async () => {
        createTokenMutate.mockImplementationOnce((_vars, opts) => opts.onError({ message: 'Network Error' }));
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);
        fireEvent.click(screen.getByRole('button', { name: /new token/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));
        expect(await screen.findByText('Network Error')).toBeInTheDocument();

        createTokenMutate.mockImplementationOnce((_vars, opts) => opts.onError({}));
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));
        expect(await screen.findByText('Failed to create token')).toBeInTheDocument();
    });

    it('copies the newly created access token and shows "Copied!"', async () => {
        createTokenMutate.mockImplementation((_vars, opts) => opts.onSuccess({ access_token: 'tok_xyz789' }));
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);
        fireEvent.click(screen.getByRole('button', { name: /new token/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));

        const dialog = await screen.findByRole('dialog');
        await within(dialog).findByText('tok_xyz789');
        fireEvent.click(within(dialog).getByTitle('Copy token'));

        await waitFor(() => expect(within(dialog).getByText('Copied!')).toBeInTheDocument());
    });

    it('renders the tokens modal in light-theme colors', async () => {
        useUIStore.setState({ theme: 'light' });
        createTokenMutate.mockImplementation((_vars, opts) => opts.onSuccess({ access_token: 'tok_xyz789' }));
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getAllByTitle('Manage tokens')[0]!);
        fireEvent.click(screen.getByRole('button', { name: /new token/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));

        expect(await screen.findByText('tok_xyz789')).toBeInTheDocument();
        useUIStore.setState({ theme: 'dark' });
    });
});
