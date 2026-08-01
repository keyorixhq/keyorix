import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { ServiceAccountsPage } from '../ServiceAccountsPage';

const useServiceAccounts = vi.fn();
const useServiceAccountTokens = vi.fn();
const createMutate = vi.fn();
const updateMutate = vi.fn();
const deactivateMutate = vi.fn();
const createTokenMutate = vi.fn();
const revokeTokenMutate = vi.fn();

vi.mock('../../../features/admin', () => ({
    useServiceAccounts: (...args: any[]) => useServiceAccounts(...args),
    useCreateServiceAccount: () => ({ mutate: createMutate, isPending: false }),
    useUpdateServiceAccount: () => ({ mutate: updateMutate, isPending: false }),
    useDeactivateServiceAccount: () => ({ mutate: deactivateMutate, isPending: false }),
    useServiceAccountTokens: (...args: any[]) => useServiceAccountTokens(...args),
    useCreateToken: () => ({ mutate: createTokenMutate, isPending: false }),
    useRevokeToken: () => ({ mutate: revokeTokenMutate, isPending: false }),
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
});

describe('ServiceAccountsPage — deactivate', () => {
    it('confirms and deactivates', async () => {
        render(<ServiceAccountsPage />);
        fireEvent.click(screen.getByTitle('Deactivate'));
        expect(screen.getByText(/all tokens issued to this/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));

        await waitFor(() => expect(deactivateMutate).toHaveBeenCalledWith(1, expect.anything()));
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
});
