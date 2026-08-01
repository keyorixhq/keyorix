import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { APITokensPage } from '../APITokensPage';
import { formatDateShort } from '../../../utils';

const { useServiceAccounts, revokeTokenMutate, listTokensMock, revokeState } = vi.hoisted(() => ({
    useServiceAccounts: vi.fn(),
    revokeTokenMutate: vi.fn(),
    listTokensMock: vi.fn(),
    revokeState: { isPending: false },
}));

vi.mock('../../../features/admin', () => ({
    useServiceAccounts: (...args: unknown[]) => useServiceAccounts(...args),
    useRevokeToken: () => ({ mutate: revokeTokenMutate, isPending: revokeState.isPending }),
}));

vi.mock('../../../services/serviceAccounts', () => ({
    serviceAccountsApi: {
        listTokens: (...args: unknown[]) => listTokensMock(...args),
    },
}));

const saOne = {
    id: 1,
    name: 'ci-deploy',
    description: 'CI pipeline',
    client_id: 'client-abc',
    scopes: 'secrets:read',
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
};

const saTwo = {
    id: 2,
    name: 'nightly-job',
    description: '',
    client_id: 'client-def',
    scopes: 'secrets:read',
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
};

const activeToken = {
    id: 101,
    client_id: 1,
    scope: 'secrets:read',
    expires_at: null,
    created_at: '2026-01-01T00:00:00Z',
    revoked: false,
};

const revokedToken = {
    id: 102,
    client_id: 1,
    scope: '',
    expires_at: null,
    created_at: '2026-01-02T00:00:00Z',
    revoked: true,
};

const expiredToken = {
    id: 103,
    client_id: 2,
    scope: 'secrets:write',
    expires_at: '2020-01-01T00:00:00Z',
    created_at: '2019-01-01T00:00:00Z',
    revoked: false,
};

beforeEach(() => {
    vi.clearAllMocks();
    revokeState.isPending = false;
    useServiceAccounts.mockReturnValue({ data: [], isLoading: false, isError: false });
    listTokensMock.mockResolvedValue([]);
});

describe('APITokensPage — loading / error / empty states', () => {
    it('shows a loading spinner while service accounts are loading', () => {
        useServiceAccounts.mockReturnValue({ data: [], isLoading: true, isError: false });
        render(<APITokensPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows a loading spinner while token queries are still in flight', () => {
        useServiceAccounts.mockReturnValue({ data: [saOne], isLoading: false, isError: false });
        listTokensMock.mockReturnValue(new Promise(() => {})); // never resolves
        render(<APITokensPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an error state when service accounts fail to load', () => {
        useServiceAccounts.mockReturnValue({ data: [], isLoading: false, isError: true });
        render(<APITokensPage />);
        expect(screen.getByText('Failed to load service accounts')).toBeInTheDocument();
        expect(screen.getByText('Check that the server is running and you have admin access.')).toBeInTheDocument();
    });

    it('shows an empty state when there are no service accounts at all', async () => {
        render(<APITokensPage />);
        expect(await screen.findByText('No tokens found across any service accounts.')).toBeInTheDocument();
    });

    it('shows an empty state when service accounts exist but have no tokens', async () => {
        useServiceAccounts.mockReturnValue({ data: [saOne], isLoading: false, isError: false });
        listTokensMock.mockResolvedValue([]);
        render(<APITokensPage />);
        expect(await screen.findByText('No tokens found across any service accounts.')).toBeInTheDocument();
    });
});

describe('APITokensPage — populated list', () => {
    it('flattens tokens from multiple service accounts with the owning account name', async () => {
        useServiceAccounts.mockReturnValue({ data: [saOne, saTwo], isLoading: false, isError: false });
        listTokensMock.mockImplementation((serviceAccountId: number) => {
            if (serviceAccountId === 1) return Promise.resolve([activeToken, revokedToken]);
            if (serviceAccountId === 2) return Promise.resolve([expiredToken]);
            return Promise.resolve([]);
        });
        render(<APITokensPage />);

        expect(await screen.findByText('#101')).toBeInTheDocument();
        expect(screen.getByText('#102')).toBeInTheDocument();
        expect(screen.getByText('#103')).toBeInTheDocument();

        const row101 = screen.getByText('#101').closest('tr')!;
        expect(within(row101).getByText('ci-deploy')).toBeInTheDocument();
        expect(within(row101).getByText('secrets:read')).toBeInTheDocument();
        expect(within(row101).getByText(formatDateShort(activeToken.created_at))).toBeInTheDocument();
        expect(within(row101).getByText('—')).toBeInTheDocument(); // no expiry
        expect(within(row101).getByText('Active')).toBeInTheDocument();

        const row102 = screen.getByText('#102').closest('tr')!;
        expect(within(row102).getByText('Revoked')).toBeInTheDocument();
        // Empty scope renders the dash fallback rather than a scope pill.
        expect(within(row102).getAllByText('—').length).toBeGreaterThan(0);

        const row103 = screen.getByText('#103').closest('tr')!;
        expect(within(row103).getByText('nightly-job')).toBeInTheDocument();
        expect(within(row103).getByText('Expired')).toBeInTheDocument();
        expect(within(row103).getByText(formatDateShort(expiredToken.expires_at))).toBeInTheDocument();
    });

    it('disables the revoke action for revoked and expired tokens', async () => {
        useServiceAccounts.mockReturnValue({ data: [saOne, saTwo], isLoading: false, isError: false });
        listTokensMock.mockImplementation((serviceAccountId: number) => {
            if (serviceAccountId === 1) return Promise.resolve([activeToken, revokedToken]);
            if (serviceAccountId === 2) return Promise.resolve([expiredToken]);
            return Promise.resolve([]);
        });
        render(<APITokensPage />);
        await screen.findByText('#101');

        const row101 = screen.getByText('#101').closest('tr')!;
        const row102 = screen.getByText('#102').closest('tr')!;
        const row103 = screen.getByText('#103').closest('tr')!;

        expect(within(row101).getByRole('button', { name: 'Revoke' })).not.toBeDisabled();
        expect(within(row102).getByRole('button', { name: 'Revoke' })).toBeDisabled();
        expect(within(row103).getByRole('button', { name: 'Revoke' })).toBeDisabled();
    });
});

describe('APITokensPage — revoke flow', () => {
    beforeEach(() => {
        useServiceAccounts.mockReturnValue({ data: [saOne], isLoading: false, isError: false });
        listTokensMock.mockResolvedValue([activeToken]);
    });

    it('arms the revoke action, then confirms and calls the mutation with the token id', async () => {
        render(<APITokensPage />);
        const row = (await screen.findByText('#101')).closest('tr')!;

        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
        expect(within(row).getByText('Revoke?')).toBeInTheDocument();

        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));

        await waitFor(() => expect(revokeTokenMutate).toHaveBeenCalledWith({ tokenId: 101 }, expect.anything()));
    });

    it('cancels the armed revoke action without calling the mutation', async () => {
        render(<APITokensPage />);
        const row = (await screen.findByText('#101')).closest('tr')!;

        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
        expect(within(row).getByText('Revoke?')).toBeInTheDocument();

        fireEvent.click(within(row).getByRole('button', { name: 'Cancel' }));

        expect(screen.queryByText('Revoke?')).not.toBeInTheDocument();
        expect(revokeTokenMutate).not.toHaveBeenCalled();
    });

    it('shows the busy label while the mutation is pending', async () => {
        revokeState.isPending = true;
        render(<APITokensPage />);
        const row = (await screen.findByText('#101')).closest('tr')!;

        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
        expect(within(row).getByRole('button', { name: '…' })).toBeDisabled();
    });

    it('clears the pending confirmation on a successful revoke', async () => {
        revokeTokenMutate.mockImplementation((_vars, opts) => opts.onSuccess());
        render(<APITokensPage />);
        const row = (await screen.findByText('#101')).closest('tr')!;

        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));

        await waitFor(() => expect(screen.queryByText('Revoke?')).not.toBeInTheDocument());
    });

    it('surfaces the server error message and lets it be dismissed', async () => {
        revokeTokenMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { error: 'Token already revoked' } } })
        );
        render(<APITokensPage />);
        const row = (await screen.findByText('#101')).closest('tr')!;

        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));

        expect(await screen.findByText('Token already revoked')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByText('Token already revoked')).not.toBeInTheDocument();
    });

    it('falls back to a generic error message when the server gives no error field', async () => {
        revokeTokenMutate.mockImplementation((_vars, opts) => opts.onError({ message: 'Network Error' }));
        render(<APITokensPage />);
        const row = (await screen.findByText('#101')).closest('tr')!;

        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
        fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));

        expect(await screen.findByText('Network Error')).toBeInTheDocument();
    });
});
