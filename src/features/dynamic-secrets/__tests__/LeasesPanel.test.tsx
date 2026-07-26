import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { LeasesPanel } from '../LeasesPanel';

// Issuing a cloud-IAM lease returns the credential as `fields` (no username/password).
const issueMutate = vi.fn((_: unknown, opts: { onSuccess: (c: unknown) => void }) =>
    opts.onSuccess({
        leaseId: 'lease-1',
        username: '',
        password: '',
        fields: {
            access_key_id: 'AKIAEXAMPLE',
            secret_access_key: 'sekret',
            session_token: 'tok',
            expiration: '2026-06-15T12:00:00Z',
        },
        expiresAt: '2026-06-15T12:00:00Z',
    })
);

vi.mock('../api', () => ({
    useDynamicLeases: () => ({ data: [], isLoading: false }),
    useIssueLease: () => ({ mutate: issueMutate, isPending: false }),
    useRevokeLease: () => ({ mutate: vi.fn(), isPending: false }),
    useRevokeAllLeases: () => ({ mutate: vi.fn(), isPending: false }),
}));

describe('LeasesPanel cloud credentials', () => {
    it('shows an issued cloud credential as labelled fields, not username/password', () => {
        render(<LeasesPanel configId={5} canManage />);

        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
        expect(issueMutate).toHaveBeenCalledTimes(1);

        // The cloud credential fields are rendered (humanized labels), expiration excluded.
        expect(screen.getByText('Access key id')).toBeInTheDocument();
        expect(screen.getByText('AKIAEXAMPLE')).toBeInTheDocument();
        expect(screen.getByText('Session token')).toBeInTheDocument();
        // No empty username/password rows for a cloud credential.
        expect(screen.queryByText('Username')).not.toBeInTheDocument();
        expect(screen.queryByText('Password')).not.toBeInTheDocument();
        // expiration is shown as the "Expires …" line, not a copy row.
        expect(screen.queryByText('Expiration')).not.toBeInTheDocument();
    });
});
