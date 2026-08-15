import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { LeasesPanel } from '../LeasesPanel';
import { DEFAULT_SENSITIVE_IDLE_MS } from '../../../hooks/useAutoClearOnIdle';

let leasesData: any[] = [];
let leasesLoading = false;

const issueMutate = vi.fn();
const revokeMutate = vi.fn();
const revokeAllMutate = vi.fn();

vi.mock('../api', () => ({
    useDynamicLeases: () => ({ data: leasesData, isLoading: leasesLoading }),
    useIssueLease: () => ({ mutate: issueMutate, isPending: false }),
    useRevokeLease: () => ({ mutate: revokeMutate, isPending: false }),
    useRevokeAllLeases: () => ({ mutate: revokeAllMutate, isPending: false }),
}));

beforeEach(() => {
    leasesData = [];
    leasesLoading = false;
    issueMutate.mockReset();
    revokeMutate.mockReset();
    revokeAllMutate.mockReset();
});

describe('LeasesPanel cloud credentials', () => {
    it('shows an issued cloud credential as labelled fields, not username/password', () => {
        issueMutate.mockImplementation((_vars, opts) =>
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

describe('LeasesPanel', () => {
    it('shows a loading message while leases load', () => {
        leasesLoading = true;
        render(<LeasesPanel configId={5} canManage />);
        expect(screen.getByText('Loading leases…')).toBeInTheDocument();
    });

    it('shows an empty state when there are no leases', () => {
        render(<LeasesPanel configId={5} canManage />);
        expect(screen.getByText('No leases issued yet.')).toBeInTheDocument();
    });

    it('renders every lease status style, expiry, and role/leaseId fallback', () => {
        leasesData = [
            {
                leaseId: 'lease-active',
                roleName: 'readonly-role',
                status: 'active',
                expiresAt: '2026-06-15T12:00:00Z',
            },
            { leaseId: 'lease-expired', roleName: '', status: 'expired' },
            { leaseId: 'lease-failed', roleName: 'admin-role', status: 'revoke_failed' },
            { leaseId: 'lease-revoked', roleName: 'old-role', status: 'revoked' },
        ];
        render(<LeasesPanel configId={5} canManage />);

        expect(screen.getByText('active')).toBeInTheDocument();
        expect(screen.getByText('expired')).toBeInTheDocument();
        expect(screen.getByText('revoke failed')).toBeInTheDocument();
        expect(screen.getByText('revoked')).toBeInTheDocument();

        // roleName fallback: falls back to the leaseId when roleName is blank.
        expect(screen.getByText('lease-expired')).toBeInTheDocument();
        expect(screen.getByText('readonly-role')).toBeInTheDocument();

        // expiresAt renders for the active lease only.
        expect(screen.getByText(/expires/i)).toBeInTheDocument();

        // Only the active lease is revocable.
        expect(screen.getAllByTitle('Revoke lease')).toHaveLength(1);
    });

    it('hides revoke controls for non-managers even on an active lease', () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];
        render(<LeasesPanel configId={5} canManage={false} />);
        expect(screen.queryByTitle('Revoke lease')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /issue credential/i })).not.toBeInTheDocument();
    });

    it('revokes a single lease and surfaces a fallback error when the server gives no detail', () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];
        revokeMutate.mockImplementation((_id, opts) => opts.onError({}));

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByTitle('Revoke lease'));

        expect(revokeMutate).toHaveBeenCalledWith('lease-1', expect.anything());
        expect(screen.getByText('Failed to revoke lease.')).toBeInTheDocument();
    });

    it('hides "Revoke all" when there are no active leases, shows it (with a count) when there are', () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'expired' }];
        const { rerender } = render(<LeasesPanel configId={5} canManage />);
        expect(screen.queryByRole('button', { name: /revoke all/i })).not.toBeInTheDocument();

        leasesData = [
            { leaseId: 'lease-1', roleName: 'role', status: 'active' },
            { leaseId: 'lease-2', roleName: 'role2', status: 'active' },
        ];
        rerender(<LeasesPanel configId={5} canManage />);
        expect(screen.getByRole('button', { name: 'Revoke all (2)' })).toBeInTheDocument();
    });

    it('revokes all active leases and surfaces the server error message on failure', () => {
        leasesData = [{ leaseId: 'lease-1', roleName: 'role', status: 'active' }];
        revokeAllMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'Vault unreachable' } } })
        );

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /revoke all/i }));

        expect(revokeAllMutate).toHaveBeenCalled();
        expect(screen.getByText('Vault unreachable')).toBeInTheDocument();
    });

    it('shows the server message when issuing a credential fails', () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { error: 'backend disabled' } } })
        );

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));

        expect(screen.getByText('backend disabled')).toBeInTheDocument();
    });

    it('shows a database-style credential as username/password copy rows, without an expiry line', async () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({
                leaseId: 'lease-db',
                username: 'app_user',
                password: 'super-secret',
            })
        );

        render(<LeasesPanel configId={5} canManage />);
        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));

        expect(screen.getByText('Username')).toBeInTheDocument();
        expect(screen.getByText('app_user')).toBeInTheDocument();
        expect(screen.getByText('Password')).toBeInTheDocument();
        expect(screen.getByText('super-secret')).toBeInTheDocument();
        // No expiry line when the credential carries no expiresAt.
        expect(screen.queryByText(/^Expires/)).not.toBeInTheDocument();

        // Copying a field writes it to the clipboard and flips the button label.
        const copyButtons = screen.getAllByRole('button', { name: 'Copy' });
        fireEvent.click(copyButtons[0]);
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('app_user');
        await waitFor(() => expect(screen.getAllByRole('button', { name: 'Copied' })).toHaveLength(1));
    });

    it('closes the credential modal via the close (X) control and via Done', () => {
        issueMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({ leaseId: 'lease-x', username: 'u', password: 'p' })
        );

        render(<LeasesPanel configId={5} canManage />);

        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
        expect(screen.getByText('Credential issued')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByText('Credential issued')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
        expect(screen.getByText('Credential issued')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('Credential issued')).not.toBeInTheDocument();
    });

    // G28: the one-time credential must not linger indefinitely with no explicit close.
    describe('auto-clear (G28)', () => {
        afterEach(() => {
            vi.useRealTimers();
        });

        it('auto-closes the credential modal after the idle timeout elapses, without an explicit close', async () => {
            issueMutate.mockImplementation((_vars, opts) =>
                opts.onSuccess({ leaseId: 'lease-idle', username: 'app_user', password: 'idle-secret' })
            );
            vi.useFakeTimers();

            render(<LeasesPanel configId={5} canManage />);
            fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
            expect(screen.getByText('idle-secret')).toBeInTheDocument();

            await act(async () => {
                await vi.advanceTimersByTimeAsync(DEFAULT_SENSITIVE_IDLE_MS);
            });

            expect(screen.queryByText('idle-secret')).not.toBeInTheDocument();
            expect(screen.queryByText('Credential issued')).not.toBeInTheDocument();
        });

        it('auto-closes the credential modal when the tab is backgrounded, without an explicit close', () => {
            issueMutate.mockImplementation((_vars, opts) =>
                opts.onSuccess({ leaseId: 'lease-bg', username: 'app_user', password: 'bg-secret' })
            );

            render(<LeasesPanel configId={5} canManage />);
            fireEvent.click(screen.getByRole('button', { name: /issue credential/i }));
            expect(screen.getByText('bg-secret')).toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
            act(() => {
                document.dispatchEvent(new Event('visibilitychange'));
            });

            expect(screen.queryByText('bg-secret')).not.toBeInTheDocument();
            expect(screen.queryByText('Credential issued')).not.toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
        });
    });
});
