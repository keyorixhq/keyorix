import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '../../../test/test-utils';
import { BackupRefusedBanner } from '../BackupRefusedBanner';
import { useAuthStore } from '../../../store/authStore';
import type { User } from '../../../types';

// Real useSystemInfo hook; only the network layer is mocked.
const getInfo = vi.fn();
vi.mock('../../../services/system', () => ({
    systemApi: { getInfo: (...args: unknown[]) => getInfo(...args) },
}));

const setSession = (isAuthenticated: boolean) =>
    useAuthStore.setState({
        isAuthenticated,
        user: isAuthenticated ? ({ id: 1 } as unknown as User) : null,
    });

const info = (security: Record<string, unknown>) => ({ version: 'v1', security });

const REMEDY =
    'Check that no `admin encryption rotate-kek` is running, then move the staging file out of the key directory.';

const expectNoBanner = async () => {
    await waitFor(() => expect(getInfo).toHaveBeenCalledTimes(1));
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByTestId('backup-refused-banner')).not.toBeInTheDocument();
};

describe('BackupRefusedBanner (WEB-POSTURE-NOV-1, #4105)', () => {
    beforeEach(() => {
        getInfo.mockReset();
        setSession(true);
    });

    it('shows what happened, the files and the server remedy while backups are refused', async () => {
        getInfo.mockResolvedValue(
            info({
                backup_refused: {
                    reason: 'key-rotation-staging-file',
                    files: ['keys/kek.salt.pending'],
                    staging_salt_only: true,
                    remedy: REMEDY,
                },
            })
        );
        render(<BackupRefusedBanner />);
        const banner = await screen.findByTestId('backup-refused-banner');
        expect(banner).toHaveAttribute('role', 'alert');
        expect(banner).toHaveTextContent('Backups are refused');
        expect(banner).toHaveTextContent('keys/kek.salt.pending');
        expect(banner).toHaveTextContent('(exit 4)');
        expect(banner).toHaveTextContent(REMEDY);
        expect(banner).toHaveTextContent('docs/operator/j6-key-rotation.md');
    });

    it('names the check failure with its own exit code', async () => {
        getInfo.mockResolvedValue(
            info({ backup_refused: { reason: 'staging-file-check-failed', remedy: 'Fix the key directory.' } })
        );
        render(<BackupRefusedBanner />);
        const banner = await screen.findByTestId('backup-refused-banner');
        expect(banner).toHaveTextContent('could not check the key directory');
        expect(banner).toHaveTextContent('(exit 1)');
    });

    it('renders nothing when the field is absent (backups not refused, or not an admin)', async () => {
        getInfo.mockResolvedValue(info({ audit_enabled: true }));
        render(<BackupRefusedBanner />);
        await expectNoBanner();
    });

    it('goes away when the field clears on a later response', async () => {
        getInfo.mockResolvedValue(
            info({
                backup_refused: {
                    reason: 'key-rotation-staging-file',
                    files: ['keys/kek.salt.pending'],
                    remedy: REMEDY,
                },
            })
        );
        const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
        render(
            <QueryClientProvider client={queryClient}>
                <BackupRefusedBanner />
            </QueryClientProvider>
        );
        expect(await screen.findByTestId('backup-refused-banner')).toBeInTheDocument();

        // The operator moved the file: the next system info response omits the field.
        getInfo.mockResolvedValue(info({ audit_enabled: true }));
        await queryClient.invalidateQueries({ queryKey: ['systemInfo'] });
        await waitFor(() => expect(screen.queryByTestId('backup-refused-banner')).not.toBeInTheDocument());
    });

    it('does not ask the server when signed out', async () => {
        setSession(false);
        render(<BackupRefusedBanner />);
        await new Promise((r) => setTimeout(r, 20));
        expect(getInfo).not.toHaveBeenCalled();
        expect(screen.queryByTestId('backup-refused-banner')).not.toBeInTheDocument();
    });
});
