import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { MachineIdentitiesPage } from '../MachineIdentitiesPage';

const mockReport = vi.fn();
const getMock = vi.fn();

vi.mock('../../../features/admin', () => ({
    useMachineIdentitiesAuditReport: () => mockReport(),
}));

vi.mock('../../../services/client', () => ({
    apiClient: { get: (...args: any[]) => getMock(...args) },
}));

beforeEach(() => {
    mockReport.mockReset();
    getMock.mockReset();
    // jsdom has no object-URL API; stub it for the CSV download.
    (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as any).revokeObjectURL = vi.fn();
});

describe('MachineIdentitiesPage', () => {
    it('shows the summary counts and the machine table', () => {
        mockReport.mockReturnValue({
            isLoading: false,
            isError: false,
            data: {
                generated_at: '2026-07-01T00:00:00Z',
                total_count: 2,
                stale_count: 1,
                revoked_count: 0,
                machines: [
                    {
                        machine_id: 1,
                        name: 'github-actions-deploy',
                        description: 'CI deploy runner',
                        credential_count: 2,
                        last_used_at: null,
                        is_stale: true,
                        is_revoked: false,
                        created_at: '2026-01-01T00:00:00Z',
                    },
                    {
                        machine_id: 2,
                        name: 'k8s-prod-rotator',
                        description: '',
                        credential_count: 1,
                        last_used_at: '2026-07-01T00:00:00Z',
                        is_stale: false,
                        is_revoked: false,
                        created_at: '2026-02-01T00:00:00Z',
                    },
                ],
            },
        });

        render(<MachineIdentitiesPage />);

        expect(screen.getByText('github-actions-deploy')).toBeInTheDocument();
        expect(screen.getByText('k8s-prod-rotator')).toBeInTheDocument();
        // "Stale" appears both as the summary stat label and the row status badge.
        expect(screen.getAllByText('Stale').length).toBeGreaterThanOrEqual(2);
        expect(screen.getByText('Active')).toBeInTheDocument();
    });

    it('shows an empty state when there are no machine identities', () => {
        mockReport.mockReturnValue({
            isLoading: false,
            isError: false,
            data: { generated_at: '', total_count: 0, stale_count: 0, revoked_count: 0, machines: [] },
        });

        render(<MachineIdentitiesPage />);
        expect(screen.getByText('No machine identities yet.')).toBeInTheDocument();
    });

    it('shows an error state on failure', () => {
        mockReport.mockReturnValue({ isLoading: false, isError: true, data: undefined });
        render(<MachineIdentitiesPage />);
        expect(screen.getByText('Failed to load machine identities')).toBeInTheDocument();
    });

    it('exports the CSV report on click', async () => {
        mockReport.mockReturnValue({
            isLoading: false,
            isError: false,
            data: { generated_at: '', total_count: 0, stale_count: 0, revoked_count: 0, machines: [] },
        });
        getMock.mockResolvedValue({ data: new Blob(['csv']) });

        render(<MachineIdentitiesPage />);
        fireEvent.click(screen.getByRole('button', { name: /export csv/i }));

        await waitFor(() =>
            expect(getMock).toHaveBeenCalledWith('/api/v1/machine-identities/audit.csv', {
                responseType: 'blob',
            })
        );
    });

    it('shows a loading spinner while the report is loading', () => {
        mockReport.mockReturnValue({ isLoading: true, isError: false, data: undefined });
        render(<MachineIdentitiesPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('renders a revoked status badge, revoked stat tone, and a dash for missing created_at', () => {
        mockReport.mockReturnValue({
            isLoading: false,
            isError: false,
            data: {
                generated_at: '2026-07-01T00:00:00Z',
                total_count: 1,
                stale_count: 0,
                revoked_count: 1,
                machines: [
                    {
                        machine_id: 3,
                        name: 'legacy-runner',
                        description: '',
                        credential_count: 0,
                        last_used_at: null,
                        is_stale: false,
                        is_revoked: true,
                        created_at: null,
                    },
                ],
            },
        });

        render(<MachineIdentitiesPage />);
        expect(screen.getByText('legacy-runner')).toBeInTheDocument();
        // "Revoked" appears both as the summary stat label and the row status badge.
        expect(screen.getAllByText('Revoked').length).toBeGreaterThanOrEqual(2);
        expect(screen.getByText('—')).toBeInTheDocument();
    });

    it('surfaces the server-provided message when the CSV export fails', async () => {
        mockReport.mockReturnValue({
            isLoading: false,
            isError: false,
            data: { generated_at: '', total_count: 0, stale_count: 0, revoked_count: 0, machines: [] },
        });
        getMock.mockRejectedValue({ response: { data: { message: 'Export disabled' } } });

        render(<MachineIdentitiesPage />);
        fireEvent.click(screen.getByRole('button', { name: /export csv/i }));

        expect(await screen.findByText('Export disabled')).toBeInTheDocument();
    });

    it('falls back to the server error field when there is no message', async () => {
        mockReport.mockReturnValue({
            isLoading: false,
            isError: false,
            data: { generated_at: '', total_count: 0, stale_count: 0, revoked_count: 0, machines: [] },
        });
        getMock.mockRejectedValue({ response: { data: { error: 'Not authorized' } } });

        render(<MachineIdentitiesPage />);
        fireEvent.click(screen.getByRole('button', { name: /export csv/i }));

        expect(await screen.findByText('Not authorized')).toBeInTheDocument();
    });

    it('falls back to a generic export error message when the server gives no detail', async () => {
        mockReport.mockReturnValue({
            isLoading: false,
            isError: false,
            data: { generated_at: '', total_count: 0, stale_count: 0, revoked_count: 0, machines: [] },
        });
        getMock.mockRejectedValue(new Error('network down'));

        render(<MachineIdentitiesPage />);
        fireEvent.click(screen.getByRole('button', { name: /export csv/i }));

        expect(await screen.findByText('Failed to export.')).toBeInTheDocument();
    });
});
