import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { BillingPage } from '../BillingPage';
import type { BillingReport } from '../../../services/billing';

const { useBillingReportMock } = vi.hoisted(() => ({ useBillingReportMock: vi.fn() }));

vi.mock('../../../features/billing', () => ({
    useBillingReport: (params: unknown) => useBillingReportMock(params),
}));

function defaultState() {
    return {
        report: undefined as BillingReport | undefined,
        isLoading: false,
        isError: false,
        error: null as unknown,
        isLicenseRequired: false,
    };
}

const reportState = (overrides?: Partial<ReturnType<typeof defaultState>>) => ({
    ...defaultState(),
    ...overrides,
});

const sampleReport = (): BillingReport => ({
    from: '2026-01-01T00:00:00Z',
    to: '2026-02-01T00:00:00Z',
    generatedAt: '2026-02-01T00:00:00Z',
    totals: {
        projects: 2,
        secretCount: 12,
        secretReads: 340,
        secretWrites: 20,
        secretRotations: 3,
        uniqueUsers: 5,
        machineReads: 100,
    },
    projects: [
        {
            projectId: 1,
            projectName: 'acme-prod',
            secretCount: 8,
            secretReads: 300,
            secretWrites: 15,
            secretRotations: 2,
            uniqueUsers: 4,
            machineReads: 90,
        },
        {
            projectId: 2,
            projectName: 'acme-staging',
            secretCount: 4,
            secretReads: 40,
            secretWrites: 5,
            secretRotations: 1,
            uniqueUsers: 2,
            machineReads: 10,
        },
    ],
});

beforeEach(() => {
    useBillingReportMock.mockReset();
    useBillingReportMock.mockReturnValue(reportState());
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-02-15T12:00:00.000Z'));
});

afterEach(() => {
    vi.useRealTimers();
});

describe('BillingPage', () => {
    it('shows a loading skeleton while the report is loading', () => {
        useBillingReportMock.mockReturnValue(reportState({ isLoading: true }));
        const { container } = render(<BillingPage />);

        expect(container.querySelector('.animate-pulse')).toBeInTheDocument();
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });

    it('shows the commercial-license notice when the report is license-gated', () => {
        useBillingReportMock.mockReturnValue(
            reportState({ isError: true, error: new Error('license'), isLicenseRequired: true })
        );
        render(<BillingPage />);

        expect(screen.getByText('FinOps billing reports are a commercial feature')).toBeInTheDocument();
        expect(screen.queryByText(/administrators \(system\.read\)/)).not.toBeInTheDocument();
    });

    it('shows a permission-specific message on a non-license 403', () => {
        useBillingReportMock.mockReturnValue(
            reportState({
                isError: true,
                error: { response: { status: 403 } },
                isLicenseRequired: false,
            })
        );
        render(<BillingPage />);

        expect(screen.getByText('Billing reports are available to administrators (system.read).')).toBeInTheDocument();
        expect(screen.queryByText('FinOps billing reports are a commercial feature')).not.toBeInTheDocument();
    });

    it('shows a generic message for a non-403 error', () => {
        useBillingReportMock.mockReturnValue(
            reportState({ isError: true, error: new Error('boom'), isLicenseRequired: false })
        );
        render(<BillingPage />);

        expect(screen.getByText('Could not load the billing report. Try again shortly.')).toBeInTheDocument();
    });

    it('renders totals and a per-project table sorted by reads descending', () => {
        useBillingReportMock.mockReturnValue(reportState({ report: sampleReport() }));
        render(<BillingPage />);

        expect(screen.getByText('340')).toBeInTheDocument(); // totals.secretReads
        expect(screen.getByText('12')).toBeInTheDocument(); // totals.secretCount

        const rows = screen.getAllByRole('row').slice(1); // drop header row
        expect(rows[0]).toHaveTextContent('acme-prod');
        expect(rows[1]).toHaveTextContent('acme-staging');
    });

    it('shows the empty state when the report has no project activity', () => {
        useBillingReportMock.mockReturnValue(
            reportState({
                report: { ...sampleReport(), projects: [], totals: { ...sampleReport().totals, projects: 0 } },
            })
        );
        render(<BillingPage />);

        expect(screen.getByText('No secrets or activity recorded for any project in this window.')).toBeInTheDocument();
    });

    it('falls back to "(project <id>)" when a project has no name', () => {
        const report = sampleReport();
        report.projects[0].projectName = '';
        useBillingReportMock.mockReturnValue(reportState({ report }));
        render(<BillingPage />);

        expect(screen.getByText('(project 1)')).toBeInTheDocument();
    });

    it('defaults to the "This month" preset and recomputes the window on preset change', () => {
        render(<BillingPage />);

        const firstCall = useBillingReportMock.mock.calls[0][0];
        expect(firstCall.from).toBe(new Date(Date.UTC(2026, 1, 1)).toISOString());
        expect(firstCall.to).toBe(new Date(Date.UTC(2026, 1, 15)).toISOString());

        fireEvent.click(screen.getByRole('button', { name: 'Last 30 days' }));

        const lastCall = useBillingReportMock.mock.calls[useBillingReportMock.mock.calls.length - 1][0];
        expect(lastCall.from).toBe(new Date(Date.UTC(2026, 1, 15) - 30 * 86_400_000).toISOString());
        expect(lastCall.to).toBe(new Date(Date.UTC(2026, 1, 15)).toISOString());
    });

    it('switches to a custom range when a date input is edited directly', () => {
        render(<BillingPage />);

        fireEvent.change(screen.getByLabelText('From date'), { target: { value: '2026-01-05' } });

        const lastCall = useBillingReportMock.mock.calls[useBillingReportMock.mock.calls.length - 1][0];
        expect(lastCall.from).toBe('2026-01-05T00:00:00Z');
    });

    it('switches to a custom range when the "To date" input is edited directly', () => {
        render(<BillingPage />);

        fireEvent.change(screen.getByLabelText('To date'), { target: { value: '2026-01-20' } });

        const lastCall = useBillingReportMock.mock.calls[useBillingReportMock.mock.calls.length - 1][0];
        expect(lastCall.to).toBe('2026-01-20T00:00:00Z');
    });

    it('computes the "Last month" window', () => {
        render(<BillingPage />);

        fireEvent.click(screen.getByRole('button', { name: 'Last month' }));

        const lastCall = useBillingReportMock.mock.calls[useBillingReportMock.mock.calls.length - 1][0];
        expect(lastCall.from).toBe(new Date(Date.UTC(2026, 0, 1)).toISOString());
        expect(lastCall.to).toBe(new Date(Date.UTC(2026, 1, 1)).toISOString());
    });

    it('computes the "Last 90 days" window', () => {
        render(<BillingPage />);

        fireEvent.click(screen.getByRole('button', { name: 'Last 90 days' }));

        const lastCall = useBillingReportMock.mock.calls[useBillingReportMock.mock.calls.length - 1][0];
        expect(lastCall.from).toBe(new Date(Date.UTC(2026, 1, 15) - 90 * 86_400_000).toISOString());
        expect(lastCall.to).toBe(new Date(Date.UTC(2026, 1, 15)).toISOString());
    });
});
