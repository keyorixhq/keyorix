import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { AuditLogPage } from '../AuditLogPage';

const useAuditLog = vi.fn();
const useAnomalyAlerts = vi.fn();
const acknowledgeMutate = vi.fn();

vi.mock('../../../features/audit', () => ({
    useAuditLog: (...args: any[]) => useAuditLog(...args),
}));

vi.mock('../../../features/dashboard', () => ({
    useAnomalyAlerts: (...args: any[]) => useAnomalyAlerts(...args),
    useAcknowledgeAnomaly: () => ({ mutate: acknowledgeMutate }),
}));

const entries = [
    {
        id: 1,
        event_type: 'auth.login',
        actor: 'alice',
        actor_type: 'user',
        description: 'Logged in',
        timestamp: '2026-01-01T10:00:00Z',
    },
    {
        id: 2,
        event_type: 'secret.read',
        actor: 'bob',
        actor_type: 'user',
        description: 'Read a secret',
        timestamp: '2026-01-10T10:00:00Z',
    },
    {
        id: 3,
        event_type: 'rbac.role.assigned',
        actor: 'ci-bot',
        actor_type: 'machine_identity',
        description: 'Assigned role admin',
        timestamp: '2026-01-15T10:00:00Z',
    },
];

function mockAuditLog(
    overrides: Partial<{ isLoading: boolean; error: unknown; total: number; page: number; totalPages: number }> = {}
) {
    useAuditLog.mockReturnValue({
        data: {
            data: entries,
            total: overrides.total ?? entries.length,
            page: overrides.page ?? 1,
            pageSize: 100,
            totalPages: overrides.totalPages ?? 1,
        },
        isLoading: overrides.isLoading ?? false,
        error: overrides.error ?? null,
    });
}

function mockAnomalies(alerts: any[] = [], isLoading = false) {
    useAnomalyAlerts.mockReturnValue({ data: { data: { alerts } }, isLoading });
}

beforeEach(() => {
    vi.clearAllMocks();
    mockAuditLog();
    mockAnomalies();
    window.history.pushState({}, '', '/');
});

describe('AuditLogPage — audit tab', () => {
    it('renders every entry with its event badge and total count', () => {
        render(<AuditLogPage />);
        expect(
            screen.getByText('Complete record of all secret access and system events', { exact: false })
        ).toBeInTheDocument();
        expect(screen.getByText('3 events')).toBeInTheDocument();

        // Scope to the table: "Login" also appears as an <option> in the event-type filter.
        const table = within(screen.getByRole('table'));
        expect(table.getByText('Login')).toBeInTheDocument();
        expect(table.getByText('Read')).toBeInTheDocument();
        expect(table.getByText('alice')).toBeInTheDocument();
        expect(table.getByText('bob')).toBeInTheDocument();
        expect(table.getByText('machine')).toBeInTheDocument(); // ci-bot's machine badge
    });

    it('filters by actor', () => {
        render(<AuditLogPage />);
        fireEvent.change(screen.getByPlaceholderText('Filter by actor…'), { target: { value: 'alice' } });

        expect(screen.getByText('alice')).toBeInTheDocument();
        expect(screen.queryByText('bob')).not.toBeInTheDocument();
        expect(screen.getByText('1 event')).toBeInTheDocument();
    });

    it('filters by event type', () => {
        render(<AuditLogPage />);
        fireEvent.change(screen.getByLabelText('Filter by event type'), { target: { value: 'secret.read' } });

        expect(screen.getByText('bob')).toBeInTheDocument();
        expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });

    it('filters by actor type', () => {
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Machine' }));

        expect(screen.getByText('ci-bot')).toBeInTheDocument();
        expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });

    it('filters by date range', () => {
        render(<AuditLogPage />);
        fireEvent.change(screen.getByLabelText('From date'), { target: { value: '2026-01-05' } });

        expect(screen.queryByText('alice')).not.toBeInTheDocument(); // Jan 1, before the range
        expect(screen.getByText('bob')).toBeInTheDocument(); // Jan 10
    });

    it('shows an error alert when the query fails', () => {
        mockAuditLog({ error: new Error('network down') });
        render(<AuditLogPage />);
        expect(screen.getByText('Failed to load audit log')).toBeInTheDocument();
    });

    it('exports the currently filtered entries as CSV', () => {
        (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
        (URL as any).revokeObjectURL = vi.fn();
        const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        render(<AuditLogPage />);
        fireEvent.click(screen.getByTitle('Export as CSV'));

        expect(URL.createObjectURL).toHaveBeenCalled();
        expect(clickSpy).toHaveBeenCalled();
        clickSpy.mockRestore();
    });
});

describe('AuditLogPage — url filter banner', () => {
    it('shows the banner for a known filter and clears it', () => {
        window.history.pushState({}, '', '/audit?filter=logins');
        render(<AuditLogPage />);

        expect(screen.getByText('Filtered:')).toBeInTheDocument();
        expect(screen.getByText('Login events')).toBeInTheDocument();

        fireEvent.click(screen.getByText('✕ Clear filter'));
        expect(window.location.search).toBe('?tab=audit');
    });
});

describe('AuditLogPage — RBAC tab', () => {
    it('shows the governance banner and only rbac.* events', () => {
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: 'RBAC Events' }));

        expect(screen.getByText('Access governance events')).toBeInTheDocument();
        expect(screen.getByText('ci-bot')).toBeInTheDocument();
        expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });
});

describe('AuditLogPage — Anomaly Alerts tab', () => {
    const alert = {
        ID: 1,
        AlertType: 'unusual_access_time',
        SecretName: 'db-password',
        AccessedBy: 'alice',
        IPAddress: '10.0.0.1',
        Severity: 'high',
        DetectedAt: '2026-01-01T00:00:00Z',
        Acknowledged: false,
        Description: 'Accessed outside business hours',
    };

    it('shows an unacknowledged-count badge on the tab', () => {
        mockAnomalies([alert]);
        render(<AuditLogPage />);
        const anomaliesTab = screen.getByRole('button', { name: /anomaly alerts/i });
        expect(within(anomaliesTab).getByText('1')).toBeInTheDocument();
    });

    it('lists alerts, expands details, and dismisses (acknowledges) one', () => {
        mockAnomalies([alert]);
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));

        expect(screen.getByText('db-password')).toBeInTheDocument();
        expect(screen.getByText('Unusual Access Time')).toBeInTheDocument();

        fireEvent.click(screen.getByText('db-password'));
        expect(screen.getByText('Accessed outside business hours')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
        expect(acknowledgeMutate).toHaveBeenCalledWith(1);
    });

    it('shows an empty state when there are no anomalies', () => {
        mockAnomalies([]);
        render(<AuditLogPage />);
        fireEvent.click(screen.getByRole('button', { name: /anomaly alerts/i }));
        expect(screen.getByText('No anomalies detected')).toBeInTheDocument();
    });
});

describe('AuditLogPage — initial tab from URL', () => {
    it('opens directly on the anomalies tab when ?tab=anomalies', () => {
        window.history.pushState({}, '', '/audit?tab=anomalies');
        mockAnomalies([]);
        render(<AuditLogPage />);
        expect(screen.getByText('No anomalies detected')).toBeInTheDocument();
    });
});
