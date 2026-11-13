import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { AuditLogPage } from '../AuditLogPage';

// #4185: the actor, actor-type and event-type filters used to run over the 100 newest
// rows the page had loaded, so a machine identity's rows (id 77 among 259) were never
// found. They go to the server now. The real feed hook runs here; only the HTTP client
// is faked, and it answers like the server: the newest page without a filter, the
// matching rows (wherever they are) with one.

const apiGet = vi.fn();

vi.mock('../../../services/client', () => ({
    apiClient: { get: (...args: any[]) => apiGet(...args) },
    apiErrorMessage: (_e: unknown, fallback: string) => fallback,
}));
vi.mock('../../../features/dashboard', () => ({
    useAnomalyAlerts: () => ({ data: { data: { alerts: [] } }, isLoading: false }),
    useAcknowledgeAnomaly: () => ({ mutate: vi.fn() }),
}));
vi.mock('../../../features/admin', () => ({
    useRoles: () => ({ data: [] }),
    useGroups: () => ({ data: { groups: [], total: 0 } }),
}));

const row = (id: number, actor: string, actor_type: string, event_type: string) => ({
    id,
    event_type,
    actor,
    actor_type,
    description: `row ${id}`,
    timestamp: '2026-11-12T10:00:00Z',
});

// The newest page holds only human rows; ci-app's row (id 77) is older than all of them.
const newest = Array.from({ length: 100 }, (_, i) => row(259 - i, 'admin', 'user', 'secret.read'));
const ciRow = row(77, 'ci-app', 'machine_identity', 'secret.machine_read');

function serverAnswer(url: string, params: Record<string, unknown> = {}) {
    if (url === '/api/v1/audit/search') {
        const wanted = String(params.actor ?? '').toLowerCase();
        const events = [ciRow].filter((e) => e.actor.includes(wanted));
        return { data: { data: { events, next_cursor: null } } };
    }
    if (url === '/api/v1/audit/logs') {
        if (params.actor_type === 'machine_identity') return { data: { data: { logs: [ciRow], total: 1 } } };
        return { data: { data: { logs: newest, total: 259, total_exact: true, next_cursor: 'c1' } } };
    }
    return { data: { data: { users: [] } } };
}

const auditCalls = (url: string) => apiGet.mock.calls.filter(([u]) => u === url).map(([, cfg]) => cfg?.params ?? {});

beforeEach(() => {
    vi.clearAllMocks();
    apiGet.mockImplementation(async (url: string, cfg?: { params?: Record<string, unknown> }) =>
        serverAnswer(url, cfg?.params)
    );
    window.history.pushState({}, '', '/');
});

describe('AuditLogPage server-side filters (#4185)', () => {
    it('typing an actor asks the server and shows a row outside the newest 100', async () => {
        render(<AuditLogPage />);
        expect(await screen.findAllByText('admin')).not.toHaveLength(0);
        expect(screen.queryByText('ci-app')).not.toBeInTheDocument();

        fireEvent.change(screen.getByPlaceholderText('Filter by actor…'), { target: { value: 'ci-app' } });

        await waitFor(() =>
            expect(auditCalls('/api/v1/audit/search')).toContainEqual(expect.objectContaining({ actor: 'ci-app' }))
        );
        const table = within(await screen.findByRole('table'));
        expect(await table.findByText('ci-app')).toBeInTheDocument();
        expect(table.queryByText('admin')).not.toBeInTheDocument();
    });

    it('choosing Machine sends actor_type and shows the machine row', async () => {
        render(<AuditLogPage />);
        await screen.findAllByText('admin');

        fireEvent.click(screen.getByRole('button', { name: 'Machine' }));

        await waitFor(() =>
            expect(auditCalls('/api/v1/audit/logs')).toContainEqual(
                expect.objectContaining({ actor_type: 'machine_identity' })
            )
        );
        const table = within(await screen.findByRole('table'));
        expect(await table.findByText('ci-app')).toBeInTheDocument();
    });

    it('choosing an event type sends it as the action parameter', async () => {
        render(<AuditLogPage />);
        await screen.findAllByText('admin');

        fireEvent.change(screen.getByLabelText('Filter by event type'), { target: { value: 'secret.read' } });

        await waitFor(() =>
            expect(auditCalls('/api/v1/audit/logs')).toContainEqual(expect.objectContaining({ action: 'secret.read' }))
        );
    });

    it('sends nothing extra while no filter is set', async () => {
        render(<AuditLogPage />);
        await screen.findAllByText('admin');
        for (const p of auditCalls('/api/v1/audit/logs')) {
            expect(p).not.toHaveProperty('actor_type');
            expect(p).not.toHaveProperty('action');
        }
        expect(auditCalls('/api/v1/audit/search')).toHaveLength(0);
    });
});
