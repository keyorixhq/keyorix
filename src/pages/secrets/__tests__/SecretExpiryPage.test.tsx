import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { SecretExpiryPage } from '../SecretExpiryPage';
import { Secret } from '../../../types';

const { listMock } = vi.hoisted(() => ({
    listMock: vi.fn(),
}));

vi.mock('../../../services/secrets', () => ({
    secretsApi: {
        list: listMock,
    },
}));

// Fixed "now" so day-threshold bucketing (expired / soon / future) is deterministic
// rather than computed off the real clock. Midnight UTC keeps daysRemaining() exact.
const NOW = new Date('2024-01-15T00:00:00.000Z');

const makeSecret = (overrides: Partial<Secret> = {}): Secret => ({
    id: 1,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2024-01-01T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    Expiration: null,
    ...overrides,
});

// One secret per bucket, chosen to also exercise the exact day thresholds used by
// statusBucket()/daysRemaining() in the source: < 0 = expired, 0..30 = soon, > 30 = future.
const expiredSecret = makeSecret({
    id: 1,
    name: 'expired-api-key',
    type: 'api_key',
    environment: 'production',
    Expiration: '2024-01-10T00:00:00.000Z', // 5 days ago
});
const soonSecret = makeSecret({
    id: 2,
    name: 'soon-cert',
    type: 'certificate',
    environment: 'staging',
    Expiration: '2024-02-14T00:00:00.000Z', // exactly 30 days out -> still "soon"
});
const futureSecret = makeSecret({
    id: 3,
    name: 'future-json-blob',
    type: 'json',
    environment: 'production',
    Expiration: '2024-02-15T00:00:00.000Z', // exactly 31 days out -> "future"
});
const todaySecret = makeSecret({
    id: 4,
    name: 'expires-today',
    type: 'text',
    environment: 'production',
    Expiration: '2024-01-15T00:00:00.000Z', // 0 days -> "soon", label "Today"
});
const noExpirySecret = makeSecret({
    id: 5,
    name: 'no-expiry-secret',
    type: 'password',
    environment: 'production',
    Expiration: null,
});

function listResponse(secrets: Secret[], total?: number) {
    return {
        data: secrets,
        total: total ?? secrets.length,
        page: 1,
        pageSize: 500,
        totalPages: 1,
    };
}

describe('SecretExpiryPage', () => {
    beforeEach(() => {
        vi.resetAllMocks();
        // setSystemTime alone (without useFakeTimers) mocks Date without touching
        // setTimeout — real timers stay live, so findBy/waitFor's own polling
        // still works instead of freezing forever.
        vi.setSystemTime(NOW);
        window.history.pushState({}, '', '/');
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('shows a loading state while the query is in flight', async () => {
        listMock.mockImplementation(() => new Promise(() => {}));
        render(<SecretExpiryPage />);

        expect(await screen.findByText('Loading...')).toBeInTheDocument();
        expect(screen.getByText('Secret Expiry')).toBeInTheDocument();
    });

    it('shows an error state with a working retry action', async () => {
        listMock.mockRejectedValue(new Error('network down'));
        render(<SecretExpiryPage />);

        expect(await screen.findByText('Failed to load secrets')).toBeInTheDocument();
        expect(screen.getByText('There was an error fetching secrets. Please try again.')).toBeInTheDocument();

        listMock.mockResolvedValueOnce(listResponse([]));
        fireEvent.click(screen.getByRole('button', { name: 'Retry' }));

        expect(await screen.findByText('No secrets with expiration')).toBeInTheDocument();
        expect(listMock).toHaveBeenCalledTimes(2);
    });

    it('shows the empty state for the "all" tab when nothing has an expiration', async () => {
        listMock.mockResolvedValue(listResponse([noExpirySecret]));
        render(<SecretExpiryPage />);

        expect(await screen.findByText('No secrets with expiration')).toBeInTheDocument();
        expect(screen.getByText('Set an expiration date on a secret to track it here.')).toBeInTheDocument();
        // secrets without an Expiration are excluded entirely, including from the summary cards
        expect(screen.getByText('All (0)')).toBeInTheDocument();
    });

    it('buckets secrets into expired/soon/future and renders summary counts + rows', async () => {
        listMock.mockResolvedValue(
            listResponse([expiredSecret, soonSecret, futureSecret, todaySecret, noExpirySecret])
        );
        render(<SecretExpiryPage />);

        await screen.findByText('expired-api-key');

        // withExpiry excludes noExpirySecret, so 4 remain across the three buckets
        expect(screen.getByText('All (4)')).toBeInTheDocument();
        expect(screen.getByText('Expired (1)')).toBeInTheDocument();
        // soonSecret (30d) + todaySecret (0d) both land in "soon"
        expect(screen.getByText('Expiring Soon (2)')).toBeInTheDocument();
        expect(screen.getByText('Future (1)')).toBeInTheDocument();

        // rows are sorted ascending by days remaining: expired(-5) < today(0) < soon(30) < future(31)
        const rows = screen.getAllByRole('row').slice(1); // drop header row
        expect(rows).toHaveLength(4);
        expect(within(rows[0]!).getByText('expired-api-key')).toBeInTheDocument();
        expect(within(rows[1]!).getByText('expires-today')).toBeInTheDocument();
        expect(within(rows[2]!).getByText('soon-cert')).toBeInTheDocument();
        expect(within(rows[3]!).getByText('future-json-blob')).toBeInTheDocument();

        // day-left + status labels for the boundary cases
        expect(within(rows[0]!).getByText('5d ago')).toBeInTheDocument();
        expect(within(rows[0]!).getByText('Expired')).toBeInTheDocument();
        expect(within(rows[1]!).getByText('Today')).toBeInTheDocument();
        expect(within(rows[2]!).getByText('30d')).toBeInTheDocument();
        expect(within(rows[2]!).getByText('Expiring Soon')).toBeInTheDocument();
        expect(within(rows[3]!).getByText('31d')).toBeInTheDocument();
        expect(within(rows[3]!).getByText('Active')).toBeInTheDocument();

        // footer summary count (5 total secrets fetched, 4 of which have an expiration set)
        expect(screen.getByText(/Showing 4 of 4 secrets with expiration dates set/)).toBeInTheDocument();
    });

    it('filters the table when the Expired tab is selected', async () => {
        listMock.mockResolvedValue(listResponse([expiredSecret, soonSecret, futureSecret]));
        render(<SecretExpiryPage />);

        await screen.findByText('expired-api-key');
        expect(screen.getByText('future-json-blob')).toBeInTheDocument();

        // "Expired (1)" (the tab nav button) is unambiguous — the Expired summary
        // card above it also renders the word "Expired" but as "1" + "Expired" in
        // separate nodes, so it doesn't collide with this accessible name.
        fireEvent.click(screen.getByRole('button', { name: 'Expired (1)' }));

        expect(screen.getByText('expired-api-key')).toBeInTheDocument();
        expect(screen.queryByText('soon-cert')).not.toBeInTheDocument();
        expect(screen.queryByText('future-json-blob')).not.toBeInTheDocument();
    });

    it('shows the tab-specific empty state when a bucket has no matches', async () => {
        listMock.mockResolvedValue(listResponse([expiredSecret]));
        render(<SecretExpiryPage />);

        await screen.findByText('expired-api-key');

        fireEvent.click(screen.getByRole('button', { name: 'Future (0)' }));

        expect(screen.getByText('No future expirations')).toBeInTheDocument();
        expect(screen.getByText('No secrets with expiration dates beyond 30 days.')).toBeInTheDocument();
    });

    it('filters by name or environment via the search input, scoped to the active tab', async () => {
        listMock.mockResolvedValue(listResponse([expiredSecret, soonSecret, futureSecret]));
        render(<SecretExpiryPage />);

        await screen.findByText('expired-api-key');

        const search = screen.getByPlaceholderText('Filter by name or environment…');
        fireEvent.change(search, { target: { value: 'staging' } });

        // only soon-cert has environment "staging"
        expect(screen.getByText('soon-cert')).toBeInTheDocument();
        expect(screen.queryByText('expired-api-key')).not.toBeInTheDocument();
        expect(screen.queryByText('future-json-blob')).not.toBeInTheDocument();

        fireEvent.change(search, { target: { value: 'future-json' } });
        expect(screen.getByText('future-json-blob')).toBeInTheDocument();
        expect(screen.queryByText('soon-cert')).not.toBeInTheDocument();
    });

    it('links each row to the all-secrets view, sorted and highlighting that secret', async () => {
        listMock.mockResolvedValue(listResponse([expiredSecret]));
        render(<SecretExpiryPage />);

        const link = await screen.findByRole('link', { name: /View/ });
        expect(link).toHaveAttribute('href', '/secrets?sort=expiry_asc&highlight=1');
    });

    it('notes when results are truncated to the first 500 secrets', async () => {
        listMock.mockResolvedValue(listResponse([expiredSecret], 600));
        render(<SecretExpiryPage />);

        expect(await screen.findByText(/fetched from first 500 secrets/)).toBeInTheDocument();
    });

    it('requests up to 500 secrets from the API', async () => {
        listMock.mockResolvedValue(listResponse([]));
        render(<SecretExpiryPage />);

        await screen.findByText('No secrets with expiration');
        expect(listMock).toHaveBeenCalledWith({ pageSize: 500 });
    });
});
