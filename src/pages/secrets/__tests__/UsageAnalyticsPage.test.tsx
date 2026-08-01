import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { UsageAnalyticsPage } from '../UsageAnalyticsPage';

const { mostAccessedMock, unusedMock } = vi.hoisted(() => ({
    mostAccessedMock: vi.fn(),
    unusedMock: vi.fn(),
}));

vi.mock('../../../features/secrets/useUsageAnalytics', () => ({
    useMostAccessedSecrets: (params?: unknown) => mostAccessedMock(params),
    useUnusedSecrets: (params?: unknown) => unusedMock(params),
}));

const mostAccessedState = (overrides?: Partial<ReturnType<typeof defaultMostAccessed>>) => ({
    ...defaultMostAccessed(),
    ...overrides,
});

function defaultMostAccessed() {
    return { secrets: [] as unknown[], isLoading: false, error: null as unknown };
}

const unusedState = (overrides?: Partial<ReturnType<typeof defaultUnused>>) => ({
    ...defaultUnused(),
    ...overrides,
});

function defaultUnused() {
    return { secrets: [] as unknown[], isLoading: false, error: null as unknown };
}

// Locate a section card's content area by its heading text, scoping queries with `within`
// to avoid collisions when the same secret name appears in both sections.
function getSectionCard(headingText: string): HTMLElement {
    const heading = screen.getByRole('heading', { name: headingText });
    const card = heading.closest('.bg-surface');
    if (!card) throw new Error(`Could not find section card for heading "${headingText}"`);
    return card as HTMLElement;
}

beforeEach(() => {
    mostAccessedMock.mockReset();
    unusedMock.mockReset();
    mostAccessedMock.mockReturnValue(mostAccessedState());
    unusedMock.mockReturnValue(unusedState());
});

describe('UsageAnalyticsPage', () => {
    it('shows a loading indicator per section while each hook is loading', () => {
        mostAccessedMock.mockReturnValue(mostAccessedState({ isLoading: true }));
        unusedMock.mockReturnValue(unusedState({ isLoading: true }));
        render(<UsageAnalyticsPage />);

        const mostAccessedCard = getSectionCard('Most Accessed');
        const unusedCard = getSectionCard('Unused Secrets');
        expect(within(mostAccessedCard).getByText(/loading/i)).toBeInTheDocument();
        expect(within(unusedCard).getByText(/loading/i)).toBeInTheDocument();
    });

    it('renders only the most-accessed section as loading when unused has resolved', () => {
        mostAccessedMock.mockReturnValue(mostAccessedState({ isLoading: true }));
        unusedMock.mockReturnValue(unusedState({ isLoading: false }));
        render(<UsageAnalyticsPage />);

        const mostAccessedCard = getSectionCard('Most Accessed');
        const unusedCard = getSectionCard('Unused Secrets');
        expect(within(mostAccessedCard).getByText(/loading/i)).toBeInTheDocument();
        expect(
            within(unusedCard).getByText('Every secret has been read recently — nothing stale.')
        ).toBeInTheDocument();
    });

    // BUG (documented, not fixed per coverage-only scope): the page destructures only
    // `secrets`/`isLoading` from both hooks and never reads `error`. When a query errors,
    // `secrets` still defaults to `[]` and `isLoading` is `false`, so the UI silently falls
    // back to the generic empty-state copy ("No secret reads recorded...") instead of
    // surfacing any error indication to the user.
    it('falls back to the empty-state copy (not an error message) when a hook reports an error', () => {
        mostAccessedMock.mockReturnValue(
            mostAccessedState({ error: new Error('network down'), secrets: [], isLoading: false })
        );
        unusedMock.mockReturnValue(unusedState({ error: new Error('network down'), secrets: [], isLoading: false }));
        render(<UsageAnalyticsPage />);

        expect(screen.getByText('No secret reads recorded in this window.')).toBeInTheDocument();
        expect(screen.getByText('Every secret has been read recently — nothing stale.')).toBeInTheDocument();
        expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
    });

    it('renders the most-accessed list with rank, name, and pluralized read counts', () => {
        mostAccessedMock.mockReturnValue(
            mostAccessedState({
                secrets: [
                    { secret_id: 1, secret_name: 'db-password', read_count: 42, last_read: null },
                    { secret_id: 2, secret_name: 'api-key', read_count: 1, last_read: null },
                ],
            })
        );
        render(<UsageAnalyticsPage />);

        const card = getSectionCard('Most Accessed');
        expect(within(card).getByText('db-password')).toBeInTheDocument();
        expect(within(card).getByText('42 reads')).toBeInTheDocument();
        expect(within(card).getByText('api-key')).toBeInTheDocument();
        expect(within(card).getByText('1 read')).toBeInTheDocument();
        expect(within(card).getByText('1.')).toBeInTheDocument();
        expect(within(card).getByText('2.')).toBeInTheDocument();
    });

    it('renders unused secrets with relative last-read copy, including a distinct "never read" case', () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2026-01-15T12:00:00.000Z'));
        try {
            unusedMock.mockReturnValue(
                unusedState({
                    secrets: [
                        { secret_id: 10, secret_name: 'stale-token', last_read: '2026-01-14T12:00:00.000Z' },
                        { secret_id: 11, secret_name: 'ancient-cert', last_read: '2025-11-15T12:00:00.000Z' },
                        { secret_id: 12, secret_name: 'never-touched', last_read: null },
                    ],
                })
            );
            render(<UsageAnalyticsPage />);

            const card = getSectionCard('Unused Secrets');
            expect(within(card).getByText('stale-token')).toBeInTheDocument();
            expect(within(card).getByText('last read yesterday')).toBeInTheDocument();
            expect(within(card).getByText('ancient-cert')).toBeInTheDocument();
            expect(within(card).getByText('last read 2mo ago')).toBeInTheDocument();
            expect(within(card).getByText('never-touched')).toBeInTheDocument();
            expect(within(card).getByText('never read')).toBeInTheDocument();
            expect(within(card).getByText('3 secrets candidates for review or retirement')).toBeInTheDocument();
        } finally {
            vi.useRealTimers();
        }
    });

    it('shows independent empty states when one section has data and the other does not', () => {
        mostAccessedMock.mockReturnValue(
            mostAccessedState({
                secrets: [{ secret_id: 1, secret_name: 'shared-name', read_count: 5, last_read: null }],
            })
        );
        unusedMock.mockReturnValue(unusedState({ secrets: [] }));
        render(<UsageAnalyticsPage />);

        const mostAccessedCard = getSectionCard('Most Accessed');
        const unusedCard = getSectionCard('Unused Secrets');
        expect(within(mostAccessedCard).getByText('shared-name')).toBeInTheDocument();
        expect(
            within(unusedCard).getByText('Every secret has been read recently — nothing stale.')
        ).toBeInTheDocument();

        // Flip it: unused has data, most-accessed is empty — and reuse the same secret name
        // across sections to exercise the within() scoping this suite relies on.
        mostAccessedMock.mockReturnValue(mostAccessedState({ secrets: [] }));
        unusedMock.mockReturnValue(
            unusedState({ secrets: [{ secret_id: 2, secret_name: 'shared-name', last_read: null }] })
        );
        render(<UsageAnalyticsPage />);

        const mostAccessedCards = screen.getAllByText('No secret reads recorded in this window.');
        expect(mostAccessedCards.length).toBeGreaterThan(0);
        const unusedCards = screen.getAllByText('shared-name');
        expect(unusedCards.length).toBeGreaterThan(0);
    });

    it('defaults to a 30-day window and re-invokes both hooks with the new window on toggle', () => {
        render(<UsageAnalyticsPage />);

        expect(mostAccessedMock).toHaveBeenCalledWith({ days: 30, limit: 10 });
        expect(unusedMock).toHaveBeenCalledWith({ days: 30 });
        expect(screen.getByText(/over the last 30 days/)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: '60d' }));

        expect(mostAccessedMock).toHaveBeenLastCalledWith({ days: 60, limit: 10 });
        expect(unusedMock).toHaveBeenLastCalledWith({ days: 60 });
        expect(screen.getByText(/over the last 60 days/)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: '90d' }));

        expect(mostAccessedMock).toHaveBeenLastCalledWith({ days: 90, limit: 10 });
        expect(unusedMock).toHaveBeenLastCalledWith({ days: 90 });
        expect(screen.getByText(/over the last 90 days/)).toBeInTheDocument();
    });
});

afterEach(() => {
    vi.useRealTimers();
});
