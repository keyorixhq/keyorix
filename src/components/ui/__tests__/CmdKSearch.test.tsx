import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { CmdKSearch } from '../CmdKSearch';
import { ROUTES } from '../../../constants';

const { mockUseProjects, mockGet, mockNavigate } = vi.hoisted(() => ({
    mockUseProjects: vi.fn(),
    mockGet: vi.fn(),
    mockNavigate: vi.fn(),
}));

vi.mock('../../../features/projects/api', () => ({
    useProjects: () => mockUseProjects(),
}));

vi.mock('../../../services/client', () => ({
    apiClient: { get: (...args: unknown[]) => mockGet(...args) },
}));

vi.mock('react-router-dom', async () => {
    const actual = await vi.importActual('react-router-dom');
    return { ...actual, useNavigate: () => mockNavigate };
});

const projects = [
    { id: 1, name: 'Alpha Project', description: 'Core alpha stuff' },
    { id: 2, name: 'Beta Project', description: 'special sauce backend' },
    { id: 3, name: 'Gamma', description: '' },
];

const emptySecretsResponse = { data: { data: { secrets: [] } } };

const onClose = vi.fn();

async function typeAndWaitForSettle(input: HTMLElement, value: string) {
    fireEvent.change(input, { target: { value } });
    // The search is debounced by 250ms before it fires; wait past that plus
    // the (mocked, resolved) async secrets request before asserting.
    await waitFor(() => expect(mockGet).toHaveBeenCalled(), { timeout: 1000 });
}

describe('CmdKSearch', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockUseProjects.mockReturnValue({ data: projects });
        mockGet.mockResolvedValue(emptySecretsResponse);
    });

    it('renders the palette with an empty, focused input and keyboard hints', () => {
        render(<CmdKSearch onClose={onClose} />);

        const input = screen.getByPlaceholderText('Search projects and secrets…');
        expect(input).toHaveValue('');
        expect(input).toHaveFocus();

        // Footer hints are shown while the query is empty.
        expect(screen.getByText('navigate')).toBeInTheDocument();
        expect(screen.getByText('open')).toBeInTheDocument();
        expect(screen.getByText('close')).toBeInTheDocument();

        // No results list yet since nothing has been typed.
        expect(screen.queryByRole('list')).not.toBeInTheDocument();
    });

    it('clicking the backdrop calls onClose', () => {
        render(<CmdKSearch onClose={onClose} />);

        fireEvent.click(screen.getByRole('button', { name: 'Close search' }));

        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('pressing Escape calls onClose', () => {
        render(<CmdKSearch onClose={onClose} />);

        const input = screen.getByPlaceholderText('Search projects and secrets…');
        fireEvent.keyDown(input, { key: 'Escape' });

        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('filters projects by a case-insensitive name substring match', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'alpha');

        await waitFor(() => expect(screen.getByText('Alpha Project')).toBeInTheDocument());
        expect(screen.queryByText('Beta Project')).not.toBeInTheDocument();
        expect(screen.queryByText('Gamma')).not.toBeInTheDocument();
    });

    it('filters projects by a description substring match', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'sauce');

        await waitFor(() => expect(screen.getByText('Beta Project')).toBeInTheDocument());
        expect(screen.queryByText('Alpha Project')).not.toBeInTheDocument();
    });

    it('calls the secrets search endpoint with the typed query and merges the results', async () => {
        mockGet.mockResolvedValue({
            data: {
                data: {
                    secrets: [
                        // PascalCase field variant (primary branch of each `??` fallback).
                        { ID: 10, Name: 'API_KEY_PROD', ProjectID: 3, environment_name: 'production' },
                        // snake_case / lowercase field variant with no project (fallback branches).
                        { id: 11, name: 'DB_PASSWORD', project_id: null, environment: 'staging' },
                    ],
                },
            },
        });

        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'key');

        expect(mockGet).toHaveBeenCalledWith('/api/v1/secrets', { params: { search: 'key', pageSize: 8 } });

        await waitFor(() => expect(screen.getByText('API_KEY_PROD')).toBeInTheDocument());
        expect(screen.getByText('production')).toBeInTheDocument();
        expect(screen.getByText('DB_PASSWORD')).toBeInTheDocument();
        expect(screen.getByText('staging')).toBeInTheDocument();

        const list = screen.getByRole('list');
        // Both entries are tagged with their result type.
        expect(within(list).getAllByText('secret')).toHaveLength(2);
    });

    it('builds an href with the project id and encoded environment for a secret with a project', async () => {
        mockGet.mockResolvedValue({
            data: {
                data: {
                    secrets: [{ ID: 10, Name: 'API_KEY_PROD', ProjectID: 3, environment_name: 'east coast' }],
                },
            },
        });

        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'key');
        await waitFor(() => expect(screen.getByText('API_KEY_PROD')).toBeInTheDocument());

        fireEvent.click(screen.getByText('API_KEY_PROD'));

        expect(mockNavigate).toHaveBeenCalledWith(`${ROUTES.PROJECT_DETAIL(3)}?env=east%20coast`);
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('falls back to /secrets when a secret result has no project id', async () => {
        mockGet.mockResolvedValue({
            data: {
                data: {
                    secrets: [{ id: 11, name: 'DB_PASSWORD', project_id: null, environment: 'staging' }],
                },
            },
        });

        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'db');
        await waitFor(() => expect(screen.getByText('DB_PASSWORD')).toBeInTheDocument());

        fireEvent.click(screen.getByText('DB_PASSWORD'));

        expect(mockNavigate).toHaveBeenCalledWith(ROUTES.SECRETS);
    });

    it('falls back to project-only results when the secrets request fails', async () => {
        mockGet.mockRejectedValue(new Error('network down'));

        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'alpha');

        await waitFor(() => expect(screen.getByText('Alpha Project')).toBeInTheDocument());
        // No secret entries were merged in since the request rejected.
        expect(screen.queryByText('secret')).not.toBeInTheDocument();
    });

    it('shows an empty-results message quoting the query when nothing matches', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'nonexistent-zzz');

        await waitFor(() => expect(screen.getByText('"nonexistent-zzz"')).toBeInTheDocument());
        expect(screen.getByText(/No results for/)).toBeInTheDocument();
    });

    it('hides the keyboard-hint footer once a query is typed', () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        fireEvent.change(input, { target: { value: 'a' } });

        expect(screen.queryByText('navigate')).not.toBeInTheDocument();
    });

    it('navigates via keyboard: ArrowDown moves the active result, Enter selects it', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        // Query matches both Alpha (id 1) and Beta (id 2) via name/description.
        await typeAndWaitForSettle(input, 'project');
        await waitFor(() => expect(screen.getByText('Alpha Project')).toBeInTheDocument());
        expect(screen.getByText('Beta Project')).toBeInTheDocument();

        // Alpha is first and active by default (activeIndex resets to 0 on new results).
        fireEvent.keyDown(input, { key: 'ArrowDown' });
        fireEvent.keyDown(input, { key: 'Enter' });

        expect(mockNavigate).toHaveBeenCalledWith(ROUTES.PROJECT_DETAIL(2));
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('ArrowUp clamps the active index at 0 and Enter selects the first result', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'project');
        await waitFor(() => expect(screen.getByText('Alpha Project')).toBeInTheDocument());

        // Already at index 0; ArrowUp must not go negative (Math.max clamp).
        fireEvent.keyDown(input, { key: 'ArrowUp' });
        fireEvent.keyDown(input, { key: 'Enter' });

        expect(mockNavigate).toHaveBeenCalledWith(ROUTES.PROJECT_DETAIL(1));
    });

    it('ArrowDown clamps at the last result and does not run past the end', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'project');
        await waitFor(() => expect(screen.getByText('Alpha Project')).toBeInTheDocument());

        // Two results (Alpha, Beta): press ArrowDown three times, should clamp at index 1 (Beta).
        fireEvent.keyDown(input, { key: 'ArrowDown' });
        fireEvent.keyDown(input, { key: 'ArrowDown' });
        fireEvent.keyDown(input, { key: 'ArrowDown' });
        fireEvent.keyDown(input, { key: 'Enter' });

        expect(mockNavigate).toHaveBeenCalledWith(ROUTES.PROJECT_DETAIL(2));
    });

    it('clicking a result navigates to its href and closes the palette', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'alpha');
        await waitFor(() => expect(screen.getByText('Alpha Project')).toBeInTheDocument());

        fireEvent.click(screen.getByText('Alpha Project'));

        expect(mockNavigate).toHaveBeenCalledWith(ROUTES.PROJECT_DETAIL(1));
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('hovering a result makes it the active (highlighted) one', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'project');
        await waitFor(() => expect(screen.getByText('Alpha Project')).toBeInTheDocument());

        const betaButton = screen.getByText('Beta Project').closest('button') as HTMLElement;
        fireEvent.mouseEnter(betaButton);
        fireEvent.keyDown(input, { key: 'Enter' });

        // Hovering Beta made it active, so Enter selects Beta rather than the
        // default first (Alpha) result.
        expect(mockNavigate).toHaveBeenCalledWith(ROUTES.PROJECT_DETAIL(2));
    });

    it('Enter is a no-op when there are no results to select', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'nonexistent-zzz');
        await waitFor(() => expect(screen.getByText(/No results for/)).toBeInTheDocument());

        fireEvent.keyDown(input, { key: 'Enter' });

        expect(mockNavigate).not.toHaveBeenCalled();
        expect(onClose).not.toHaveBeenCalled();
    });

    it('limits project matches to the first five', async () => {
        mockUseProjects.mockReturnValue({
            data: Array.from({ length: 8 }, (_, i) => ({
                id: i + 1,
                name: `Match Project ${i + 1}`,
                description: '',
            })),
        });

        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'match');

        await waitFor(() => expect(screen.getByText('Match Project 1')).toBeInTheDocument());
        expect(screen.getByText('Match Project 5')).toBeInTheDocument();
        expect(screen.queryByText('Match Project 6')).not.toBeInTheDocument();
    });

    // BUG (documented, not fixed per task scope): `isSearching` is only ever
    // reset to `false` by the `.finally()` of the debounced secrets request in
    // `useGlobalSearch`. When the query is cleared back to empty, the effect's
    // early-return branch (`if (!query.trim())`) never resets `isSearching`,
    // so a spinner that was mid-flight when the user cleared the box can be
    // left showing `true` indefinitely even though no results/list are
    // rendered anymore (the list itself is gated on `query.trim()` in the
    // component, so this doesn't produce a visible artifact today, but the
    // stale internal state would resurface as a incorrectly-persistent
    // spinner if the results list's visibility were ever decoupled from the
    // raw `query` in a future refactor).
    it('does not show a result list while the query is empty, even after a prior search', async () => {
        render(<CmdKSearch onClose={onClose} />);
        const input = screen.getByPlaceholderText('Search projects and secrets…');

        await typeAndWaitForSettle(input, 'alpha');
        await waitFor(() => expect(screen.getByText('Alpha Project')).toBeInTheDocument());

        fireEvent.change(input, { target: { value: '' } });

        expect(screen.queryByRole('list')).not.toBeInTheDocument();
        expect(screen.getByText('navigate')).toBeInTheDocument();
    });
});
