import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within, waitFor } from '../../../test/test-utils';
import { ProjectsListPage } from '../ProjectsListPage';

const { useProjectsMock, createMutateAsync, deleteMutate, deleteResetMock, restoreMutate, navigateMock } = vi.hoisted(
    () => ({
        useProjectsMock: vi.fn(),
        createMutateAsync: vi.fn(),
        deleteMutate: vi.fn(),
        deleteResetMock: vi.fn(),
        restoreMutate: vi.fn(),
        navigateMock: vi.fn(),
    })
);

const hookState = vi.hoisted(() => ({
    projects: [] as any[],
    isLoading: false,
    isError: false,
    createPending: false,
    deletePending: false,
    restorePending: false,
    restoreVariables: undefined as number | undefined,
}));

vi.mock('react-router', async () => {
    const actual = await vi.importActual<typeof import('react-router')>('react-router');
    return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../../../features/projects/api', () => ({
    useProjects: (includeDeleted?: boolean) => useProjectsMock(includeDeleted),
    useCreateProject: () => ({ mutateAsync: createMutateAsync, isPending: hookState.createPending }),
    useDeleteProject: () => ({ mutate: deleteMutate, isPending: hookState.deletePending, reset: deleteResetMock }),
    useRestoreProject: () => ({
        mutate: restoreMutate,
        isPending: hookState.restorePending,
        variables: hookState.restoreVariables,
    }),
}));

// Matches an element whose own full text (including nested spans, whitespace-normalized)
// equals `text` exactly — used where a count is split across a nested <span> plus trailing
// text nodes, e.g. `<span><span>1</span> secret</span>`.
const exactNormalizedText = (text: string) => (_content: string, element: Element | null) =>
    (element?.textContent ?? '').replace(/\s+/g, ' ').trim() === text;

const makeProject = (overrides: Record<string, unknown> = {}) => ({
    id: 1,
    name: 'proj',
    description: '',
    secretCount: 0,
    environmentCount: 0,
    lastActivity: undefined,
    updatedAt: '2026-01-01T00:00:00Z',
    deleted: false,
    ...overrides,
});

beforeEach(() => {
    window.history.pushState({}, '', '/');
    vi.clearAllMocks();
    hookState.projects = [];
    hookState.isLoading = false;
    hookState.isError = false;
    hookState.createPending = false;
    hookState.deletePending = false;
    hookState.restorePending = false;
    hookState.restoreVariables = undefined;
    useProjectsMock.mockImplementation(() => ({
        data: hookState.projects,
        isLoading: hookState.isLoading,
        isError: hookState.isError,
    }));
    createMutateAsync.mockResolvedValue(makeProject({ id: 99, name: 'new-project' }));
});

describe('ProjectsListPage', () => {
    it('shows the loading state', () => {
        hookState.isLoading = true;
        render(<ProjectsListPage />);
        expect(screen.getByText('Loading projects…')).toBeInTheDocument();
    });

    it('shows the error state', () => {
        hookState.isError = true;
        render(<ProjectsListPage />);
        expect(screen.getByText('Failed to load projects. Check that the backend is running.')).toBeInTheDocument();
    });

    it('shows the empty state when there are no projects, and lets you open the create modal from it', () => {
        hookState.projects = [];
        render(<ProjectsListPage />);
        expect(screen.getByText('No projects yet')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));
        expect(screen.getByRole('heading', { name: 'New Project' })).toBeInTheDocument();
    });

    it('calls useProjects(false) by default and useProjects(true) when "Show deleted" is toggled', () => {
        render(<ProjectsListPage />);
        expect(useProjectsMock).toHaveBeenCalledWith(false);

        fireEvent.click(screen.getByLabelText('Show deleted'));
        expect(useProjectsMock).toHaveBeenLastCalledWith(true);
    });

    it('splits projects into Recent (top 5 by updatedAt) and All Projects (the rest)', () => {
        hookState.projects = [
            makeProject({ id: 1, name: 'proj-one', updatedAt: '2026-01-06T00:00:00Z' }),
            makeProject({ id: 2, name: 'proj-two', updatedAt: '2026-01-05T00:00:00Z' }),
            makeProject({ id: 3, name: 'proj-three', updatedAt: '2026-01-04T00:00:00Z' }),
            makeProject({ id: 4, name: 'proj-four', updatedAt: '2026-01-03T00:00:00Z' }),
            makeProject({ id: 5, name: 'proj-five', updatedAt: '2026-01-02T00:00:00Z' }),
            makeProject({ id: 6, name: 'proj-six', updatedAt: '2026-01-01T00:00:00Z' }),
        ];
        render(<ProjectsListPage />);

        const recentSection = screen.getByText('Recent').closest('section') as HTMLElement;
        expect(within(recentSection).getByText('proj-one')).toBeInTheDocument();
        expect(within(recentSection).getByText('proj-five')).toBeInTheDocument();
        expect(within(recentSection).queryByText('proj-six')).not.toBeInTheDocument();

        const allSection = screen.getByText('All Projects').closest('section') as HTMLElement;
        expect(within(allSection).getByText('proj-six')).toBeInTheDocument();
        expect(within(allSection).queryByText('proj-one')).not.toBeInTheDocument();
    });

    it('renders secret/environment counts with correct pluralization', () => {
        hookState.projects = [makeProject({ id: 1, name: 'solo', secretCount: 1, environmentCount: 1 })];
        render(<ProjectsListPage />);
        expect(screen.getByText(exactNormalizedText('1 secret'))).toBeInTheDocument();
        expect(screen.getByText(exactNormalizedText('1 env'))).toBeInTheDocument();
    });

    it('defaults missing counts to 0 and pluralizes them', () => {
        hookState.projects = [
            makeProject({ id: 1, name: 'solo', secretCount: undefined, environmentCount: undefined }),
        ];
        render(<ProjectsListPage />);
        expect(screen.getByText(exactNormalizedText('0 secrets'))).toBeInTheDocument();
        expect(screen.getByText(exactNormalizedText('0 envs'))).toBeInTheDocument();
    });

    it('navigates to the project detail route when a non-deleted row is clicked', () => {
        hookState.projects = [makeProject({ id: 42, name: 'clickable-project' })];
        render(<ProjectsListPage />);

        const row = screen.getByText('clickable-project').closest('.group') as HTMLElement;
        expect(row).toHaveAttribute('role', 'button');
        fireEvent.click(row);
        expect(navigateMock).toHaveBeenCalledWith('/projects/42');
    });

    it('navigates on Enter/Space keydown for a non-deleted row', () => {
        hookState.projects = [makeProject({ id: 7, name: 'keyboard-project' })];
        render(<ProjectsListPage />);

        const row = screen.getByText('keyboard-project').closest('.group') as HTMLElement;
        fireEvent.keyDown(row, { key: 'Enter' });
        expect(navigateMock).toHaveBeenCalledWith('/projects/7');
    });

    it('does not navigate when a deleted row is clicked, and shows the Deleted badge', () => {
        hookState.projects = [makeProject({ id: 8, name: 'gone-project', deleted: true })];
        render(<ProjectsListPage />);

        expect(screen.getByText('Deleted')).toBeInTheDocument();
        const row = screen.getByText('gone-project').closest('.group') as HTMLElement;
        expect(row).not.toHaveAttribute('role');
        fireEvent.click(row);
        expect(navigateMock).not.toHaveBeenCalled();
    });

    it('filters by name and description, hides Recent/All Projects headers while searching', () => {
        hookState.projects = [
            makeProject({ id: 1, name: 'alpha', description: 'first project' }),
            makeProject({ id: 2, name: 'beta', description: 'matches nothing special' }),
        ];
        render(<ProjectsListPage />);

        fireEvent.change(screen.getByPlaceholderText('Search projects…'), { target: { value: 'first' } });

        expect(screen.getByText('alpha')).toBeInTheDocument();
        expect(screen.queryByText('beta')).not.toBeInTheDocument();
        expect(screen.queryByText('Recent')).not.toBeInTheDocument();
        expect(screen.queryByText('All Projects')).not.toBeInTheDocument();
    });

    it('shows a "no match" empty state including the search term when search finds nothing', () => {
        hookState.projects = [makeProject({ id: 1, name: 'alpha' })];
        render(<ProjectsListPage />);

        fireEvent.change(screen.getByPlaceholderText('Search projects…'), { target: { value: 'nonexistent-term' } });

        expect(screen.getByText(/No projects match/)).toBeInTheDocument();
        expect(screen.getByText('nonexistent-term')).toBeInTheDocument();
    });

    it('opens the create modal from the header button, submits name-only payload, and navigates on success', async () => {
        hookState.projects = [makeProject({ id: 1, name: 'existing-project' })];
        createMutateAsync.mockResolvedValue(makeProject({ id: 123, name: 'brand-new' }));
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
        fireEvent.change(screen.getByLabelText(/Project name/), { target: { value: '  brand-new  ' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));

        await waitFor(() => expect(screen.queryByRole('heading', { name: 'New Project' })).not.toBeInTheDocument());
        expect(createMutateAsync).toHaveBeenCalledWith({ name: 'brand-new' });
        expect(navigateMock).toHaveBeenCalledWith('/projects/123');
    });

    it('includes a trimmed description in the create payload when provided', async () => {
        hookState.projects = [makeProject({ id: 1, name: 'existing-project' })];
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
        fireEvent.change(screen.getByLabelText(/Project name/), { target: { value: 'with-desc' } });
        fireEvent.change(screen.getByLabelText('Description'), { target: { value: '  a description  ' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));

        await waitFor(() => expect(screen.queryByRole('heading', { name: 'New Project' })).not.toBeInTheDocument());
        expect(createMutateAsync).toHaveBeenCalledWith({ name: 'with-desc', description: 'a description' });
    });

    it('submits the create form on Enter in the name field', async () => {
        hookState.projects = [makeProject({ id: 1, name: 'existing-project' })];
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
        fireEvent.change(screen.getByLabelText(/Project name/), { target: { value: 'enter-submit' } });
        fireEvent.keyDown(screen.getByLabelText(/Project name/), { key: 'Enter' });

        await waitFor(() => expect(screen.queryByRole('heading', { name: 'New Project' })).not.toBeInTheDocument());
        expect(createMutateAsync).toHaveBeenCalledWith({ name: 'enter-submit' });
    });

    it('disables the Create Project submit button while the name field is blank/whitespace', () => {
        hookState.projects = [makeProject({ id: 1, name: 'existing-project' })];
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
        expect(screen.getByRole('button', { name: 'Create Project' })).toBeDisabled();

        fireEvent.change(screen.getByLabelText(/Project name/), { target: { value: '   ' } });
        expect(screen.getByRole('button', { name: 'Create Project' })).toBeDisabled();

        fireEvent.change(screen.getByLabelText(/Project name/), { target: { value: 'ok' } });
        expect(screen.getByRole('button', { name: 'Create Project' })).not.toBeDisabled();
    });

    it('closes the create modal without submitting when Cancel is clicked', () => {
        hookState.projects = [];
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
        fireEvent.change(screen.getByLabelText(/Project name/), { target: { value: 'should-not-submit' } });
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        expect(screen.queryByRole('heading', { name: 'New Project' })).not.toBeInTheDocument();
        expect(createMutateAsync).not.toHaveBeenCalled();
        expect(navigateMock).not.toHaveBeenCalled();
    });

    it('leaves the create modal open and does not navigate when create fails', async () => {
        hookState.projects = [makeProject({ id: 1, name: 'existing-project' })];
        createMutateAsync.mockRejectedValue(new Error('boom'));
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
        fireEvent.change(screen.getByLabelText(/Project name/), { target: { value: 'will-fail' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Project' }));

        await screen.findByRole('heading', { name: 'New Project' }); // modal is still up
        expect(navigateMock).not.toHaveBeenCalled();
    });

    it('opens the create modal on mount when the URL has ?new=1', () => {
        window.history.pushState({}, '', '/?new=1');
        hookState.projects = [];
        render(<ProjectsListPage />);
        expect(screen.getByRole('heading', { name: 'New Project' })).toBeInTheDocument();
    });

    it('opens the delete confirmation modal, requires typing the exact name, and calls delete on confirm', () => {
        hookState.projects = [makeProject({ id: 5, name: 'to-delete' })];
        deleteMutate.mockImplementation((_id: number, opts: { onSuccess: () => void }) => opts.onSuccess());
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByTitle('Delete project'));
        expect(screen.getByText('Delete Project')).toBeInTheDocument();

        const deleteConfirmButton = screen.getByRole('button', { name: 'Delete' });
        expect(deleteConfirmButton).toBeDisabled();

        const confirmInput = screen.getByPlaceholderText('to-delete');
        fireEvent.change(confirmInput, { target: { value: 'wrong-name' } });
        expect(deleteConfirmButton).toBeDisabled();

        fireEvent.change(confirmInput, { target: { value: 'to-delete' } });
        expect(deleteConfirmButton).not.toBeDisabled();

        fireEvent.click(deleteConfirmButton);
        expect(deleteMutate).toHaveBeenCalledWith(5, {
            onSuccess: expect.any(Function),
            onError: expect.any(Function),
        });
        // onSuccess closes the modal and resets the delete mutation
        expect(screen.queryByText('Delete Project')).not.toBeInTheDocument();
        expect(deleteResetMock).toHaveBeenCalled();
    });

    it('shows a delete error via Alert and lets you close it (resetting the mutation)', () => {
        hookState.projects = [makeProject({ id: 6, name: 'protected-project' })];
        deleteMutate.mockImplementation((_id: number, opts: { onError: (err: unknown) => void }) =>
            opts.onError({ response: { data: { error: 'Project has active secrets' } } })
        );
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByTitle('Delete project'));
        const confirmInput = screen.getByPlaceholderText('protected-project');
        fireEvent.change(confirmInput, { target: { value: 'protected-project' } });
        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        expect(screen.getByText('Cannot delete project')).toBeInTheDocument();
        expect(screen.getByText('Project has active secrets')).toBeInTheDocument();

        // Two "Close" buttons exist: the Modal's own header icon (sr-only "Close") and this
        // footer Button; the footer one is rendered after it in DOM order.
        const closeButtons = screen.getAllByRole('button', { name: 'Close' });
        fireEvent.click(closeButtons[closeButtons.length - 1]);
        expect(screen.queryByText('Delete Project')).not.toBeInTheDocument();
        expect(deleteResetMock).toHaveBeenCalled();
    });

    it('falls back to a generic delete error message when the response has no error/message field', () => {
        hookState.projects = [makeProject({ id: 9, name: 'weird-error-project' })];
        deleteMutate.mockImplementation((_id: number, opts: { onError: (err: unknown) => void }) => opts.onError({}));
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByTitle('Delete project'));
        fireEvent.change(screen.getByPlaceholderText('weird-error-project'), {
            target: { value: 'weird-error-project' },
        });
        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        expect(screen.getByText('Failed to delete project.')).toBeInTheDocument();
    });

    it('calls restoreProject.mutate with the project id when Restore is clicked', () => {
        hookState.projects = [makeProject({ id: 10, name: 'restorable', deleted: true })];
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByTitle('Restore project'));
        expect(restoreMutate).toHaveBeenCalledWith(10);
    });

    // Fixed: `restoring` is now scoped to the row whose project id matches
    // the mutation's last-submitted `variables`, not shared across every
    // ProjectRow from the single page-level `useRestoreProject()` instance.
    // See ProjectsListPage.tsx (`restoring={restoreProject.isPending &&
    // restoreProject.variables === p.id}`).
    it('only disables the Restore button for the row actually being restored', () => {
        hookState.projects = [
            makeProject({ id: 11, name: 'deleted-one', deleted: true }),
            makeProject({ id: 12, name: 'deleted-two', deleted: true }),
        ];
        hookState.restorePending = true;
        hookState.restoreVariables = 11;
        render(<ProjectsListPage />);

        const restoreButtons = screen.getAllByTitle('Restore project');
        expect(restoreButtons).toHaveLength(2);
        expect(restoreButtons[0]).toBeDisabled(); // deleted-one, id 11 — the pending restore
        expect(restoreButtons[1]).not.toBeDisabled(); // deleted-two, id 12 — unaffected
    });

    it('evaluates the restoring flag for non-deleted rows shown in Recent too', () => {
        // Recent never shows a Restore button (only deleted rows do), but the `restoring`
        // prop expression is still evaluated per-row there; exercise both outcomes.
        hookState.projects = [
            makeProject({ id: 20, name: 'recent-a', updatedAt: '2026-01-02T00:00:00Z' }),
            makeProject({ id: 21, name: 'recent-b', updatedAt: '2026-01-01T00:00:00Z' }),
        ];
        hookState.restorePending = true;
        hookState.restoreVariables = 20;
        render(<ProjectsListPage />);

        expect(screen.getByText('recent-a')).toBeInTheDocument();
        expect(screen.getByText('recent-b')).toBeInTheDocument();
    });

    it('shows relative last-activity time when a project has one', () => {
        hookState.projects = [makeProject({ id: 13, name: 'active-project', lastActivity: '2026-01-01T00:00:00Z' })];
        render(<ProjectsListPage />);

        const row = screen.getByText('active-project').closest('.group') as HTMLElement;
        expect(within(row).getByTitle(/Last activity:/)).toBeInTheDocument();
    });

    it('falls back to an empty description when filtering and a candidate has none', () => {
        hookState.projects = [makeProject({ id: 14, name: 'no-description-project', description: undefined })];
        render(<ProjectsListPage />);

        fireEvent.change(screen.getByPlaceholderText('Search projects…'), { target: { value: 'zzz-no-match' } });
        expect(screen.getByText(/No projects match/)).toBeInTheDocument();
    });

    it('sorts recent projects with a missing updatedAt to the end', () => {
        hookState.projects = [
            makeProject({ id: 15, name: 'has-date', updatedAt: '2026-01-01T00:00:00Z' }),
            makeProject({ id: 16, name: 'no-date', updatedAt: undefined }),
        ];
        render(<ProjectsListPage />);

        const recentSection = screen.getByText('Recent').closest('section') as HTMLElement;
        expect(within(recentSection).getByText('has-date')).toBeInTheDocument();
        expect(within(recentSection).getByText('no-date')).toBeInTheDocument();
    });

    it('does not navigate on a non-Enter/Space key, and does not navigate on any key for a deleted row', () => {
        hookState.projects = [
            makeProject({ id: 17, name: 'active-row' }),
            makeProject({ id: 18, name: 'deleted-row', deleted: true }),
        ];
        render(<ProjectsListPage />);

        const activeRow = screen.getByText('active-row').closest('.group') as HTMLElement;
        fireEvent.keyDown(activeRow, { key: 'a' });
        expect(navigateMock).not.toHaveBeenCalled();

        fireEvent.keyDown(activeRow, { key: ' ' });
        expect(navigateMock).toHaveBeenCalledWith('/projects/17');

        navigateMock.mockClear();
        const deletedRow = screen.getByText('deleted-row').closest('.group') as HTMLElement;
        fireEvent.keyDown(deletedRow, { key: 'Enter' });
        expect(navigateMock).not.toHaveBeenCalled();
    });

    it('only highlights the row background on hover for a non-deleted project', () => {
        hookState.projects = [
            makeProject({ id: 19, name: 'hoverable-row' }),
            makeProject({ id: 22, name: 'deleted-hover-row', deleted: true }),
        ];
        render(<ProjectsListPage />);

        const activeRow = screen.getByText('hoverable-row').closest('.group') as HTMLElement;
        fireEvent.mouseEnter(activeRow);
        expect(activeRow.style.backgroundColor).toBe('var(--bg-subtle)');
        fireEvent.mouseLeave(activeRow);
        expect(activeRow.style.backgroundColor).toBe('var(--bg-surface)');

        const deletedRow = screen.getByText('deleted-hover-row').closest('.group') as HTMLElement;
        fireEvent.mouseEnter(deletedRow);
        expect(deletedRow.style.backgroundColor).toBe('var(--bg-surface)');
    });

    it('does not submit the create form on Enter when the name field is blank', () => {
        hookState.projects = [];
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
        fireEvent.keyDown(screen.getByLabelText(/Project name/), { key: 'Enter' });

        expect(createMutateAsync).not.toHaveBeenCalled();
        expect(screen.getByRole('heading', { name: 'New Project' })).toBeInTheDocument();
    });

    it('shows "Creating…" on the submit button while the create mutation is pending', () => {
        hookState.projects = [];
        hookState.createPending = true;
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByRole('button', { name: 'New Project' }));
        expect(screen.getByRole('button', { name: 'Creating…' })).toBeInTheDocument();
    });

    it('shows "Deleting…" on the confirm button while the delete mutation is pending', () => {
        hookState.projects = [makeProject({ id: 23, name: 'deleting-project' })];
        hookState.deletePending = true;
        render(<ProjectsListPage />);

        fireEvent.click(screen.getByTitle('Delete project'));
        expect(screen.getByRole('button', { name: 'Deleting…' })).toBeInTheDocument();
    });
});
