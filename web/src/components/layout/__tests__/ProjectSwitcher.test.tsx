import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { ProjectSwitcher } from '../ProjectSwitcher';
import { useProjectMruStore } from '../../../store';
import type { Project } from '../../../services/projects';

const { navigateMock, useProjectsMock } = vi.hoisted(() => ({
    navigateMock: vi.fn(),
    useProjectsMock: vi.fn(),
}));

vi.mock('react-router', async (importOriginal) => {
    const actual = (await importOriginal()) as object;
    return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../../../features/projects/api', () => ({
    useProjects: () => useProjectsMock(),
}));

const projects: Project[] = [
    { id: 1, name: 'Payments', secretCount: 3, environmentCount: 2 },
    { id: 2, name: 'Platform', secretCount: 0 },
    { id: 3, name: 'Pricing' },
];

function setPath(path: string) {
    window.history.pushState({}, '', path);
}

describe('ProjectSwitcher', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        useProjectMruStore.setState({ recentIds: [] });
        useProjectsMock.mockReturnValue({ data: projects, isLoading: false });
        setPath('/');
    });

    it('shows a loading label on the trigger while projects are loading', () => {
        useProjectsMock.mockReturnValue({ data: undefined, isLoading: true });
        render(<ProjectSwitcher />);
        expect(screen.getByText('Loading…')).toBeInTheDocument();
    });

    it('shows a placeholder trigger label when no project is active', () => {
        render(<ProjectSwitcher />);
        expect(screen.getByText('Select project')).toBeInTheDocument();
    });

    it('shows the current project name on the trigger when the URL matches a project', () => {
        setPath('/projects/2');
        render(<ProjectSwitcher />);
        expect(screen.getByText('Platform')).toBeInTheDocument();
    });

    it('renders an empty state when there are no projects', () => {
        useProjectsMock.mockReturnValue({ data: [], isLoading: false });
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        expect(screen.getByText('No projects yet')).toBeInTheDocument();
    });

    it('opens the dropdown and lists all projects (capped at 5) when there is no MRU history', () => {
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        expect(screen.getByPlaceholderText('Search projects…')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Payments/ })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Platform/ })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Pricing/ })).toBeInTheDocument();
        // No recentIds recorded yet, so no "Recent" heading.
        expect(screen.queryByText('Recent')).not.toBeInTheDocument();
    });

    it('shows a secret/environment count subline only when secretCount is present', () => {
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        expect(screen.getByText('3 secrets · 2 envs')).toBeInTheDocument();
        expect(screen.getByText('0 secrets')).toBeInTheDocument();
        // "Pricing" has no secretCount at all, so it renders no subline.
        const pricingButton = screen.getByRole('button', { name: /Pricing/ });
        expect(within(pricingButton).queryByText(/secret/)).not.toBeInTheDocument();
    });

    it('orders the list by MRU recency and labels the section "Recent" when history exists', () => {
        useProjectMruStore.setState({ recentIds: [3, 1] });
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        expect(screen.getByText('Recent')).toBeInTheDocument();

        const list = screen.getByPlaceholderText('Search projects…').closest('div')!.parentElement!
            .nextElementSibling as HTMLElement;
        const names = within(list)
            .getAllByRole('button')
            .map((btn) => within(btn).getByText(/Payments|Platform|Pricing/).textContent);
        // Pricing (id 3) most-recent, then Payments (id 1), then Platform (unranked, list order).
        expect(names).toEqual(['Pricing', 'Payments', 'Platform']);
    });

    it('filters the list by name when searching, ignoring MRU order', () => {
        useProjectMruStore.setState({ recentIds: [2] });
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        fireEvent.change(screen.getByPlaceholderText('Search projects…'), { target: { value: 'pri' } });

        expect(screen.getByRole('button', { name: /Pricing/ })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /Payments/ })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /Platform/ })).not.toBeInTheDocument();
        // "Recent" heading is search-mode-only suppressed.
        expect(screen.queryByText('Recent')).not.toBeInTheDocument();
    });

    it('shows a "no matches" message including the query when search yields nothing', () => {
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        fireEvent.change(screen.getByPlaceholderText('Search projects…'), { target: { value: 'zzz' } });
        expect(screen.getByText('No projects matching "zzz"')).toBeInTheDocument();
    });

    it('marks the current project with a check icon in the list, unlike other rows', () => {
        setPath('/projects/1');
        render(<ProjectSwitcher />);
        // Trigger's accessible name is exactly "Payments" (no other text), so this is unambiguous
        // even though the dropdown row will also expose "Payments" once it renders.
        fireEvent.click(screen.getByRole('button', { name: 'Payments' }));

        const paymentsMatches = screen.getAllByRole('button', { name: /Payments/ });
        expect(paymentsMatches).toHaveLength(2); // trigger + list row
        const paymentsRow = paymentsMatches[1];
        expect(paymentsRow.querySelectorAll('svg')).toHaveLength(2); // folder icon + check icon

        const platformRow = screen.getByRole('button', { name: /Platform/ });
        expect(platformRow.querySelectorAll('svg')).toHaveLength(1); // folder icon only, no check
    });

    it('selecting a project navigates to its detail page, closes the dropdown, and calls onNavigate', () => {
        const onNavigate = vi.fn();
        render(<ProjectSwitcher onNavigate={onNavigate} />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        fireEvent.click(screen.getByRole('button', { name: /Platform/ }));

        expect(navigateMock).toHaveBeenCalledWith('/projects/2');
        expect(onNavigate).toHaveBeenCalledTimes(1);
        expect(screen.queryByPlaceholderText('Search projects…')).not.toBeInTheDocument();
    });

    it('selecting a project clears any in-progress search', () => {
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        fireEvent.change(screen.getByPlaceholderText('Search projects…'), { target: { value: 'pay' } });
        fireEvent.click(screen.getByRole('button', { name: /Payments/ }));

        // Selecting doesn't change the mocked navigate's target location, so the trigger
        // still reads "Select project" — reopen through it and check search was reset.
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        expect(screen.getByPlaceholderText('Search projects…')).toHaveValue('');
    });

    it('"New project" navigates to the create-project flow and closes the dropdown', () => {
        const onNavigate = vi.fn();
        render(<ProjectSwitcher onNavigate={onNavigate} />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        fireEvent.click(screen.getByRole('button', { name: /New project/i }));

        expect(navigateMock).toHaveBeenCalledWith('/projects?new=1');
        expect(onNavigate).toHaveBeenCalledTimes(1);
        expect(screen.queryByPlaceholderText('Search projects…')).not.toBeInTheDocument();
    });

    it('"All projects" is a real link to /projects and closes the dropdown on click', () => {
        const onNavigate = vi.fn();
        render(<ProjectSwitcher onNavigate={onNavigate} />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));

        const allProjectsLink = screen.getByRole('link', { name: /All projects/i });
        expect(allProjectsLink).toHaveAttribute('href', '/projects');

        fireEvent.click(allProjectsLink);
        expect(onNavigate).toHaveBeenCalledTimes(1);
        expect(screen.queryByPlaceholderText('Search projects…')).not.toBeInTheDocument();
    });

    it('toggles the dropdown closed when the trigger is clicked again', () => {
        render(<ProjectSwitcher />);
        const trigger = screen.getByRole('button', { name: 'Select project' });
        fireEvent.click(trigger);
        expect(screen.getByPlaceholderText('Search projects…')).toBeInTheDocument();
        fireEvent.click(trigger);
        expect(screen.queryByPlaceholderText('Search projects…')).not.toBeInTheDocument();
    });

    it('closes the dropdown and clears search on an outside click', () => {
        render(
            <div>
                <div data-testid="outside">outside</div>
                <ProjectSwitcher />
            </div>
        );
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        fireEvent.change(screen.getByPlaceholderText('Search projects…'), { target: { value: 'pay' } });

        fireEvent.mouseDown(screen.getByTestId('outside'));
        expect(screen.queryByPlaceholderText('Search projects…')).not.toBeInTheDocument();

        // Reopen: search should have been reset by the outside click too.
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        expect(screen.getByPlaceholderText('Search projects…')).toHaveValue('');
    });

    it('does not close when clicking inside the dropdown container', () => {
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        const searchInput = screen.getByPlaceholderText('Search projects…');
        fireEvent.mouseDown(searchInput);
        expect(screen.getByPlaceholderText('Search projects…')).toBeInTheDocument();
    });

    it('shows a singular "secret" label (no trailing "s") when secretCount is exactly 1', () => {
        useProjectsMock.mockReturnValue({
            data: [{ id: 4, name: 'Solo', secretCount: 1 }],
            isLoading: false,
        });
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));
        expect(screen.getByText('1 secret')).toBeInTheDocument();
    });

    it('applies a hover background on the trigger only while the dropdown is closed', () => {
        render(<ProjectSwitcher />);
        const trigger = screen.getByRole('button', { name: 'Select project' });

        // Closed: hover sets the subtle background, then clears it on leave.
        // (Checked via the raw style property rather than toHaveStyle — jsdom
        // normalizes the 'transparent' keyword to an rgba() value on read-back.)
        fireEvent.mouseEnter(trigger);
        expect(trigger.style.backgroundColor).toBe('var(--bg-subtle)');
        fireEvent.mouseLeave(trigger);
        expect(trigger.style.backgroundColor).toBe('transparent');

        // Open: hover/leave must not touch the trigger's background.
        fireEvent.click(trigger);
        fireEvent.mouseEnter(trigger);
        expect(trigger.style.backgroundColor).toBe('var(--bg-subtle)');
        fireEvent.mouseLeave(trigger);
        expect(trigger.style.backgroundColor).toBe('var(--bg-subtle)');
    });

    it('applies and clears a hover background on project rows, the "All projects" link, and "New project"', () => {
        render(<ProjectSwitcher />);
        fireEvent.click(screen.getByRole('button', { name: 'Select project' }));

        const row = screen.getByRole('button', { name: /Payments/ });
        fireEvent.mouseEnter(row);
        expect(row).toHaveStyle({ backgroundColor: 'var(--bg-subtle)' });
        fireEvent.mouseLeave(row);
        expect(row).toHaveStyle({ backgroundColor: '' });

        const allProjectsLink = screen.getByRole('link', { name: /All projects/i });
        fireEvent.mouseEnter(allProjectsLink);
        expect(allProjectsLink).toHaveStyle({ backgroundColor: 'var(--bg-subtle)' });
        fireEvent.mouseLeave(allProjectsLink);
        expect(allProjectsLink).toHaveStyle({ backgroundColor: '' });

        const newProjectButton = screen.getByRole('button', { name: /New project/i });
        fireEvent.mouseEnter(newProjectButton);
        expect(newProjectButton).toHaveStyle({ backgroundColor: 'var(--bg-subtle)' });
        fireEvent.mouseLeave(newProjectButton);
        expect(newProjectButton).toHaveStyle({ backgroundColor: '' });
    });
});
