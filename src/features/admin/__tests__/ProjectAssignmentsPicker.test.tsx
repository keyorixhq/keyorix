import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { ProjectAssignmentsPicker } from '../ProjectAssignmentsPicker';
import type { ProjectAssignment } from '../../../services/users';

const projects = [
    { id: 1, name: 'Payments', deleted: false },
    { id: 2, name: 'Platform', deleted: false },
    { id: 3, name: 'Pricing', deleted: false },
    { id: 9, name: 'Archived', deleted: true },
];

vi.mock('../../projects/api', () => ({
    useProjects: () => ({ data: projects, isLoading: false, isError: false }),
}));

beforeEach(() => {
    vi.clearAllMocks();
});

describe('ProjectAssignmentsPicker', () => {
    it('filters projects by the typeahead query and excludes deleted ones', () => {
        render(<ProjectAssignmentsPicker assignments={[]} onChange={vi.fn()} />);
        fireEvent.change(screen.getByPlaceholderText(/search projects/i), { target: { value: 'pa' } });
        // "Payments" matches; "Pricing"/"Platform" don't contain "pa".
        expect(screen.getByRole('button', { name: 'Payments' })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Pricing' })).not.toBeInTheDocument();
        // Deleted projects never surface, even on a matching query.
        fireEvent.change(screen.getByPlaceholderText(/search projects/i), { target: { value: 'arch' } });
        expect(screen.queryByRole('button', { name: 'Archived' })).not.toBeInTheDocument();
        expect(screen.getByText(/no matching projects/i)).toBeInTheDocument();
    });

    it('adds a project with the default viewer role on click', () => {
        const onChange = vi.fn();
        render(<ProjectAssignmentsPicker assignments={[]} onChange={onChange} />);
        fireEvent.change(screen.getByPlaceholderText(/search projects/i), { target: { value: 'platform' } });
        fireEvent.click(screen.getByRole('button', { name: 'Platform' }));
        expect(onChange).toHaveBeenCalledWith([{ project_id: 2, project_name: 'Platform', role: 'project_viewer' }]);
    });

    it('hides already-assigned projects from the results', () => {
        const assignments: ProjectAssignment[] = [{ project_id: 1, project_name: 'Payments', role: 'project_admin' }];
        render(<ProjectAssignmentsPicker assignments={assignments} onChange={vi.fn()} />);
        fireEvent.change(screen.getByPlaceholderText(/search projects/i), { target: { value: 'pay' } });
        expect(screen.queryByRole('button', { name: 'Payments' })).not.toBeInTheDocument();
        expect(screen.getByText(/no matching projects/i)).toBeInTheDocument();
    });

    it('changes an assignment role and removes a row', () => {
        const onChange = vi.fn();
        const assignments: ProjectAssignment[] = [{ project_id: 1, project_name: 'Payments', role: 'project_viewer' }];
        render(<ProjectAssignmentsPicker assignments={assignments} onChange={onChange} />);

        fireEvent.change(screen.getByDisplayValue('Viewer'), { target: { value: 'project_admin' } });
        expect(onChange).toHaveBeenLastCalledWith([{ project_id: 1, project_name: 'Payments', role: 'project_admin' }]);

        fireEvent.click(screen.getByTitle(/remove assignment/i));
        expect(onChange).toHaveBeenLastCalledWith([]);
    });
});
