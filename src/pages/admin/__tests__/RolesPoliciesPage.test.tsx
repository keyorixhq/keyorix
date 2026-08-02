import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { RolesPoliciesPage } from '../RolesPoliciesPage';
import type { Permission, RoleWithPermissions } from '../../../types/rbac';

const {
    useRoles,
    usePermissions,
    createMutate,
    createReset,
    updateMutate,
    updateReset,
    deleteMutate,
    deleteReset,
    assignMutate,
    removeMutate,
} = vi.hoisted(() => ({
    useRoles: vi.fn(),
    usePermissions: vi.fn(),
    createMutate: vi.fn(),
    createReset: vi.fn(),
    updateMutate: vi.fn(),
    updateReset: vi.fn(),
    deleteMutate: vi.fn(),
    deleteReset: vi.fn(),
    assignMutate: vi.fn(),
    removeMutate: vi.fn(),
}));

const mutationState = vi.hoisted(() => ({
    create: { isPending: false, isError: false },
    update: { isPending: false, isError: false },
    delete: { isPending: false, isError: false },
    assign: { isPending: false },
    remove: { isPending: false },
}));

vi.mock('../../../features/admin', () => ({
    useRoles: (...args: any[]) => useRoles(...args),
    usePermissions: (...args: any[]) => usePermissions(...args),
    useCreateRole: () => ({ mutate: createMutate, reset: createReset, ...mutationState.create }),
    useUpdateRole: () => ({ mutate: updateMutate, reset: updateReset, ...mutationState.update }),
    useDeleteRole: () => ({ mutate: deleteMutate, reset: deleteReset, ...mutationState.delete }),
    useAssignPermissionToRole: () => ({ mutate: assignMutate, ...mutationState.assign }),
    useRemovePermissionFromRole: () => ({ mutate: removeMutate, ...mutationState.remove }),
}));

const permRead: Permission = {
    id: 1,
    name: 'Read Secrets',
    description: 'Can read secret values',
    resource: 'secrets',
    action: 'read',
};
const permWrite: Permission = {
    id: 2,
    name: 'Write Secrets',
    description: 'Can create and update secrets',
    resource: 'secrets',
    action: 'write',
};
const permViewRoles: Permission = {
    id: 3,
    name: 'View Roles',
    description: 'Can view roles',
    resource: 'rbac',
    action: 'read',
};
const allPermissions: Permission[] = [permRead, permWrite, permViewRoles];

// 'admin' is a BUILT_IN_ROLES entry — used to exercise the built-in delete-protection UI.
const roleDeveloper: RoleWithPermissions = {
    id: 1,
    name: 'developer',
    description: 'Writes and ships code',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    permissions: [permRead],
};
const roleAdmin: RoleWithPermissions = {
    id: 2,
    name: 'admin',
    description: '',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    permissions: [permRead, permWrite],
};

beforeEach(() => {
    vi.clearAllMocks();
    mutationState.create = { isPending: false, isError: false };
    mutationState.update = { isPending: false, isError: false };
    mutationState.delete = { isPending: false, isError: false };
    mutationState.assign = { isPending: false };
    mutationState.remove = { isPending: false };
    useRoles.mockReturnValue({ data: [roleDeveloper, roleAdmin], isLoading: false, error: null });
    usePermissions.mockReturnValue({ data: allPermissions, isLoading: false });
});

const getRoleCard = (name: string) => screen.getByText(name).closest('.rounded-xl') as HTMLElement;

// The "Permissions" tab button shares its accessible name with each role card's
// "Permissions" (manage) button, so it must be scoped to the tab bar via its
// unique "Roles" sibling rather than queried globally.
const switchToPermissionsTab = () => {
    const tabBar = screen.getByRole('button', { name: 'Roles' }).closest('div') as HTMLElement;
    fireEvent.click(within(tabBar).getByRole('button', { name: 'Permissions' }));
};

describe('RolesPoliciesPage — roles list states', () => {
    it('shows a loading spinner while roles are loading', () => {
        useRoles.mockReturnValue({ data: undefined, isLoading: true, error: null });
        render(<RolesPoliciesPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an empty state when there are no roles', () => {
        useRoles.mockReturnValue({ data: [], isLoading: false, error: null });
        render(<RolesPoliciesPage />);
        expect(screen.getByText('No roles found.')).toBeInTheDocument();
    });

    it('shows an error state when the roles query fails', () => {
        useRoles.mockReturnValue({ data: undefined, isLoading: false, error: new Error('boom') });
        render(<RolesPoliciesPage />);
        expect(screen.getByText('Failed to load roles. Please try again.')).toBeInTheDocument();
    });

    it('renders each role card with name, description and permission count', () => {
        render(<RolesPoliciesPage />);
        expect(screen.getByText('developer')).toBeInTheDocument();
        expect(screen.getByText('Writes and ships code')).toBeInTheDocument();
        expect(screen.getByText('1 permission')).toBeInTheDocument();
        expect(screen.getByText('admin')).toBeInTheDocument();
        expect(screen.getByText('2 permissions')).toBeInTheDocument();
    });

    it('marks the built-in role and disables its delete button', () => {
        render(<RolesPoliciesPage />);
        const adminCard = getRoleCard('admin');
        expect(within(adminCard).getByText('Built-in')).toBeInTheDocument();
        const deleteBtn = within(adminCard).getByTitle('Built-in roles cannot be deleted');
        expect(deleteBtn).toBeDisabled();

        const devCard = getRoleCard('developer');
        expect(within(devCard).queryByText('Built-in')).not.toBeInTheDocument();
        expect(within(devCard).getByTitle('Delete role')).not.toBeDisabled();
    });

    it('does not open the delete modal when clicking a disabled built-in delete button', () => {
        render(<RolesPoliciesPage />);
        const adminCard = getRoleCard('admin');
        fireEvent.click(within(adminCard).getByTitle('Built-in roles cannot be deleted'));
        expect(screen.queryByText(/this action cannot be undone/i)).not.toBeInTheDocument();
    });

    it('does not show "No roles found" when the roles query has no data yet (not loading, not errored)', () => {
        useRoles.mockReturnValue({ data: undefined, isLoading: false, error: null });
        render(<RolesPoliciesPage />);
        expect(screen.queryByText('No roles found.')).not.toBeInTheDocument();
        expect(screen.queryByText('developer')).not.toBeInTheDocument();
    });

    it('swaps the edit and delete buttons to their hover colors on mouse enter and back on leave', () => {
        render(<RolesPoliciesPage />);
        const devCard = getRoleCard('developer');

        const editButton = within(devCard).getByTitle('Edit role');
        fireEvent.mouseEnter(editButton);
        expect(editButton.style.color).toBe('var(--text-primary)');
        fireEvent.mouseLeave(editButton);
        expect(editButton.style.color).toBe('var(--text-muted)');

        const deleteButton = within(devCard).getByTitle('Delete role');
        fireEvent.mouseEnter(deleteButton);
        expect(deleteButton.style.color).toBe('rgb(239, 68, 68)');
        fireEvent.mouseLeave(deleteButton);
        expect(deleteButton.style.color).toBe('var(--text-muted)');
    });

    it('does not tint the built-in role delete button on hover', () => {
        render(<RolesPoliciesPage />);
        const adminCard = getRoleCard('admin');
        const deleteButton = within(adminCard).getByTitle('Built-in roles cannot be deleted');
        fireEvent.mouseEnter(deleteButton);
        expect(deleteButton.style.color).toBe('var(--text-muted)');
    });
});

describe('RolesPoliciesPage — create role', () => {
    it('disables Create until a name is entered, and submits name + description', async () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(screen.getByRole('button', { name: 'New Role' }));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByRole('button', { name: 'Create' })).toBeDisabled();

        fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'auditor-lite' } });
        fireEvent.change(within(dialog).getByLabelText('Description'), {
            target: { value: 'Read-only audit access' },
        });
        expect(within(dialog).getByRole('button', { name: 'Create' })).not.toBeDisabled();

        fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
        expect(createMutate).toHaveBeenCalledWith(
            { name: 'auditor-lite', description: 'Read-only audit access' },
            expect.anything()
        );
    });

    it('resets the create mutation and clears the form each time the modal is opened', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(screen.getByRole('button', { name: 'New Role' }));
        expect(createReset).toHaveBeenCalledTimes(1);
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'temp' } });
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        fireEvent.click(screen.getByRole('button', { name: 'New Role' }));
        expect(createReset).toHaveBeenCalledTimes(2);
        expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('');
    });

    it('closes the modal on successful create', () => {
        createMutate.mockImplementation((_body, opts) => opts.onSuccess());
        render(<RolesPoliciesPage />);
        fireEvent.click(screen.getByRole('button', { name: 'New Role' }));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'auditor-lite' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('shows an error message when the create mutation fails', () => {
        mutationState.create = { isPending: false, isError: true };
        render(<RolesPoliciesPage />);
        fireEvent.click(screen.getByRole('button', { name: 'New Role' }));
        expect(screen.getByText('Failed to create role. Please try again.')).toBeInTheDocument();
    });

    it('closes the create modal via the dialog close button without submitting', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(screen.getByRole('button', { name: 'New Role' }));
        fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'draft-role' } });

        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });
});

describe('RolesPoliciesPage — edit role', () => {
    it('prefills the form from the clicked role and submits an update', () => {
        render(<RolesPoliciesPage />);
        const devCard = getRoleCard('developer');
        fireEvent.click(within(devCard).getByTitle('Edit role'));

        const dialog = screen.getByRole('dialog');
        expect((within(dialog).getByLabelText('Name') as HTMLInputElement).value).toBe('developer');
        expect((within(dialog).getByLabelText('Description') as HTMLTextAreaElement).value).toBe(
            'Writes and ships code'
        );

        fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'Updated description' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));

        expect(updateMutate).toHaveBeenCalledWith(
            { id: 1, body: { name: 'developer', description: 'Updated description' } },
            expect.anything()
        );
    });

    it('closes the modal on successful update', () => {
        updateMutate.mockImplementation((_vars, opts) => opts.onSuccess());
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByTitle('Edit role'));
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('shows an error message when the update mutation fails', () => {
        mutationState.update = { isPending: false, isError: true };
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('admin')).getByTitle('Edit role'));
        expect(screen.getByText('Failed to update role. Please try again.')).toBeInTheDocument();
    });

    it('lets the name be edited directly and closes on Cancel without submitting', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByTitle('Edit role'));

        const dialog = screen.getByRole('dialog');
        fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'developer-renamed' } });
        expect((within(dialog).getByLabelText('Name') as HTMLInputElement).value).toBe('developer-renamed');

        fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(updateMutate).not.toHaveBeenCalled();
    });

    it('closes the edit modal via the dialog close button', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByTitle('Edit role'));
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
});

describe('RolesPoliciesPage — delete role', () => {
    it('asks for confirmation and deletes the role', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByTitle('Delete role'));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText(/this action cannot be undone/i)).toBeInTheDocument();
        expect(within(dialog).getByText('developer')).toBeInTheDocument();

        fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
        expect(deleteMutate).toHaveBeenCalledWith(1, expect.anything());
    });

    it('resets the delete mutation and closes on cancel', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByTitle('Delete role'));
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(deleteReset).toHaveBeenCalled();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('closes the modal on successful delete', () => {
        deleteMutate.mockImplementation((_id, opts) => opts.onSuccess());
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByTitle('Delete role'));
        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('shows an error message when the delete mutation fails', () => {
        mutationState.delete = { isPending: false, isError: true };
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByTitle('Delete role'));
        expect(screen.getByText('Failed to delete role. Please try again.')).toBeInTheDocument();
    });

    it('closes the delete modal via the dialog close button and resets mutation state', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByTitle('Delete role'));
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));

        expect(deleteMutate).not.toHaveBeenCalled();
        expect(deleteReset).toHaveBeenCalled();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
});

describe('RolesPoliciesPage — permissions tab', () => {
    it('shows a loading spinner while permissions are loading', () => {
        usePermissions.mockReturnValue({ data: undefined, isLoading: true });
        render(<RolesPoliciesPage />);
        switchToPermissionsTab();
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('groups permissions by resource in read-only tables', () => {
        render(<RolesPoliciesPage />);
        switchToPermissionsTab();

        expect(screen.getByText('secrets')).toBeInTheDocument();
        expect(screen.getByText('rbac')).toBeInTheDocument();
        expect(screen.getByText('Read Secrets')).toBeInTheDocument();
        expect(screen.getByText('Write Secrets')).toBeInTheDocument();
        expect(screen.getByText('View Roles')).toBeInTheDocument();
    });

    it('shows an empty state when there are no permissions', () => {
        usePermissions.mockReturnValue({ data: [], isLoading: false });
        render(<RolesPoliciesPage />);
        switchToPermissionsTab();
        expect(screen.getByText('No permissions found.')).toBeInTheDocument();
    });
});

describe('RolesPoliciesPage — manage role permissions', () => {
    it('opens the modal, reflecting which permissions are already assigned', () => {
        render(<RolesPoliciesPage />);
        const devCard = getRoleCard('developer');
        fireEvent.click(within(devCard).getByRole('button', { name: /permissions/i }));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText('Permissions — developer')).toBeInTheDocument();
        const readCheckbox = within(dialog).getByRole('checkbox', { name: /Read Secrets/ }) as HTMLInputElement;
        const writeCheckbox = within(dialog).getByRole('checkbox', { name: /Write Secrets/ }) as HTMLInputElement;
        expect(readCheckbox.checked).toBe(true);
        expect(writeCheckbox.checked).toBe(false);
    });

    it('assigns an unassigned permission when its checkbox is toggled on', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByRole('button', { name: /permissions/i }));

        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /Write Secrets/ }));
        expect(assignMutate).toHaveBeenCalledWith({ roleId: 1, permissionId: 2 });
        expect(removeMutate).not.toHaveBeenCalled();
    });

    it('removes an assigned permission when its checkbox is toggled off', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByRole('button', { name: /permissions/i }));

        const dialog = screen.getByRole('dialog');
        fireEvent.click(within(dialog).getByRole('checkbox', { name: /Read Secrets/ }));
        expect(removeMutate).toHaveBeenCalledWith({ roleId: 1, permissionId: 1 });
        expect(assignMutate).not.toHaveBeenCalled();
    });

    it('disables the checkboxes while an assign/remove mutation is pending', () => {
        mutationState.assign = { isPending: true };
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByRole('button', { name: /permissions/i }));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByRole('checkbox', { name: /Write Secrets/ })).toBeDisabled();
    });

    it('shows a loading spinner while permissions are loading', () => {
        usePermissions.mockReturnValue({ data: undefined, isLoading: true });
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByRole('button', { name: /permissions/i }));

        const dialog = screen.getByRole('dialog');
        expect(dialog.querySelector('.animate-spin')).toBeTruthy();
    });

    it('closes via the Close button', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByRole('button', { name: /permissions/i }));

        const dialog = screen.getByRole('dialog');
        // The modal has two elements named "Close": the header's icon-only Dialog.Close
        // (sr-only text) and the explicit footer Button — the footer one is the second match.
        const closeButtons = within(dialog).getAllByRole('button', { name: 'Close' });
        fireEvent.click(closeButtons[1]!);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('closes via the dialog close (X) button', () => {
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByRole('button', { name: /permissions/i }));

        const dialog = screen.getByRole('dialog');
        const closeButtons = within(dialog).getAllByRole('button', { name: 'Close' });
        fireEvent.click(closeButtons[0]!);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('shows "No permissions available" when the permissions list is empty', () => {
        usePermissions.mockReturnValue({ data: [], isLoading: false });
        render(<RolesPoliciesPage />);
        fireEvent.click(within(getRoleCard('developer')).getByRole('button', { name: /permissions/i }));

        const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText('No permissions available.')).toBeInTheDocument();
    });
});
