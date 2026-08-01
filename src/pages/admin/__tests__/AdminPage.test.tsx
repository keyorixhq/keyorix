import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '../../../test/test-utils';
import { AdminPage } from '../AdminPage';

const navigateMock = vi.fn();
vi.mock('react-router-dom', async () => {
    const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
    return { ...actual, useNavigate: () => navigateMock };
});

const useAdminUserList = vi.fn();
const createMutate = vi.fn();
const updateMutate = vi.fn();
const updateMutateAsync = vi.fn();
const deleteMutate = vi.fn();
const deleteMutateAsync = vi.fn();
const restoreMutate = vi.fn();
const updateRolesMutate = vi.fn();
const impersonateMutate = vi.fn();
const useAdminRoles = vi.fn();
const useUserRoles = vi.fn();

vi.mock('../../../features/admin', () => ({
    useAdminUserList: (...args: any[]) => useAdminUserList(...args),
    useAdminCreateUser: () => ({ mutate: createMutate, isPending: false }),
    useAdminUpdateUser: () => ({ mutate: updateMutate, mutateAsync: updateMutateAsync, isPending: false }),
    useAdminDeleteUser: () => ({ mutate: deleteMutate, mutateAsync: deleteMutateAsync, isPending: false }),
    useAdminRestoreUser: () => ({ mutate: restoreMutate, isPending: false }),
    useAdminRoles: (...args: any[]) => useAdminRoles(...args),
    useUserRoles: (...args: any[]) => useUserRoles(...args),
    useUpdateUserRoles: () => ({ mutate: updateRolesMutate, isPending: false }),
    useImpersonateUser: () => ({ mutate: impersonateMutate, isPending: false }),
    AccountStateBadge: ({ state }: { state?: string }) => <span data-testid="state-badge">{state}</span>,
    StaleAccountsSection: () => null,
    PATHygieneSection: () => null,
    MachineTokenHygieneSection: () => null,
    DeploymentHygieneSection: () => null,
    OrgNameConformanceSection: () => null,
    OrgInventoryExport: () => null,
    ProjectAssignmentsPicker: () => null,
    MaintenanceSection: () => null,
}));

vi.mock('../../../features/invitations/GlobalInviteUserModal', () => ({
    GlobalInviteUserModal: ({ isOpen }: { isOpen: boolean }) => (isOpen ? <div data-testid="invite-modal" /> : null),
}));

const activeUser = {
    id: 1,
    username: 'alice',
    email: 'alice@example.com',
    display_name: 'Alice A',
    active: true,
    account_state: 'active',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    last_login_at: '2026-02-01T00:00:00Z',
    deleted_at: null,
};

const inactiveUser = {
    id: 2,
    username: 'bob',
    email: 'bob@example.com',
    display_name: 'Bob B',
    active: false,
    account_state: 'suspended',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    last_login_at: null,
    deleted_at: null,
};

const deletedUser = {
    ...activeUser,
    id: 3,
    username: 'carol',
    deleted_at: '2026-02-15T00:00:00Z',
};

function mockUserList(
    users: any[],
    overrides: Partial<{ isLoading: boolean; isError: boolean; total: number; totalPages: number }> = {}
) {
    useAdminUserList.mockReturnValue({
        data: { users, total: overrides.total ?? users.length, total_pages: overrides.totalPages ?? 1 },
        isLoading: overrides.isLoading ?? false,
        isError: overrides.isError ?? false,
    });
}

beforeEach(() => {
    vi.clearAllMocks();
    useAdminRoles.mockReturnValue({ data: [{ id: 1, name: 'admin', description: 'Full access' }] });
    useUserRoles.mockReturnValue({ data: [], isLoading: false });
    mockUserList([activeUser, inactiveUser]);
});

describe('AdminPage — loading/empty/populated', () => {
    it('shows a loading state', () => {
        mockUserList([], { isLoading: true });
        render(<AdminPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an empty state with no users', () => {
        mockUserList([]);
        render(<AdminPage />);
        expect(screen.getByText('No users yet.')).toBeInTheDocument();
    });

    it('renders each user row', () => {
        render(<AdminPage />);
        expect(screen.getByText('Alice A')).toBeInTheDocument();
        expect(screen.getByText('bob@example.com')).toBeInTheDocument();
        expect(screen.getByText('2 users')).toBeInTheDocument();
    });
});

describe('AdminPage — search', () => {
    it('submits the search box value and resets to page 1', async () => {
        render(<AdminPage />);
        fireEvent.change(screen.getByPlaceholderText(/search by username or email/i), {
            target: { value: 'alice' },
        });
        fireEvent.click(screen.getByRole('button', { name: 'Search' }));

        await waitFor(() =>
            expect(useAdminUserList).toHaveBeenLastCalledWith(expect.objectContaining({ search: 'alice', page: 1 }))
        );
    });
});

describe('AdminPage — pagination', () => {
    it('advances to the next page', async () => {
        mockUserList([activeUser], { totalPages: 3 });
        render(<AdminPage />);

        fireEvent.click(screen.getByLabelText('Next page'));

        await waitFor(() => expect(useAdminUserList).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 })));
    });
});

describe('AdminPage — bulk actions', () => {
    it('shows Activate for a selected inactive user and Deactivate for a selected active user', () => {
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1); // skip header row
        fireEvent.click(within(rows[0]!).getByRole('checkbox')); // alice (active)
        fireEvent.click(within(rows[1]!).getByRole('checkbox')); // bob (inactive)

        expect(screen.getByText('2 selected')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Activate' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Deactivate' })).toBeInTheDocument();
    });

    it('bulk-deletes every selected user', async () => {
        deleteMutateAsync.mockResolvedValue(undefined);
        render(<AdminPage />);
        const rows = screen.getAllByRole('row').slice(1);
        fireEvent.click(within(rows[0]!).getByRole('checkbox'));
        fireEvent.click(within(rows[1]!).getByRole('checkbox'));

        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

        await waitFor(() => expect(deleteMutateAsync).toHaveBeenCalledTimes(2));
        expect(deleteMutateAsync).toHaveBeenCalledWith(1);
        expect(deleteMutateAsync).toHaveBeenCalledWith(2);
    });
});

describe('AdminPage — create user', () => {
    it('validates required fields before submitting', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));

        expect(await screen.findByText('Username is required')).toBeInTheDocument();
        expect(createMutate).not.toHaveBeenCalled();
    });

    it('creates a user with a password', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'longpassword' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create User' }));

        await waitFor(() =>
            expect(createMutate).toHaveBeenCalledWith(
                {
                    username: 'newu',
                    email: 'new@example.com',
                    display_name: 'New User',
                    password: 'longpassword',
                },
                expect.anything()
            )
        );
    });

    it('sends deliver_setup_link (no password) in setup-link mode', async () => {
        render(<AdminPage />);
        fireEvent.click(screen.getByRole('button', { name: /new user/i }));

        fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'newu' } });
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New User' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
        fireEvent.click(screen.getByLabelText('Send a setup link'));
        fireEvent.click(screen.getByRole('button', { name: 'Create & Send Link' }));

        await waitFor(() =>
            expect(createMutate).toHaveBeenCalledWith(
                {
                    username: 'newu',
                    email: 'new@example.com',
                    display_name: 'New User',
                    deliver_setup_link: true,
                },
                expect.anything()
            )
        );
    });
});

function aliceRow() {
    return screen.getAllByRole('row')[1]!; // header row is index 0; alice is the first data row
}

describe('AdminPage — edit user', () => {
    it('opens pre-filled and saves the changes', async () => {
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Edit user'));

        const emailInput = screen.getByLabelText('Email') as HTMLInputElement;
        expect(emailInput.value).toBe('alice@example.com');

        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'Alice Updated' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        await waitFor(() =>
            expect(updateMutate).toHaveBeenCalledWith(
                {
                    id: 1,
                    body: { email: 'alice@example.com', display_name: 'Alice Updated', active: true },
                },
                expect.anything()
            )
        );
    });
});

describe('AdminPage — delete user', () => {
    it('confirms and deletes a single user', async () => {
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Delete user'));
        expect(screen.getByText(/soft-deleted and can be restored/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Delete User' }));

        await waitFor(() => expect(deleteMutate).toHaveBeenCalledWith(1, expect.anything()));
    });
});

describe('AdminPage — restore user', () => {
    it('shows a restore action for a deleted user and restores it', async () => {
        mockUserList([deletedUser]);
        render(<AdminPage />);

        fireEvent.click(screen.getByTitle('Restore user'));
        fireEvent.click(screen.getByRole('button', { name: 'Restore User' }));

        await waitFor(() => expect(restoreMutate).toHaveBeenCalledWith(3, expect.anything()));
    });
});

describe('AdminPage — roles', () => {
    it('requires at least one role before saving', async () => {
        useUserRoles.mockReturnValue({ data: [{ id: 1 }], isLoading: false });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        // Uncheck the only pre-selected role.
        fireEvent.click(await screen.findByRole('checkbox', { name: /admin/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Save Roles' }));

        expect(await screen.findByText('User must have at least one role')).toBeInTheDocument();
        expect(updateRolesMutate).not.toHaveBeenCalled();
    });

    it('saves the selected roles', async () => {
        useUserRoles.mockReturnValue({ data: [], isLoading: false });
        render(<AdminPage />);
        fireEvent.click(within(aliceRow()).getByTitle('Manage roles'));

        fireEvent.click(await screen.findByRole('checkbox', { name: /admin/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Save Roles' }));

        await waitFor(() =>
            expect(updateRolesMutate).toHaveBeenCalledWith({ userId: 1, roleIds: [1] }, expect.anything())
        );
    });
});

describe('AdminPage — impersonate', () => {
    it('impersonates a user and navigates to the dashboard on success', async () => {
        impersonateMutate.mockImplementation((_vars, opts) => opts?.onSuccess?.());
        render(<AdminPage />);

        fireEvent.click(within(aliceRow()).getByTitle('Impersonate user'));

        expect(impersonateMutate).toHaveBeenCalledWith(
            { id: 1, username: 'alice', display_name: 'Alice A' },
            expect.anything()
        );
        expect(navigateMock).toHaveBeenCalledWith('/dashboard');
    });
});

describe('AdminPage — inactive filter banner', () => {
    it('shows the banner when ?filter=inactive is present and links to audit', () => {
        window.history.pushState({}, '', '/admin?filter=inactive');
        render(<AdminPage />);

        expect(screen.getByText(/showing inactive users only/i)).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /view login history/i }));
        expect(navigateMock).toHaveBeenCalledWith(expect.stringContaining('filter=logins'));

        window.history.pushState({}, '', '/');
    });
});
