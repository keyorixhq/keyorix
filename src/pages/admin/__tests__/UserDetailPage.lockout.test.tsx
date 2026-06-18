import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { UserDetailPage } from '../UserDetailPage';

let userData: Record<string, unknown>;
const unlockMutate = vi.fn();
const noop = { mutate: vi.fn(), isPending: false };

vi.mock('react-router-dom', async (orig) => ({
    ...(await orig<typeof import('react-router-dom')>()),
    useParams: () => ({ id: '5' }),
    useNavigate: () => vi.fn(),
}));

vi.mock('../../../features/admin', () => ({
    useUserDetail: () => ({ data: userData, isLoading: false, isError: false }),
    useUserRoles: () => ({ data: [] }),
    useUserMemberships: () => ({ data: [] }),
    useSuspendUser: () => noop,
    useReactivateUser: () => noop,
    useUnlockUser: () => ({ mutate: unlockMutate, isPending: false }),
    useRequirePasswordReset: () => noop,
    useRevokeSessions: () => noop,
    useResendSetupLink: () => noop,
    AccountStateBadge: ({ state }: { state: string }) => <span>state:{state}</span>,
}));

vi.mock('../../../features/auth', () => ({
    useAuth: () => ({ user: { id: 99 } }), // viewing someone else
}));

const baseUser = {
    id: 5,
    username: 'bob',
    email: 'bob@x.com',
    display_name: 'Bob',
    active: true,
    account_state: 'active',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    last_login_at: null,
    deleted_at: null,
};

beforeEach(() => {
    unlockMutate.mockClear();
    userData = { ...baseUser };
});

describe('UserDetailPage — login lockout', () => {
    it('shows a Locked out badge and Unlock action when the account is locked', () => {
        userData = { ...baseUser, login_locked_until: '2099-01-01T00:00:00Z' };
        render(<UserDetailPage />);
        expect(screen.getByText('Locked out')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Unlock login' })).toBeInTheDocument();
    });

    it('does not show the Unlock action when not locked', () => {
        render(<UserDetailPage />);
        expect(screen.queryByText('Locked out')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Unlock login' })).not.toBeInTheDocument();
    });

    it('confirms and calls unlock for the viewed user', () => {
        userData = { ...baseUser, login_locked_until: '2099-01-01T00:00:00Z' };
        render(<UserDetailPage />);
        fireEvent.click(screen.getByRole('button', { name: 'Unlock login' }));
        // Confirm modal.
        expect(screen.getByText('Clear login lockout')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
        expect(unlockMutate).toHaveBeenCalledWith(5, expect.anything());
    });
});
