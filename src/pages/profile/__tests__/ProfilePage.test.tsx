import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { ProfilePage } from '../ProfilePage';
import type { AccountSession } from '../../../services/account';
import type { PersonalAccessToken } from '../../../services/personalTokens';

// ── Hoisted mock state (referenced inside vi.mock factories below) ─────────────

const mocks = vi.hoisted(() => ({
    setUser: vi.fn(),
    clearPasswordChangeRequired: vi.fn(),
    updateProfileMutate: vi.fn(),
    changePasswordMutate: vi.fn(),
    revokeSessionMutate: vi.fn(),
    createTokenMutate: vi.fn(),
    createTokenReset: vi.fn(),
    revokeTokenMutate: vi.fn(),
    user: {
        id: 1,
        username: 'alice',
        displayName: 'Alice Anderson',
        email: 'alice@example.com',
        role: 'user',
        roles: [],
        permissions: [],
        preferences: {
            language: 'en',
            timezone: 'UTC',
            theme: 'system' as const,
            notifications: { email: true, browser: true, sharing: true, security: true },
        },
        lastLogin: '2026-01-01T00:00:00Z',
    },
    updateProfileState: { isPending: false, isError: false, error: null as Error | null },
    changePasswordState: { isPending: false, isError: false, error: null as Error | null },
    sessionsState: { data: [] as AccountSession[], isLoading: false, isError: false },
    revokeSessionState: { isPending: false },
    tokensState: { data: [] as PersonalAccessToken[], isLoading: false, isError: false },
    createTokenState: { isPending: false, isError: false, error: null as Error | null },
    revokeTokenState: { isPending: false },
    projects: [] as { id: number; name: string }[],
    environments: [] as { id: number; name: string }[],
}));

vi.mock('../../../store/authStore', () => {
    const useAuthStore: any = () => ({ user: mocks.user, setUser: mocks.setUser });
    useAuthStore.getState = () => ({ clearPasswordChangeRequired: mocks.clearPasswordChangeRequired });
    return { useAuthStore };
});

vi.mock('../../../features/account', () => ({
    useUpdateProfile: () => ({ mutate: mocks.updateProfileMutate, ...mocks.updateProfileState }),
    useChangePassword: () => ({ mutate: mocks.changePasswordMutate, ...mocks.changePasswordState }),
    useSessions: () => ({ ...mocks.sessionsState }),
    useRevokeSession: () => ({ mutate: mocks.revokeSessionMutate, ...mocks.revokeSessionState }),
    usePersonalTokens: () => ({ ...mocks.tokensState }),
    useCreatePersonalToken: () => ({
        mutate: mocks.createTokenMutate,
        reset: mocks.createTokenReset,
        ...mocks.createTokenState,
    }),
    useRevokePersonalToken: () => ({ mutate: mocks.revokeTokenMutate, ...mocks.revokeTokenState }),
}));

vi.mock('../../../features/projects/api', () => ({
    useProjects: () => ({ data: mocks.projects }),
    useProjectEnvironments: () => ({ data: mocks.environments }),
}));

// MfaSection has its own dedicated test suite (features/account/__tests__/MfaSection.test.tsx) —
// stub it here and only assert it is composed into the Security tab.
vi.mock('../../../features/account/MfaSection', () => ({
    MfaSection: () => <div data-testid="mfa-section-stub">MFA SECTION</div>,
}));

function resetMockState() {
    mocks.user.displayName = 'Alice Anderson';
    mocks.user.email = 'alice@example.com';
    mocks.updateProfileState.isPending = false;
    mocks.updateProfileState.isError = false;
    mocks.updateProfileState.error = null;
    mocks.changePasswordState.isPending = false;
    mocks.changePasswordState.isError = false;
    mocks.changePasswordState.error = null;
    mocks.sessionsState.data = [];
    mocks.sessionsState.isLoading = false;
    mocks.sessionsState.isError = false;
    mocks.revokeSessionState.isPending = false;
    mocks.tokensState.data = [];
    mocks.tokensState.isLoading = false;
    mocks.tokensState.isError = false;
    mocks.createTokenState.isPending = false;
    mocks.createTokenState.isError = false;
    mocks.createTokenState.error = null;
    mocks.revokeTokenState.isPending = false;
    mocks.projects = [];
    mocks.environments = [];
}

beforeEach(() => {
    vi.clearAllMocks();
    resetMockState();
});

function goToTab(name: string) {
    fireEvent.click(screen.getByRole('button', { name: new RegExp(`^${name}$`) }));
}

// ── Basic Info tab ───────────────────────────────────────────────────────────

describe('ProfilePage — Basic Info tab', () => {
    it('renders the current user info pre-filled', () => {
        render(<ProfilePage />);
        expect(screen.getByDisplayValue('Alice Anderson')).toBeInTheDocument();
        expect(screen.getByDisplayValue('alice@example.com')).toBeInTheDocument();
        expect(screen.getByText('alice')).toBeInTheDocument(); // read-only username
    });

    it('submits the edited display name and email', () => {
        render(<ProfilePage />);
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'Alice B' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'alice.b@example.com' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(mocks.updateProfileMutate).toHaveBeenCalledWith(
            { display_name: 'Alice B', email: 'alice.b@example.com' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('shows a success message and updates the auth store on success', () => {
        mocks.updateProfileMutate.mockImplementation((_body, opts) => {
            opts.onSuccess({ display_name: 'Alice B', email: 'alice.b@example.com' });
        });
        render(<ProfilePage />);
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

        expect(screen.getByText('Saved')).toBeInTheDocument();
        expect(mocks.setUser).toHaveBeenCalledWith(
            expect.objectContaining({ displayName: 'Alice B', email: 'alice.b@example.com' })
        );
    });

    it('shows an error message when the update fails', () => {
        mocks.updateProfileState.isError = true;
        mocks.updateProfileState.error = new Error('Email already in use');
        render(<ProfilePage />);
        expect(screen.getByText('Could not update profile')).toBeInTheDocument();
        expect(screen.getByText('Email already in use')).toBeInTheDocument();
    });
});

// ── Security tab ─────────────────────────────────────────────────────────────

describe('ProfilePage — Security tab', () => {
    it('composes the MfaSection component', () => {
        render(<ProfilePage />);
        goToTab('Security');
        expect(screen.getByTestId('mfa-section-stub')).toBeInTheDocument();
    });

    it('rejects mismatched new passwords without calling the mutation', () => {
        render(<ProfilePage />);
        goToTab('Security');
        fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: 'oldpass1' } });
        fireEvent.change(screen.getByLabelText('New Password'), { target: { value: 'newpass1' } });
        fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: 'newpass2' } });
        fireEvent.click(screen.getByRole('button', { name: /Change Password/ }));

        expect(screen.getByText('New passwords do not match.')).toBeInTheDocument();
        expect(mocks.changePasswordMutate).not.toHaveBeenCalled();
    });

    it('rejects a new password shorter than 8 characters', () => {
        render(<ProfilePage />);
        goToTab('Security');
        fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: 'oldpass1' } });
        fireEvent.change(screen.getByLabelText('New Password'), { target: { value: 'short' } });
        fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: 'short' } });
        fireEvent.click(screen.getByRole('button', { name: /Change Password/ }));

        expect(screen.getByText('New password must be at least 8 characters.')).toBeInTheDocument();
        expect(mocks.changePasswordMutate).not.toHaveBeenCalled();
    });

    it('submits a valid password change and clears the must-change-password gate', () => {
        mocks.changePasswordMutate.mockImplementation((_body, opts) => opts.onSuccess());
        render(<ProfilePage />);
        goToTab('Security');
        fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: 'oldpass1' } });
        fireEvent.change(screen.getByLabelText('New Password'), { target: { value: 'newpass1' } });
        fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: 'newpass1' } });
        fireEvent.click(screen.getByRole('button', { name: /Change Password/ }));

        expect(mocks.changePasswordMutate).toHaveBeenCalledWith(
            { current_password: 'oldpass1', new_password: 'newpass1' },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
        expect(screen.getByText('Password changed')).toBeInTheDocument();
        expect(mocks.clearPasswordChangeRequired).toHaveBeenCalled();
        // Fields are cleared after success.
        expect(screen.getByLabelText('Current Password')).toHaveValue('');
    });

    it('shows a server error from the mutation', () => {
        mocks.changePasswordState.isError = true;
        mocks.changePasswordState.error = new Error('Current password is incorrect');
        render(<ProfilePage />);
        goToTab('Security');
        expect(screen.getByText('Could not change password')).toBeInTheDocument();
        expect(screen.getByText('Current password is incorrect')).toBeInTheDocument();
    });
});

// ── Active Sessions tab ──────────────────────────────────────────────────────

describe('ProfilePage — Active Sessions tab', () => {
    it('shows a loading spinner while sessions load', () => {
        mocks.sessionsState.isLoading = true;
        const { container } = render(<ProfilePage />);
        goToTab('Active Sessions');
        expect(container.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('shows an error message if sessions fail to load', () => {
        mocks.sessionsState.isError = true;
        render(<ProfilePage />);
        goToTab('Active Sessions');
        expect(screen.getByText('Could not load sessions')).toBeInTheDocument();
    });

    it('shows an empty state with no sessions', () => {
        render(<ProfilePage />);
        goToTab('Active Sessions');
        expect(screen.getByText('No active sessions.')).toBeInTheDocument();
    });

    it('lists sessions, marks the current one, and disables its End Session button', () => {
        mocks.sessionsState.data = [
            {
                id: 1,
                user_agent: 'Chrome on macOS',
                ip_address: '10.0.0.1',
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_seen_at: '2026-01-02T00:00:00Z',
                current: true,
            },
            {
                id: 2,
                user_agent: 'Firefox on Linux',
                ip_address: '10.0.0.2',
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_seen_at: null,
                current: false,
            },
        ];
        render(<ProfilePage />);
        goToTab('Active Sessions');

        expect(screen.getByText('Chrome on macOS')).toBeInTheDocument();
        expect(screen.getByText('Current')).toBeInTheDocument();
        expect(screen.getByText('Firefox on Linux')).toBeInTheDocument();

        const currentRow = screen.getByText('Chrome on macOS').closest('div.rounded-lg') as HTMLElement;
        expect(within(currentRow).getByRole('button', { name: 'End Session' })).toBeDisabled();

        const otherRow = screen.getByText('Firefox on Linux').closest('div.rounded-lg') as HTMLElement;
        const endButton = within(otherRow).getByRole('button', { name: 'End Session' });
        expect(endButton).toBeEnabled();
        fireEvent.click(endButton);
        expect(mocks.revokeSessionMutate).toHaveBeenCalledWith(2);
    });
});

// ── API Tokens tab ────────────────────────────────────────────────────────────

describe('ProfilePage — API Tokens tab', () => {
    it('shows a loading spinner while tokens load', () => {
        mocks.tokensState.isLoading = true;
        const { container } = render(<ProfilePage />);
        goToTab('API Tokens');
        expect(container.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('shows an error message if tokens fail to load', () => {
        mocks.tokensState.isError = true;
        render(<ProfilePage />);
        goToTab('API Tokens');
        expect(screen.getByText('Could not load tokens')).toBeInTheDocument();
    });

    it('shows an empty state with no tokens', () => {
        render(<ProfilePage />);
        goToTab('API Tokens');
        expect(screen.getByText('You have no personal access tokens yet.')).toBeInTheDocument();
    });

    it('lists tokens, showing full-access, scoped, and revoked tokens', () => {
        mocks.projects = [{ id: 5, name: 'Payments' }];
        mocks.tokensState.data = [
            {
                id: 1,
                name: 'ci-pipeline',
                token_prefix: 'kx_abc',
                revoked: false,
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_used_at: null,
                scopes: [],
                project_scope: 0,
                environment_scope: 0,
            },
            {
                id: 2,
                name: 'scoped-token',
                token_prefix: 'kx_def',
                revoked: false,
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_used_at: null,
                scopes: ['secrets.read'],
                project_scope: 5,
                environment_scope: 0,
            },
            {
                id: 3,
                name: 'old-token',
                token_prefix: 'kx_ghi',
                revoked: true,
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_used_at: null,
                scopes: [],
                project_scope: 0,
                environment_scope: 0,
            },
        ];
        render(<ProfilePage />);
        goToTab('API Tokens');

        expect(screen.getAllByText('full access (all your permissions)')).toHaveLength(2);
        expect(screen.getByText('▣ Payments')).toBeInTheDocument();
        expect(screen.getByText('secrets.read')).toBeInTheDocument();
        expect(screen.getByText('revoked')).toBeInTheDocument();

        // Revoked tokens have no revoke control; active ones do.
        const revokedRow = screen.getByText('old-token').closest('div.rounded-lg') as HTMLElement;
        expect(within(revokedRow).queryByRole('button')).not.toBeInTheDocument();

        const activeRow = screen.getByText('ci-pipeline').closest('div.rounded-lg') as HTMLElement;
        fireEvent.click(within(activeRow).getByRole('button'));
        expect(mocks.revokeTokenMutate).toHaveBeenCalledWith(1);
    });

    it('creates a full-access token by default and shows it once, with copy support', () => {
        mocks.createTokenMutate.mockImplementation((_body, opts) => opts.onSuccess({ token: 'kx_live_secret' }));
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));

        fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'ci-pipeline' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));

        expect(mocks.createTokenMutate).toHaveBeenCalledWith({ name: 'ci-pipeline' }, expect.any(Object));
        expect(screen.getByText('kx_live_secret')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Copy token' }));
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('kx_live_secret');
    });

    it('builds a limited-access token payload from selected permissions and project scope', () => {
        mocks.projects = [{ id: 5, name: 'Payments' }];
        mocks.environments = [{ id: 9, name: 'production' }];
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));

        fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'scoped' } });
        fireEvent.click(screen.getByRole('radio', { name: /Limited access/ }));
        fireEvent.click(screen.getByRole('checkbox', { name: /Read secrets/ }));
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '5' } });
        fireEvent.change(screen.getByLabelText('Environment'), { target: { value: '9' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));

        expect(mocks.createTokenMutate).toHaveBeenCalledWith(
            { name: 'scoped', scopes: ['secrets.read'], project_scope: 5, environment_scope: 9 },
            expect.any(Object)
        );
    });

    it('warns and disables submit when limited access has no constraint chosen', () => {
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'unconstrained' } });
        fireEvent.click(screen.getByRole('radio', { name: /Limited access/ }));

        expect(screen.getByText(/Pick at least one permission or a project/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Create Token' })).toBeDisabled();
        expect(mocks.createTokenMutate).not.toHaveBeenCalled();
    });

    it('shows an error message when token creation fails', () => {
        mocks.createTokenState.isError = true;
        mocks.createTokenState.error = new Error('Name already in use');
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        expect(screen.getByText('Could not create token')).toBeInTheDocument();
        expect(screen.getByText('Name already in use')).toBeInTheDocument();
    });
});

// ── Tab navigation ────────────────────────────────────────────────────────────

describe('ProfilePage — tab navigation', () => {
    it('defaults to the Basic Info tab and switches on click', () => {
        render(<ProfilePage />);
        expect(screen.getByText('Profile Information')).toBeInTheDocument();

        goToTab('Active Sessions');
        expect(screen.queryByText('Profile Information')).not.toBeInTheDocument();
        expect(screen.getByText(/Devices currently signed in to your account/)).toBeInTheDocument();
    });
});
