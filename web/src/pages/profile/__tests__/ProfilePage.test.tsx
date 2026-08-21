import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, within, waitFor, act } from '../../../test/test-utils';
import { ProfilePage } from '../ProfilePage';
import type { AccountSession } from '../../../services/account';
import type { PersonalAccessToken } from '../../../services/personalTokens';
import { DEFAULT_SENSITIVE_IDLE_MS } from '../../../hooks/useAutoClearOnIdle';

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

// Test helper; `name` is always a hardcoded tab label from this file's own
// test cases below, never external/attacker-controlled input.
function goToTab(name: string) {
    fireEvent.click(screen.getByRole('button', { name: new RegExp(`^${name}$`) })); // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
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

    // G28: the one-time token must not linger indefinitely with no explicit Done.
    describe('auto-clear (G28)', () => {
        afterEach(() => {
            vi.useRealTimers();
        });

        it('auto-closes the token modal after the idle timeout elapses, without an explicit Done click', async () => {
            mocks.createTokenMutate.mockImplementation((_body, opts) => opts.onSuccess({ token: 'kx_idle_secret' }));
            vi.useFakeTimers();

            render(<ProfilePage />);
            goToTab('API Tokens');
            fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
            fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'idle-test' } });
            fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));
            expect(screen.getByText('kx_idle_secret')).toBeInTheDocument();

            await act(async () => {
                await vi.advanceTimersByTimeAsync(DEFAULT_SENSITIVE_IDLE_MS);
            });

            expect(screen.queryByText('kx_idle_secret')).not.toBeInTheDocument();
            expect(screen.queryByText('New Personal Access Token')).not.toBeInTheDocument();
        });

        it('auto-closes the token modal when the tab is backgrounded, without an explicit Done click', () => {
            mocks.createTokenMutate.mockImplementation((_body, opts) => opts.onSuccess({ token: 'kx_bg_secret' }));

            render(<ProfilePage />);
            goToTab('API Tokens');
            fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
            fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'bg-test' } });
            fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));
            expect(screen.getByText('kx_bg_secret')).toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
            act(() => {
                document.dispatchEvent(new Event('visibilitychange'));
            });

            expect(screen.queryByText('kx_bg_secret')).not.toBeInTheDocument();
            expect(screen.queryByText('New Personal Access Token')).not.toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
        });
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

// ── Additional coverage: fallbacks, pending states, and modal controls ────────

describe('ProfilePage — Basic Info tab additional coverage', () => {
    it('falls back to empty fields and skips updating the auth store when there is no signed-in user', () => {
        const originalUser = mocks.user;
        (mocks as { user: unknown }).user = null;
        mocks.updateProfileMutate.mockImplementation((_body: unknown, opts: { onSuccess: (p: unknown) => void }) =>
            opts.onSuccess({ display_name: 'X', email: 'x@example.com' })
        );
        render(<ProfilePage />);
        expect(screen.getByLabelText('Display Name')).toHaveValue('');
        expect(screen.getByLabelText('Email')).toHaveValue('');
        // Required fields must be filled for the form to actually submit (jsdom
        // enforces native HTML5 required-field validation) — the point of this
        // test is what happens once onSuccess fires with no signed-in user, not
        // the empty-fallback rendering checked just above.
        fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'X' } });
        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'x@example.com' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
        expect(mocks.updateProfileMutate).toHaveBeenCalled();
        expect(mocks.setUser).not.toHaveBeenCalled();
        (mocks as { user: unknown }).user = originalUser;
    });

    it('falls back to a generic message when the update error has no message', () => {
        mocks.updateProfileState.isError = true;
        mocks.updateProfileState.error = new Error();
        render(<ProfilePage />);
        expect(screen.getByText('Please try again.')).toBeInTheDocument();
    });

    it('shows a spinner and disables the button while the profile update is pending', () => {
        mocks.updateProfileState.isPending = true;
        render(<ProfilePage />);
        const submit = screen.getByRole('button', { name: /Save Changes/ });
        expect(submit).toBeDisabled();
        expect(submit.querySelector('svg.animate-spin')).toBeInTheDocument();
    });
});

describe('ProfilePage — Security tab additional coverage', () => {
    it('falls back to a generic message when the change-password error has no message', () => {
        mocks.changePasswordState.isError = true;
        mocks.changePasswordState.error = new Error();
        render(<ProfilePage />);
        goToTab('Security');
        expect(screen.getByText('Please try again.')).toBeInTheDocument();
    });

    it('shows a spinner and disables the button while the password change is pending', () => {
        mocks.changePasswordState.isPending = true;
        render(<ProfilePage />);
        goToTab('Security');
        const submit = screen.getByRole('button', { name: /Change Password/ });
        expect(submit).toBeDisabled();
        expect(submit.querySelector('svg.animate-spin')).toBeInTheDocument();
    });
});

describe('ProfilePage — Active Sessions tab additional coverage', () => {
    it('treats undefined sessions data as an empty list', () => {
        (mocks.sessionsState as { data: unknown }).data = undefined;
        render(<ProfilePage />);
        goToTab('Active Sessions');
        expect(screen.getByText('No active sessions.')).toBeInTheDocument();
    });

    it('shows fallback text for a session missing a user agent and IP, and an invalid last-seen date', () => {
        mocks.sessionsState.data = [
            {
                id: 1,
                user_agent: '',
                ip_address: '',
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_seen_at: 'not-a-real-date',
                current: false,
            },
        ];
        render(<ProfilePage />);
        goToTab('Active Sessions');
        expect(screen.getByText('Unknown device')).toBeInTheDocument();
        expect(screen.getByText(/unknown IP/)).toBeInTheDocument();
        expect(screen.getByText(/last active —/)).toBeInTheDocument();
    });
});

describe('ProfilePage — API Tokens tab additional coverage', () => {
    it('treats undefined tokens data as an empty list', () => {
        (mocks.tokensState as { data: unknown }).data = undefined;
        render(<ProfilePage />);
        goToTab('API Tokens');
        expect(screen.getByText('You have no personal access tokens yet.')).toBeInTheDocument();
    });

    it('renders an environment scope chip for a token scoped to an environment', () => {
        mocks.tokensState.data = [
            {
                id: 4,
                name: 'env-token',
                token_prefix: 'kx_env',
                revoked: false,
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_used_at: null,
                scopes: [],
                project_scope: 0,
                environment_scope: 7,
            },
        ];
        render(<ProfilePage />);
        goToTab('API Tokens');
        expect(screen.getByText('⬢ env #7')).toBeInTheDocument();
    });

    it('falls back to a placeholder label when a scoped project cannot be found', () => {
        mocks.projects = [];
        mocks.tokensState.data = [
            {
                id: 5,
                name: 'orphan-token',
                token_prefix: 'kx_orf',
                revoked: false,
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_used_at: null,
                scopes: [],
                project_scope: 42,
                environment_scope: 0,
            },
        ];
        render(<ProfilePage />);
        goToTab('API Tokens');
        expect(screen.getByText('▣ project #42')).toBeInTheDocument();
    });

    it('shows an expiry date for a token that has one', () => {
        mocks.tokensState.data = [
            {
                id: 6,
                name: 'expiring',
                token_prefix: 'kx_exp',
                revoked: false,
                created_at: '2026-01-01T00:00:00Z',
                expires_at: '2027-01-01T00:00:00Z',
                last_used_at: null,
                scopes: [],
                project_scope: 0,
                environment_scope: 0,
            },
        ];
        render(<ProfilePage />);
        goToTab('API Tokens');
        expect(screen.getByText(/expires/)).toBeInTheDocument();
    });

    it('closes the create-token modal via its close (X) control', () => {
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        expect(screen.getByText('New Personal Access Token')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(screen.queryByText('New Personal Access Token')).not.toBeInTheDocument();
    });

    it('closes the create form via Cancel without creating a token', () => {
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByText('New Personal Access Token')).not.toBeInTheDocument();
        expect(mocks.createTokenMutate).not.toHaveBeenCalled();
    });

    it('closes the modal via the Done button after creating a token', () => {
        mocks.createTokenMutate.mockImplementation(
            (_body: unknown, opts: { onSuccess: (r: { token: string }) => void }) =>
                opts.onSuccess({ token: 'kx_live_secret' })
        );
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'ci-pipeline' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));
        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('kx_live_secret')).not.toBeInTheDocument();
    });

    it('shows a check icon after copying the token', async () => {
        mocks.createTokenMutate.mockImplementation(
            (_body: unknown, opts: { onSuccess: (r: { token: string }) => void }) =>
                opts.onSuccess({ token: 'kx_live_secret' })
        );
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'ci-pipeline' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));

        const copyButton = screen.getByRole('button', { name: 'Copy token' });
        const before = copyButton.innerHTML;
        fireEvent.click(copyButton);
        await waitFor(() => expect(copyButton.innerHTML).not.toBe(before));
    });

    it('falls back to a generic message when the create-token error has no message', () => {
        mocks.createTokenState.isError = true;
        mocks.createTokenState.error = new Error();
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        expect(screen.getByText('Please try again.')).toBeInTheDocument();
    });

    it('shows a spinner and disables submit while a token is being created', () => {
        mocks.createTokenState.isPending = true;
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'x' } });
        const submit = screen.getByRole('button', { name: /Create Token/ });
        expect(submit).toBeDisabled();
        expect(submit.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('unchecks a previously selected permission', () => {
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.click(screen.getByRole('radio', { name: /Limited access/ }));
        const checkbox = screen.getByRole('checkbox', { name: /Read secrets/ });
        fireEvent.click(checkbox);
        expect(checkbox).toBeChecked();
        fireEvent.click(checkbox);
        expect(checkbox).not.toBeChecked();
    });

    it('accepts an expiry date and extra permissions, then reverts to full access before submitting', () => {
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'x' } });
        fireEvent.change(screen.getByLabelText('Expires (optional)'), { target: { value: '2030-01-01' } });
        fireEvent.click(screen.getByRole('radio', { name: /Limited access/ }));
        fireEvent.change(screen.getByLabelText(/Additional permissions/), { target: { value: 'rotation.write' } });
        fireEvent.click(screen.getByRole('radio', { name: /^Full access/ }));
        fireEvent.click(screen.getByRole('button', { name: 'Create Token' }));

        expect(mocks.createTokenMutate).toHaveBeenCalledWith(
            expect.objectContaining({ name: 'x', expires_at: expect.any(String) }),
            expect.any(Object)
        );
        const [body] = mocks.createTokenMutate.mock.calls[0];
        expect(body).not.toHaveProperty('scopes');
    });

    it('handles an undefined projects list when rendering the scope selector', () => {
        (mocks as { projects: unknown }).projects = undefined;
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.click(screen.getByRole('radio', { name: /Limited access/ }));
        expect(screen.getByLabelText('Project')).toBeInTheDocument();
    });

    it('handles an undefined environments list once a project is scoped', () => {
        mocks.projects = [{ id: 5, name: 'Payments' }];
        (mocks as { environments: unknown }).environments = undefined;
        render(<ProfilePage />);
        goToTab('API Tokens');
        fireEvent.click(screen.getByRole('button', { name: /New Token/ }));
        fireEvent.click(screen.getByRole('radio', { name: /Limited access/ }));
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: '5' } });
        expect(screen.getByLabelText('Environment')).toBeInTheDocument();
    });
});

// NOTE: TokensTab's `copy()` guard (`if (!newToken) return;`) is intentionally not
// exercised — the "Copy token" button that invokes `copy` only renders inside the
// `newToken ? (...) : (...)` branch, so `newToken` is always truthy when `copy` is
// called. It's purely defensive and unreachable through the UI.
