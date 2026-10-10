import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider, onlineManager } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router';
import { ProfilePage } from '../ProfilePage';
import { queryClientDefaultOptions } from '../../../lib/queryClient';

// #2787: ProfilePage's inline forms read their spinner/disabled state off a react-query
// mutation. With the default networkMode ('online') a mutation fired while the browser
// reports offline is PAUSED: its promise never settles, so isPending stays true, no
// error is shown and the control stays disabled until a reload (#2738's shape).
//
// These tests run the REAL hooks against the app's OWN mutation policy (imported, never
// re-declared), flip onlineManager offline just before the click, and require, per form:
//   1. the request is actually attempted (a paused mutation never calls the service),
//   2. the failure is shown in the form's own error alert, and
//   3. the control is usable again, and a second submit reaches the service.
// Query data is loaded while online first, since offline queries pause too.

const mocks = vi.hoisted(() => ({
    updateProfile: vi.fn(),
    changePassword: vi.fn(),
    listSessions: vi.fn(),
    revokeSession: vi.fn(),
    listTokens: vi.fn(),
    createToken: vi.fn(),
    revokeToken: vi.fn(),
}));

vi.mock('../../../store/authStore', () => {
    const user = { id: 1, username: 'alice', displayName: 'Alice', email: 'alice@example.com' };
    const useAuthStore: any = () => ({ user, setUser: vi.fn() });
    useAuthStore.getState = () => ({ clearPasswordChangeRequired: vi.fn() });
    return { useAuthStore };
});
vi.mock('../../../services/account', () => ({
    accountApi: {
        updateProfile: mocks.updateProfile,
        changePassword: mocks.changePassword,
        listSessions: mocks.listSessions,
        revokeSession: mocks.revokeSession,
    },
}));
vi.mock('../../../services/personalTokens', async (importOriginal) => ({
    ...(await importOriginal<typeof import('../../../services/personalTokens')>()),
    personalTokensApi: {
        listTokens: mocks.listTokens,
        createToken: mocks.createToken,
        revokeToken: mocks.revokeToken,
    },
}));
vi.mock('../../../features/projects/api', () => ({
    useProjects: () => ({ data: [] }),
    useProjectEnvironments: () => ({ data: [] }),
}));
vi.mock('../../../features/account/MfaSection', () => ({ MfaSection: () => null }));

function networkError(msg: string) {
    return new Error(msg);
}

function renderPage() {
    const queryClient = new QueryClient({
        defaultOptions: {
            ...queryClientDefaultOptions,
            queries: { ...queryClientDefaultOptions.queries, retry: false, gcTime: 0 },
            // The production mutation policy retries a no-response failure once after a
            // delay; shorten only the delay so the tests do not wait on it.
            mutations: { ...queryClientDefaultOptions.mutations, retryDelay: 1 },
        },
    });
    return render(
        <QueryClientProvider client={queryClient}>
            <BrowserRouter>
                <ProfilePage />
            </BrowserRouter>
        </QueryClientProvider>
    );
}

const session = { id: 2, user_agent: 'Firefox', ip_address: '10.0.0.2', current: false, last_seen_at: null };
const token = {
    id: 5,
    name: 'ci',
    token_prefix: 'kx_ab',
    revoked: false,
    scopes: [],
    project_scope: 0,
    environment_scope: 0,
    created_at: '2026-01-01T00:00:00Z',
    last_used_at: null,
    expires_at: null,
};

beforeEach(() => {
    vi.clearAllMocks();
    mocks.listSessions.mockResolvedValue([session]);
    mocks.listTokens.mockResolvedValue([token]);
});

afterEach(() => {
    onlineManager.setOnline(true);
});

describe('#2787 ProfilePage forms never wedge on a paused mutation', () => {
    it('profile form: an offline save is attempted, reports the failure, and can be retried', async () => {
        mocks.updateProfile.mockRejectedValue(networkError('Network Error'));
        renderPage();

        onlineManager.setOnline(false);
        const save = screen.getByRole('button', { name: /save changes/i });
        fireEvent.click(save);

        await waitFor(() => expect(mocks.updateProfile).toHaveBeenCalled());
        await waitFor(() => expect(screen.getByText('Could not update profile')).toBeInTheDocument());
        await waitFor(() => expect(save).not.toBeDisabled());

        const before = mocks.updateProfile.mock.calls.length;
        fireEvent.click(save);
        await waitFor(() => expect(mocks.updateProfile.mock.calls.length).toBeGreaterThan(before));
    });

    it('change-password form: an offline submit is attempted, reports the failure, and can be retried', async () => {
        mocks.changePassword.mockRejectedValue(networkError('Network Error'));
        renderPage();
        fireEvent.click(screen.getByRole('button', { name: /security/i }));

        fireEvent.change(screen.getByLabelText('Current Password'), { target: { value: 'old-password' } });
        fireEvent.change(screen.getByLabelText('New Password'), { target: { value: 'new-password-1' } });
        fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: 'new-password-1' } });
        onlineManager.setOnline(false);
        const submit = screen.getByRole('button', { name: 'Change Password' });
        fireEvent.click(submit);

        await waitFor(() => expect(mocks.changePassword).toHaveBeenCalled());
        await waitFor(() => expect(screen.getByText('Could not change password')).toBeInTheDocument());
        await waitFor(() => expect(submit).not.toBeDisabled());

        const before = mocks.changePassword.mock.calls.length;
        fireEvent.click(submit);
        await waitFor(() => expect(mocks.changePassword.mock.calls.length).toBeGreaterThan(before));
    });

    it('session revoke: an offline End Session is attempted and the button recovers', async () => {
        mocks.revokeSession.mockRejectedValue(networkError('Network Error'));
        renderPage();
        fireEvent.click(screen.getByRole('button', { name: /active sessions/i }));
        const end = await screen.findByRole('button', { name: 'End Session' });

        onlineManager.setOnline(false);
        fireEvent.click(end);

        await waitFor(() => expect(mocks.revokeSession).toHaveBeenCalledWith(2));
        await waitFor(() => expect(end).not.toBeDisabled());

        const before = mocks.revokeSession.mock.calls.length;
        fireEvent.click(end);
        await waitFor(() => expect(mocks.revokeSession.mock.calls.length).toBeGreaterThan(before));
    });

    it('token create: an offline Create Token is attempted, reports the failure, and can be retried', async () => {
        mocks.createToken.mockRejectedValue(networkError('Network Error'));
        renderPage();
        fireEvent.click(screen.getByRole('button', { name: /api tokens/i }));
        await screen.findByText('ci');

        fireEvent.click(screen.getByRole('button', { name: /new token/i }));
        fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'deploy' } });
        onlineManager.setOnline(false);
        const create = screen.getByRole('button', { name: 'Create Token' });
        fireEvent.click(create);

        await waitFor(() => expect(mocks.createToken).toHaveBeenCalled());
        await waitFor(() => expect(screen.getByText('Could not create token')).toBeInTheDocument());
        await waitFor(() => expect(create).not.toBeDisabled());

        const before = mocks.createToken.mock.calls.length;
        fireEvent.click(create);
        await waitFor(() => expect(mocks.createToken.mock.calls.length).toBeGreaterThan(before));
    });

    it('token revoke: an offline revoke is attempted and the button recovers', async () => {
        mocks.revokeToken.mockRejectedValue(networkError('Network Error'));
        renderPage();
        fireEvent.click(screen.getByRole('button', { name: /api tokens/i }));
        const revoke = await screen.findByTitle('Revoke this token');

        onlineManager.setOnline(false);
        fireEvent.click(revoke);

        await waitFor(() => expect(mocks.revokeToken).toHaveBeenCalledWith(5));
        await waitFor(() => expect(revoke).not.toBeDisabled());

        const before = mocks.revokeToken.mock.calls.length;
        fireEvent.click(revoke);
        await waitFor(() => expect(mocks.revokeToken.mock.calls.length).toBeGreaterThan(before));
    });
});
