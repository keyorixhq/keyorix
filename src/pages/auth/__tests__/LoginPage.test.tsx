import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { LoginPage } from '../LoginPage';

const authState = vi.hoisted(() => ({
    user: null as unknown,
    isAuthenticated: false,
    isLoading: false,
    hasCheckedAuth: true,
    error: null as string | null,
}));

const loginMock = vi.hoisted(() => vi.fn());
const logoutMock = vi.hoisted(() => vi.fn());
const refreshTokenMock = vi.hoisted(() => vi.fn());
const checkAuthMock = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
const clearErrorMock = vi.hoisted(() => vi.fn());
const setErrorMock = vi.hoisted(() => vi.fn());
const rehydrateMock = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));

vi.mock('../../../store/authStore', () => {
    const useAuthStore = () => ({
        user: authState.user,
        isAuthenticated: authState.isAuthenticated,
        isLoading: authState.isLoading,
        hasCheckedAuth: authState.hasCheckedAuth,
        error: authState.error,
        login: loginMock,
        logout: logoutMock,
        refreshToken: refreshTokenMock,
        checkAuth: checkAuthMock,
        clearError: clearErrorMock,
        setError: setErrorMock,
    });
    useAuthStore.persist = { rehydrate: rehydrateMock };
    return { useAuthStore };
});

const getSSOProvidersMock = vi.hoisted(() => vi.fn().mockResolvedValue([]));
const requestPasswordResetMock = vi.hoisted(() => vi.fn());

vi.mock('../../../services/auth', () => ({
    authService: {
        getSSOProviders: (...args: unknown[]) => getSSOProvidersMock(...args),
        requestPasswordReset: (...args: unknown[]) => requestPasswordResetMock(...args),
    },
}));

const navigateMock = vi.hoisted(() => vi.fn());

vi.mock('react-router-dom', async (importOriginal) => {
    const actual = await importOriginal<typeof import('react-router-dom')>();
    return {
        ...actual,
        useNavigate: () => navigateMock,
    };
});

beforeEach(() => {
    window.history.pushState({}, '', '/');
    authState.user = null;
    authState.isAuthenticated = false;
    authState.isLoading = false;
    authState.hasCheckedAuth = true;
    authState.error = null;
    loginMock.mockReset();
    logoutMock.mockReset();
    refreshTokenMock.mockReset();
    checkAuthMock.mockReset().mockResolvedValue(undefined);
    clearErrorMock.mockReset();
    setErrorMock.mockReset();
    rehydrateMock.mockReset().mockResolvedValue(undefined);
    getSSOProvidersMock.mockReset().mockResolvedValue([]);
    requestPasswordResetMock.mockReset();
    navigateMock.mockReset();
});

describe('LoginPage', () => {
    it('renders branding and the login form when unauthenticated', async () => {
        render(<LoginPage />);

        expect(screen.getByText('Keyorix')).toBeInTheDocument();
        expect(screen.getByText('Secrets management for your infrastructure')).toBeInTheDocument();
        expect(screen.getByTestId('username-input')).toBeInTheDocument();
        expect(screen.getByTestId('password-input')).toBeInTheDocument();
        expect(screen.getByTestId('login-button')).toBeInTheDocument();

        await waitFor(() => expect(getSSOProvidersMock).toHaveBeenCalled());
    });

    it('submits the login form with the entered credentials', async () => {
        loginMock.mockResolvedValue(undefined);
        render(<LoginPage />);

        fireEvent.change(screen.getByTestId('username-input'), { target: { value: 'dana' } });
        fireEvent.change(screen.getByTestId('password-input'), { target: { value: 'Str0ngPass!' } });
        fireEvent.click(screen.getByTestId('login-button'));

        await waitFor(() =>
            expect(loginMock).toHaveBeenCalledWith({
                username: 'dana',
                password: 'Str0ngPass!',
                rememberMe: false,
            })
        );
    });

    it('does not throw when login rejects (error is surfaced via the auth store)', async () => {
        loginMock.mockRejectedValue(new Error('Invalid credentials'));
        render(<LoginPage />);

        fireEvent.change(screen.getByTestId('username-input'), { target: { value: 'dana' } });
        fireEvent.change(screen.getByTestId('password-input'), { target: { value: 'Str0ngPass!' } });
        fireEvent.click(screen.getByTestId('login-button'));

        await waitFor(() => expect(loginMock).toHaveBeenCalled());
    });

    it('renders the auth-store error via the login form alert', async () => {
        authState.error = 'Invalid username or password';
        render(<LoginPage />);

        expect(await screen.findByText('Invalid username or password')).toBeInTheDocument();
    });

    it('shows a full-page loading state when already authenticated and still loading', () => {
        authState.isAuthenticated = true;
        authState.isLoading = true;
        render(<LoginPage />);

        expect(screen.getByText('Loading...')).toBeInTheDocument();
        expect(screen.queryByTestId('username-input')).not.toBeInTheDocument();
    });

    it('redirects to the dashboard when already authenticated', () => {
        authState.isAuthenticated = true;
        authState.isLoading = false;
        render(<LoginPage />);

        expect(navigateMock).toHaveBeenCalledWith('/dashboard', { replace: true });
    });

    it('redirects to the originally-requested route preserved in location state', () => {
        window.history.pushState({ usr: { from: { pathname: '/secrets' } } }, '', '/login');
        authState.isAuthenticated = true;
        authState.isLoading = false;
        render(<LoginPage />);

        expect(navigateMock).toHaveBeenCalledWith('/secrets', { replace: true });
    });

    it('shows an SSO error banner from the sso_error query param', () => {
        window.history.pushState({}, '', '/login?sso_error=access_denied');
        render(<LoginPage />);

        expect(screen.getByText('SSO sign-in failed: access_denied')).toBeInTheDocument();
    });

    it('does not show an SSO error banner when there is no sso_error param', () => {
        render(<LoginPage />);

        expect(screen.queryByText(/SSO sign-in failed/)).not.toBeInTheDocument();
    });

    it('renders SSO provider links once they load, targeting the default dashboard return_to', async () => {
        getSSOProvidersMock.mockResolvedValue(['google', 'okta']);
        render(<LoginPage />);

        const googleLink = await screen.findByRole('link', { name: 'Sign in with google' });
        expect(googleLink).toHaveAttribute('href', '/auth/sso/google/login?return_to=%2Fdashboard');

        const oktaLink = screen.getByRole('link', { name: 'Sign in with okta' });
        expect(oktaLink).toHaveAttribute('href', '/auth/sso/okta/login?return_to=%2Fdashboard');
    });

    it('preserves the originally-requested route in the SSO return_to param', async () => {
        window.history.pushState({ usr: { from: { pathname: '/secrets' } } }, '', '/login');
        getSSOProvidersMock.mockResolvedValue(['google']);
        render(<LoginPage />);

        const googleLink = await screen.findByRole('link', { name: 'Sign in with google' });
        expect(googleLink).toHaveAttribute('href', '/auth/sso/google/login?return_to=%2Fsecrets');
    });

    it('does not render the SSO divider or links when no providers are configured', async () => {
        render(<LoginPage />);

        await waitFor(() => expect(getSSOProvidersMock).toHaveBeenCalled());
        expect(screen.queryByText('or')).not.toBeInTheDocument();
        expect(screen.queryByRole('link', { name: /Sign in with/ })).not.toBeInTheDocument();
    });

    // BUG (not fixed here — coverage-only PR): LoginPage never passes an
    // `onForgotPassword` prop to <LoginForm />, so LoginForm's "Forgot
    // password?" button (which only renders when that prop is provided) never
    // appears. Since nothing else in LoginPage ever calls `setMode('reset')`,
    // the 'reset' / 'reset-success' branch and the whole PasswordResetForm
    // integration are unreachable through the rendered UI.
    it('never renders a way to reach the password-reset form (see BUG note above)', async () => {
        render(<LoginPage />);

        await waitFor(() => expect(getSSOProvidersMock).toHaveBeenCalled());
        expect(screen.queryByText('Forgot password?')).not.toBeInTheDocument();
        expect(screen.queryByText('Reset Password')).not.toBeInTheDocument();
    });
});
