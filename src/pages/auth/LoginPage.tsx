import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { LoginForm, PasswordResetForm, useAuth } from '../../features/auth';
import { authService } from '../../services/auth';
import { LoginFormData, PasswordResetRequest } from '../../types';
import { ROUTES } from '../../constants';

type AuthMode = 'login' | 'reset' | 'reset-success';

export const LoginPage: React.FC = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { login, isAuthenticated, isLoading, error, clearError } = useAuth();

    const [mode, setMode] = useState<AuthMode>('login');
    const [resetLoading, setResetLoading] = useState(false);
    const [resetError, setResetError] = useState<string | null>(null);
    const [ssoProviders, setSsoProviders] = useState<string[]>([]);
    const ssoError = new URLSearchParams(location.search).get('sso_error');

    useEffect(() => {
        let active = true;
        authService.getSSOProviders().then((p) => {
            if (active) setSsoProviders(p);
        });
        return () => {
            active = false;
        };
    }, []);

    // Where to land after SSO — preserve the originally-requested route.
    const ssoReturnTo = (location.state as any)?.from?.pathname || ROUTES.DASHBOARD;
    const ssoHref = (name: string) =>
        `/auth/sso/${encodeURIComponent(name)}/login?return_to=${encodeURIComponent(ssoReturnTo)}`;

    useEffect(() => {
        if (isAuthenticated) {
            const from = (location.state as any)?.from?.pathname || ROUTES.DASHBOARD;
            navigate(from, { replace: true });
        }
    }, [isAuthenticated, navigate, location]);

    useEffect(() => {
        clearError();
        setResetError(null);
    }, [mode, clearError]);

    const handleLogin = async (data: LoginFormData) => {
        try {
            await login(data);
        } catch {
            // Error handled by auth store
        }
    };

    const handlePasswordReset = async (data: PasswordResetRequest) => {
        setResetLoading(true);
        setResetError(null);
        try {
            await authService.requestPasswordReset(data);
            setMode('reset-success');
        } catch (error) {
            setResetError(error instanceof Error ? error.message : 'Password reset failed');
        } finally {
            setResetLoading(false);
        }
    };

    if (isLoading && isAuthenticated) {
        return (
            <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg-app)' }}>
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
                    <p style={{ color: 'var(--text-secondary)' }}>Loading...</p>
                </div>
            </div>
        );
    }

    return (
        <div
            className="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8"
            style={{ backgroundColor: 'var(--bg-app)' }}
        >
            <div className="max-w-md w-full space-y-8">
                <div className="text-center">
                    <div className="inline-flex items-center justify-center h-12 w-12 bg-blue-600 rounded-xl mb-4">
                        <span className="text-white font-bold text-lg">K</span>
                    </div>
                    <h1 className="text-3xl font-bold mb-2" style={{ color: 'var(--text-primary)' }}>
                        Keyorix
                    </h1>
                    <p style={{ color: 'var(--text-secondary)' }}>Secrets management for your infrastructure</p>
                </div>

                <div
                    className="py-8 px-6 shadow-lg rounded-lg border"
                    style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                >
                    {mode === 'login' && (
                        <>
                            {ssoError && (
                                <div
                                    className="mb-4 rounded-lg px-3 py-2 text-sm"
                                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                                >
                                    SSO sign-in failed: {ssoError}
                                </div>
                            )}
                            <LoginForm onSubmit={handleLogin} isLoading={isLoading} error={error} />
                            {ssoProviders.length > 0 && (
                                <div className="mt-6">
                                    <div className="relative flex items-center my-4">
                                        <div className="grow border-t" style={{ borderColor: 'var(--border)' }} />
                                        <span
                                            className="mx-3 text-xs uppercase tracking-wider"
                                            style={{ color: 'var(--text-muted)' }}
                                        >
                                            or
                                        </span>
                                        <div className="grow border-t" style={{ borderColor: 'var(--border)' }} />
                                    </div>
                                    <div className="space-y-2">
                                        {ssoProviders.map((name) => (
                                            <a
                                                key={name}
                                                href={ssoHref(name)}
                                                className="block w-full text-center px-4 py-2 rounded-lg text-sm font-medium border capitalize"
                                                style={{
                                                    borderColor: 'var(--border)',
                                                    color: 'var(--text-primary)',
                                                    backgroundColor: 'var(--bg-app)',
                                                }}
                                            >
                                                Sign in with {name}
                                            </a>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                    {(mode === 'reset' || mode === 'reset-success') && (
                        <PasswordResetForm
                            onSubmit={handlePasswordReset}
                            onBack={() => {
                                setMode('login');
                                setResetError(null);
                            }}
                            isLoading={resetLoading}
                            error={resetError}
                            success={mode === 'reset-success'}
                        />
                    )}
                </div>
            </div>
        </div>
    );
};
