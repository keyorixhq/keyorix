import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { LoginForm, PasswordResetForm } from '../../features/auth';
import { useAuth } from '../../features/auth';
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
        <div className="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8" style={{ backgroundColor: 'var(--bg-app)' }}>
            <div className="max-w-md w-full space-y-8">
                <div className="text-center">
                    <div className="inline-flex items-center justify-center h-12 w-12 bg-blue-600 rounded-xl mb-4">
                        <span className="text-white font-bold text-lg">K</span>
                    </div>
                    <h1 className="text-3xl font-bold mb-2" style={{ color: 'var(--text-primary)' }}>Keyorix</h1>
                    <p style={{ color: 'var(--text-secondary)' }}>Secrets management for your infrastructure</p>
                </div>

                <div className="py-8 px-6 shadow-lg rounded-lg border" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
                    {mode === 'login' && (
                        <LoginForm
                            onSubmit={handleLogin}
                            isLoading={isLoading}
                            error={error}
                        />
                    )}
                    {(mode === 'reset' || mode === 'reset-success') && (
                        <PasswordResetForm
                            onSubmit={handlePasswordReset}
                            onBack={() => { setMode('login'); setResetError(null); }}
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
