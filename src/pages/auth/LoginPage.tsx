import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { LoginForm, PasswordResetForm } from '../../components/forms';
import { useAuth } from '../../hooks/useAuth';
import { authService } from '../../services/auth';
import { LoginFormData, PasswordResetRequest } from '../../types';
import { ROUTES } from '../../constants';

type AuthMode = 'login' | 'reset' | 'reset-success';

export const LoginPage: React.FC = () => {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const location = useLocation();
    const { login, isAuthenticated, isLoading, error, clearError } = useAuth();

    const [mode, setMode] = useState<AuthMode>('login');
    const [resetLoading, setResetLoading] = useState(false);
    const [resetError, setResetError] = useState<string | null>(null);

    // Redirect if already authenticated
    useEffect(() => {
        if (isAuthenticated) {
            const from = (location.state as any)?.from?.pathname || ROUTES.DASHBOARD;
            navigate(from, { replace: true });
        }
    }, [isAuthenticated, navigate, location]);

    // Clear errors when mode changes
    useEffect(() => {
        clearError();
        setResetError(null);
    }, [mode, clearError]);

    const handleLogin = async (data: LoginFormData) => {
        try {
            await login(data);
            // Navigation will be handled by the useEffect above
        } catch (error) {
            // Error is handled by the auth store
        }
    };

    const handlePasswordReset = async (data: PasswordResetRequest) => {
        setResetLoading(true);
        setResetError(null);

        try {
            await authService.requestPasswordReset(data);
            setMode('reset-success');
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Password reset failed';
            setResetError(errorMessage);
        } finally {
            setResetLoading(false);
        }
    };

    const handleBackToLogin = () => {
        setMode('login');
        setResetError(null);
    };

    const handleForgotPassword = () => {
        setMode('reset');
    };

    if (isLoading && isAuthenticated) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                    <p className="text-gray-600">{t('common.loading')}...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-md w-full space-y-8">
                {/* Header */}
                <div className="text-center">
                    <h1 className="text-3xl font-bold text-gray-900 mb-2">
                        Keyorix
                    </h1>
                    <p className="text-gray-600">
                        {t('dashboard.welcome')}
                    </p>
                </div>

                {/* Auth Form Container */}
                <div className="bg-white py-8 px-6 shadow-lg rounded-lg">
                    {mode === 'login' && (
                        <LoginForm
                            onSubmit={handleLogin}
                            isLoading={isLoading}
                            error={error}
                            onForgotPassword={handleForgotPassword}
                        />
                    )}

                    {(mode === 'reset' || mode === 'reset-success') && (
                        <PasswordResetForm
                            onSubmit={handlePasswordReset}
                            onBack={handleBackToLogin}
                            isLoading={resetLoading}
                            error={resetError}
                            success={mode === 'reset-success'}
                        />
                    )}
                </div>

                {/* Footer */}
                <div className="text-center text-sm text-gray-500">
                    <p>
                        {t('auth.secureLogin')} • {t('auth.protectedBySSL')}
                    </p>
                </div>
            </div>
        </div>
    );
};