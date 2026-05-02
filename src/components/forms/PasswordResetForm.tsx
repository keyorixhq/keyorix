import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { PasswordResetRequest } from '../../types';
import { isValidEmail, cn } from '../../utils';

interface PasswordResetFormProps {
    onSubmit: (data: PasswordResetRequest) => Promise<void>;
    onBack: () => void;
    isLoading?: boolean;
    error?: string | null;
    success?: boolean;
}

export const PasswordResetForm: React.FC<PasswordResetFormProps> = ({
    onSubmit,
    onBack,
    isLoading = false,
    error,
    success = false,
}) => {
    const { t } = useTranslation();
    const [email, setEmail] = useState('');
    const [validationError, setValidationError] = useState<string>('');

    const validateForm = (): boolean => {
        if (!email.trim()) {
            setValidationError(t('validation.required', { field: t('auth.email') }));
            return false;
        }

        if (!isValidEmail(email)) {
            setValidationError(t('validation.invalidEmail'));
            return false;
        }

        setValidationError('');
        return true;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) {
            return;
        }

        try {
            await onSubmit({ email });
        } catch (error) {
            // Error handling is done by parent component
        }
    };

    const handleEmailChange = (value: string) => {
        setEmail(value);
        if (validationError) {
            setValidationError('');
        }
    };

    if (success) {
        return (
            <div className="text-center">
                <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
                    <svg
                        className="h-6 w-6 text-green-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                        <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth="2"
                            d="M5 13l4 4L19 7"
                        />
                    </svg>
                </div>
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                    {t('auth.passwordResetSent')}
                </h3>
                <p className="text-sm text-gray-600 mb-6">
                    {t('auth.passwordResetInstructions', { email })}
                </p>
                <button
                    type="button"
                    onClick={onBack}
                    className="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                    {t('auth.backToLogin')}
                </button>
            </div>
        );
    }

    return (
        <form onSubmit={handleSubmit} className="space-y-6" noValidate>
            <div className="text-center mb-6">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">
                    {t('auth.resetPassword')}
                </h2>
                <p className="text-sm text-gray-600">
                    {t('auth.resetPasswordDescription')}
                </p>
            </div>

            {/* Email Field */}
            <div>
                <label
                    htmlFor="reset-email"
                    className="block text-sm font-medium text-gray-700 mb-1"
                >
                    {t('auth.email')}
                </label>
                <input
                    type="email"
                    id="reset-email"
                    name="email"
                    autoComplete="email"
                    required
                    value={email}
                    onChange={(e) => handleEmailChange(e.target.value)}
                    className={cn(
                        'block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400',
                        'focus:outline-none focus:ring-2 focus:ring-offset-2',
                        validationError
                            ? 'border-red-300 focus:border-red-500 focus:ring-red-500'
                            : 'border-gray-300 focus:border-blue-500 focus:ring-blue-500'
                    )}
                    placeholder="user@example.com"
                    disabled={isLoading}
                />
                {validationError && (
                    <p className="mt-1 text-sm text-red-600" role="alert">
                        {validationError}
                    </p>
                )}
            </div>

            {/* Error Message */}
            {error && (
                <div className="rounded-md bg-red-50 p-4" role="alert">
                    <div className="text-sm text-red-700">
                        {error}
                    </div>
                </div>
            )}

            {/* Action Buttons */}
            <div className="space-y-3">
                <button
                    type="submit"
                    disabled={isLoading}
                    className={cn(
                        'w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white',
                        'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500',
                        isLoading
                            ? 'bg-gray-400 cursor-not-allowed'
                            : 'bg-blue-600 hover:bg-blue-700'
                    )}
                >
                    {isLoading ? (
                        <div className="flex items-center">
                            <svg
                                className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                                xmlns="http://www.w3.org/2000/svg"
                                fill="none"
                                viewBox="0 0 24 24"
                            >
                                <circle
                                    className="opacity-25"
                                    cx="12"
                                    cy="12"
                                    r="10"
                                    stroke="currentColor"
                                    strokeWidth="4"
                                ></circle>
                                <path
                                    className="opacity-75"
                                    fill="currentColor"
                                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                                ></path>
                            </svg>
                            {t('common.loading')}
                        </div>
                    ) : (
                        t('auth.sendResetLink')
                    )}
                </button>

                <button
                    type="button"
                    onClick={onBack}
                    disabled={isLoading}
                    className="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    {t('auth.backToLogin')}
                </button>
            </div>
        </form>
    );
};