import React, { useState } from 'react';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import { LoginFormData } from '../../types';
import { cn } from '../../utils';

interface LoginFormProps {
    onSubmit: (data: LoginFormData) => Promise<void>;
    isLoading?: boolean;
    error?: string | null;
    onForgotPassword?: () => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({
    onSubmit,
    isLoading = false,
    error,
    onForgotPassword,
}) => {
    const [formData, setFormData] = useState<LoginFormData>({
        username: '',
        password: '',
        rememberMe: false,
    });
    const [showPassword, setShowPassword] = useState(false);
    const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

    const validateForm = (): boolean => {
        const errors: Record<string, string> = {};
        if (!formData.username.trim()) errors.username = 'Username is required';
        if (!formData.password.trim()) {
            errors.password = 'Password is required';
        } else if (formData.password.length < 6) {
            errors.password = 'Password must be at least 6 characters long';
        }
        setValidationErrors(errors);
        return Object.keys(errors).length === 0;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!validateForm()) return;
        try {
            await onSubmit(formData);
        } catch {
            // Error handling done by parent
        }
    };

    const handleInputChange = (field: keyof LoginFormData, value: string | boolean) => {
        setFormData(prev => ({ ...prev, [field]: value }));
        if (validationErrors[field]) {
            setValidationErrors(prev => { const e = { ...prev }; delete e[field]; return e; });
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6" noValidate>
            <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                    Username
                </label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    autoComplete="username"
                    required
                    value={formData.username}
                    onChange={(e) => handleInputChange('username', e.target.value)}
                    className={cn(
                        'block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400',
                        'focus:outline-none focus:ring-2 focus:ring-offset-2',
                        validationErrors.username
                            ? 'border-red-300 focus:border-red-500 focus:ring-red-500'
                            : 'border-gray-300 focus:border-blue-500 focus:ring-blue-500'
                    )}
                    placeholder="Username"
                    disabled={isLoading}
                />
                {validationErrors.username && (
                    <p className="mt-1 text-sm text-red-600" role="alert">{validationErrors.username}</p>
                )}
            </div>

            <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                    Password
                </label>
                <div className="relative">
                    <input
                        type={showPassword ? 'text' : 'password'}
                        id="password"
                        name="password"
                        autoComplete="current-password"
                        required
                        value={formData.password}
                        onChange={(e) => handleInputChange('password', e.target.value)}
                        className={cn(
                            'block w-full px-3 py-2 pr-10 border rounded-md shadow-sm placeholder-gray-400',
                            'focus:outline-none focus:ring-2 focus:ring-offset-2',
                            validationErrors.password
                                ? 'border-red-300 focus:border-red-500 focus:ring-red-500'
                                : 'border-gray-300 focus:border-blue-500 focus:ring-blue-500'
                        )}
                        placeholder="Password"
                        disabled={isLoading}
                    />
                    <button
                        type="button"
                        className="absolute inset-y-0 right-0 pr-3 flex items-center"
                        onClick={() => setShowPassword(!showPassword)}
                        disabled={isLoading}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                        {showPassword ? (
                            <EyeSlashIcon className="h-5 w-5 text-gray-400" />
                        ) : (
                            <EyeIcon className="h-5 w-5 text-gray-400" />
                        )}
                    </button>
                </div>
                {validationErrors.password && (
                    <p className="mt-1 text-sm text-red-600" role="alert">{validationErrors.password}</p>
                )}
            </div>

            <div className="flex items-center justify-between">
                <div className="flex items-center">
                    <input
                        id="rememberMe"
                        name="rememberMe"
                        type="checkbox"
                        checked={formData.rememberMe}
                        onChange={(e) => handleInputChange('rememberMe', e.target.checked)}
                        className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                        disabled={isLoading}
                    />
                    <label htmlFor="rememberMe" className="ml-2 block text-sm text-gray-700">
                        Remember me
                    </label>
                </div>
                {onForgotPassword && (
                    <button
                        type="button"
                        onClick={onForgotPassword}
                        className="text-sm text-blue-600 hover:text-blue-500 focus:outline-none focus:underline"
                        disabled={isLoading}
                    >
                        Forgot password?
                    </button>
                )}
            </div>

            {error && (
                <div className="rounded-md bg-red-50 p-4" role="alert">
                    <div className="text-sm text-red-700">{error}</div>
                </div>
            )}

            <button
                type="submit"
                disabled={isLoading}
                className={cn(
                    'w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white',
                    'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500',
                    isLoading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
                )}
            >
                {isLoading ? (
                    <div className="flex items-center">
                        <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Loading...
                    </div>
                ) : 'Sign in'}
            </button>
        </form>
    );
};
