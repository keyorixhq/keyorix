import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import { Input } from '../../components/ui/Input';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import type { LoginFormData } from '../../types';

const schema = z.object({
    username: z.string().min(1, 'Username is required'),
    password: z.string().min(6, 'Password must be at least 6 characters'),
    rememberMe: z.boolean(),
});

interface LoginFormProps {
    onSubmit: (data: LoginFormData) => Promise<void>;
    isLoading?: boolean;
    error?: string | null;
    onForgotPassword?: () => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({ onSubmit, isLoading = false, error, onForgotPassword }) => {
    const [showPassword, setShowPassword] = useState(false);

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<z.infer<typeof schema>>({
        resolver: zodResolver(schema),
        defaultValues: { username: '', password: '', rememberMe: false },
    });

    return (
        <form onSubmit={handleSubmit((data) => onSubmit(data))} className="space-y-6" noValidate>
            <Input
                label="Username"
                type="text"
                autoComplete="username"
                placeholder="Username"
                disabled={isLoading}
                data-testid="username-input"
                {...(errors.username?.message && { error: errors.username.message })}
                {...register('username')}
            />

            <Input
                label="Password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                placeholder="Password"
                disabled={isLoading}
                data-testid="password-input"
                {...(errors.password?.message && { error: errors.password.message })}
                trailingElement={
                    <button
                        type="button"
                        onClick={() => setShowPassword((v) => !v)}
                        disabled={isLoading}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        className="focus:outline-hidden"
                    >
                        {showPassword ? (
                            <EyeSlashIcon className="h-5 w-5 text-base-muted" />
                        ) : (
                            <EyeIcon className="h-5 w-5 text-base-muted" />
                        )}
                    </button>
                }
                {...register('password')}
            />

            <div className="flex items-center justify-between">
                <div className="flex items-center">
                    <input
                        id="rememberMe"
                        type="checkbox"
                        className="h-4 w-4 rounded-sm"
                        disabled={isLoading}
                        data-testid="remember-me-checkbox"
                        {...register('rememberMe')}
                    />
                    <label htmlFor="rememberMe" className="ml-2 text-sm text-base-secondary">
                        Remember me
                    </label>
                </div>
                {onForgotPassword && (
                    <button
                        type="button"
                        onClick={onForgotPassword}
                        disabled={isLoading}
                        className="text-sm text-[var(--accent-text)] hover:underline focus:outline-hidden focus:underline"
                    >
                        Forgot password?
                    </button>
                )}
            </div>

            {error && <Alert type="error" message={error} />}

            <Button
                type="submit"
                className="w-full"
                loading={isLoading}
                disabled={isLoading}
                data-testid="login-button"
            >
                Sign in
            </Button>
        </form>
    );
};
