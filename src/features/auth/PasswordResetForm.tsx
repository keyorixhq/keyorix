import React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { CheckCircleIcon } from '@heroicons/react/24/outline';
import { Input } from '../../components/ui/Input';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import type { PasswordResetRequest } from '../../types';

const schema = z.object({
    email: z.string().min(1, 'Email is required').email('Please enter a valid email address'),
});

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
    const { register, handleSubmit, getValues, formState: { errors } } = useForm<z.infer<typeof schema>>({
        resolver: zodResolver(schema),
        defaultValues: { email: '' },
    });

    if (success) {
        return (
            <div className="text-center">
                <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full mb-4"
                    style={{ backgroundColor: 'var(--success-subtle)' }}>
                    <CheckCircleIcon className="h-6 w-6" style={{ color: 'var(--success)' }} />
                </div>
                <h3 className="text-lg font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
                    Reset Link Sent
                </h3>
                <p className="text-sm mb-6" style={{ color: 'var(--text-secondary)' }}>
                    We've sent a password reset link to {getValues('email')}. Please check
                    your email and follow the instructions to reset your password.
                </p>
                <Button variant="outline" className="w-full" onClick={onBack}>
                    Back to Login
                </Button>
            </div>
        );
    }

    return (
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6" noValidate>
            <div className="text-center mb-6">
                <h2 className="text-2xl font-bold mb-2" style={{ color: 'var(--text-primary)' }}>
                    Reset Password
                </h2>
                <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                    Enter your email address and we'll send you a link to reset your password.
                </p>
            </div>

            <Input
                label="Email"
                type="email"
                autoComplete="email"
                placeholder="user@example.com"
                disabled={isLoading}
                {...(errors.email?.message && { error: errors.email.message })}
                {...register('email')}
            />

            {error && <Alert type="error" message={error} />}

            <div className="space-y-3">
                <Button type="submit" className="w-full" loading={isLoading} disabled={isLoading}>
                    Send Reset Link
                </Button>
                <Button
                    type="button"
                    variant="outline"
                    className="w-full"
                    onClick={onBack}
                    disabled={isLoading}
                >
                    Back to Login
                </Button>
            </div>
        </form>
    );
};
