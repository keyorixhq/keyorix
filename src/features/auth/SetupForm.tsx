import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import { Input } from '../../components/ui/Input';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';

const schema = z.object({
    password: z.string().min(1, 'Password is required'),
    confirm:  z.string(),
}).refine(data => data.password === data.confirm, {
    message: 'Passwords do not match',
    path:    ['confirm'],
});

interface SetupFormProps {
    onSubmit: (password: string) => Promise<void>;
    isLoading?: boolean;
    error?: string | null;
}

export const SetupForm: React.FC<SetupFormProps> = ({ onSubmit, isLoading = false, error }) => {
    const [showPassword, setShowPassword] = useState(false);

    const { register, handleSubmit, formState: { errors } } = useForm<z.infer<typeof schema>>({
        resolver: zodResolver(schema),
        defaultValues: { password: '', confirm: '' },
    });

    const revealToggle = (
        <button
            type="button"
            onClick={() => setShowPassword(v => !v)}
            disabled={isLoading}
            aria-label={showPassword ? 'Hide password' : 'Show password'}
            className="focus:outline-hidden"
        >
            {showPassword
                ? <EyeSlashIcon className="h-5 w-5 text-base-muted" />
                : <EyeIcon className="h-5 w-5 text-base-muted" />}
        </button>
    );

    return (
        <form
            onSubmit={handleSubmit(data => onSubmit(data.password))}
            className="space-y-6"
            noValidate
        >
            <Input
                label="New password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder="New password"
                disabled={isLoading}
                {...(errors.password?.message && { error: errors.password.message })}
                trailingElement={revealToggle}
                {...register('password')}
            />

            <Input
                label="Confirm password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder="Confirm password"
                disabled={isLoading}
                {...(errors.confirm?.message && { error: errors.confirm.message })}
                {...register('confirm')}
            />

            {error && <Alert type="error" message={error} />}

            <Button type="submit" className="w-full" loading={isLoading} disabled={isLoading}>
                Set password and continue
            </Button>
        </form>
    );
};
