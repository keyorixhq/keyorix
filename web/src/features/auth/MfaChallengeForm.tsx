import React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Input } from '../../components/ui/Input';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';

const schema = z.object({
    code: z.string().min(1, 'Enter your authenticator code or a recovery code'),
});

interface MfaChallengeFormProps {
    onSubmit: (code: string) => Promise<void>;
    onBack: () => void;
    isLoading?: boolean;
    error?: string | null;
}

// MfaChallengeForm is step two of login for an MFA-enabled account (#2442):
// rendered once authStore's pendingMfa is set (a correct password, but the
// session isn't minted yet). Accepts either a TOTP code or a recovery code in
// the same field -- server/http/handlers/mfa.go's VerifyMFA (via
// core.VerifyMFACredentials) tries both, so the client doesn't need to ask
// which kind the user is entering.
export const MfaChallengeForm: React.FC<MfaChallengeFormProps> = ({ onSubmit, onBack, isLoading = false, error }) => {
    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<z.infer<typeof schema>>({
        resolver: zodResolver(schema),
        defaultValues: { code: '' },
    });

    return (
        <form onSubmit={handleSubmit((data) => onSubmit(data.code))} className="space-y-6" noValidate>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                Enter the 6-digit code from your authenticator app, or one of your recovery codes.
            </p>

            <Input
                label="Authenticator code or recovery code"
                type="text"
                inputMode="text"
                autoComplete="one-time-code"
                placeholder="123456"
                autoFocus
                disabled={isLoading}
                data-testid="mfa-code-input"
                {...(errors.code?.message && { error: errors.code.message })}
                {...register('code')}
            />

            {error && <Alert type="error" message={error} />}

            <div className="flex items-center justify-between">
                <button
                    type="button"
                    onClick={onBack}
                    disabled={isLoading}
                    className="text-sm text-[var(--accent-text)] hover:underline focus:outline-hidden focus:underline"
                >
                    Back to sign in
                </button>
                <Button type="submit" loading={isLoading} disabled={isLoading} data-testid="mfa-verify-button">
                    Verify
                </Button>
            </div>
        </form>
    );
};
