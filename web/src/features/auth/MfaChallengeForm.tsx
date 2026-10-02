import React, { useState } from 'react';
import { Input } from '../../components/ui/Input';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';

// MfaChallengeForm is the login-time MFA second step (#2442): rendered once
// authStore.login() reports mfa_required, it collects either a current TOTP
// code or a recovery code (the backend accepts both at the same endpoint —
// internal/core/mfa.go's VerifyMFACredentials tries TOTP first, then a
// recovery code) and submits it against the pending challenge.
interface MfaChallengeFormProps {
    onSubmit: (code: string) => Promise<void>;
    onBack: () => void;
    isLoading?: boolean;
    error?: string | null;
}

export const MfaChallengeForm: React.FC<MfaChallengeFormProps> = ({ onSubmit, onBack, isLoading = false, error }) => {
    const [code, setCode] = useState('');

    const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        onSubmit(code.trim());
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6" noValidate>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                Enter the 6-digit code from your authenticator app, or one of your recovery codes.
            </p>

            <Input
                label="Authentication code"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                disabled={isLoading}
                data-testid="mfa-code-input"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoFocus
            />

            {/* Deliberately renders whatever message the API returned, verbatim —
                see authStore.verifyMfa's doc comment: the backend already collapses
                wrong-code/expired-challenge/lockout into one generic string (or a
                distinct rate-limit message), and this must not try to guess which. */}
            {error && <Alert type="error" message={error} />}

            <div className="flex items-center justify-between gap-2">
                <button
                    type="button"
                    onClick={onBack}
                    disabled={isLoading}
                    className="text-sm text-[var(--accent-text)] hover:underline focus:outline-hidden focus:underline"
                >
                    Back to login
                </button>
                <Button type="submit" loading={isLoading} disabled={isLoading || !code} data-testid="mfa-verify-button">
                    Verify
                </Button>
            </div>
        </form>
    );
};
