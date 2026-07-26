import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { SetupForm } from '../../features/auth/SetupForm';
import { setupService, SetupTokenInfo } from '../../services/setup';
import { useAuthStore } from '../../store/authStore';
import { ROUTES } from '../../constants';

type Phase = 'loading' | 'ready' | 'invalid';

// SetupPage is the public landing for a credential-delivery setup link (ADR-028):
// /auth/setup/:token. It validates the token, shows a set-password form, consumes
// the token, and lands the user logged in.
export const SetupPage: React.FC = () => {
    const { token } = useParams<{ token: string }>();
    const navigate = useNavigate();
    const completeSetup = useAuthStore((s) => s.completeSetup);

    const [phase, setPhase] = useState<Phase>('loading');
    const [info, setInfo] = useState<SetupTokenInfo | null>(null);
    const [invalidReason, setInvalidReason] = useState<string>('');
    const [submitting, setSubmitting] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        if (!token) {
            setPhase('invalid');
            setInvalidReason('This setup link is missing its token.');
            return;
        }
        setupService
            .describe(token)
            .then((i) => {
                if (!active) return;
                setInfo(i);
                setPhase('ready');
            })
            .catch((err: unknown) => {
                if (!active) return;
                setInvalidReason(err instanceof Error ? err.message : 'This setup link is no longer valid.');
                setPhase('invalid');
            });
        return () => {
            active = false;
        };
    }, [token]);

    const handleSubmit = async (password: string) => {
        if (!token) return;
        setSubmitting(true);
        setSubmitError(null);
        try {
            const session = await setupService.consume(token, password);
            completeSetup(session);
            navigate(ROUTES.DASHBOARD, { replace: true });
        } catch (err) {
            // A policy rejection keeps the link usable — surface it and let the user retry.
            setSubmitError(err instanceof Error ? err.message : 'Setup failed');
            throw err;
        } finally {
            setSubmitting(false);
        }
    };

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
                    <p style={{ color: 'var(--text-secondary)' }}>Set up your account</p>
                </div>

                <div
                    className="py-8 px-6 shadow-lg rounded-lg border"
                    style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                >
                    {phase === 'loading' && (
                        <div className="text-center py-4">
                            <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-500 mx-auto mb-4"></div>
                            <p style={{ color: 'var(--text-secondary)' }}>Checking your setup link…</p>
                        </div>
                    )}

                    {phase === 'invalid' && (
                        <div className="text-center space-y-4">
                            <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
                                This link can’t be used
                            </h2>
                            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                {invalidReason}
                            </p>
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                Setup links are single-use and expire. Ask your administrator to send a new one.
                            </p>
                            <a href={ROUTES.LOGIN} className="inline-block text-sm text-blue-600 hover:text-blue-500">
                                Back to sign in
                            </a>
                        </div>
                    )}

                    {phase === 'ready' && info && (
                        <div className="space-y-6">
                            <div>
                                <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                    {info.display_name ? `Welcome, ${info.display_name}.` : 'Welcome.'} Choose a
                                    password to finish setting up your account for{' '}
                                    <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
                                        {info.email}
                                    </span>
                                    .
                                </p>
                            </div>
                            <SetupForm onSubmit={handleSubmit} isLoading={submitting} error={submitError} />
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};
