import React, { useState, useEffect, useRef } from 'react';
import { ExclamationTriangleIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useAuth } from '../../features/auth';
import { getTimeUntilAbsoluteExpiry } from '../../utils/auth';

interface AbsoluteSessionExpiryWarningProps {
    // How long before the hard ceiling to start warning (default 5 minutes).
    warningTimeMs?: number;
}

/**
 * A non-blocking banner that warns as the session's ABSOLUTE lifetime ceiling
 * approaches. Distinct from SessionTimeoutWarning (which is inactivity-based and
 * offers "Extend Session"): the absolute ceiling cannot be extended — refresh is
 * refused past it (see authStore.refreshToken) — so the only remedy is to sign in
 * again. We give an active user a heads-up to save their work, then sign them out
 * the moment the ceiling is reached.
 *
 * Renders nothing when no ceiling is configured (getTimeUntilAbsoluteExpiry()
 * returns null — the refreshable-indefinitely / legacy case).
 */
export const AbsoluteSessionExpiryWarning: React.FC<AbsoluteSessionExpiryWarningProps> = ({
    warningTimeMs = 5 * 60 * 1000,
}) => {
    const { isAuthenticated, logout } = useAuth();
    const [remaining, setRemaining] = useState<number | null>(null);
    const [dismissed, setDismissed] = useState(false);

    // Keep a stable ref to logout so the 1s interval doesn't re-subscribe.
    const logoutRef = useRef(logout);
    useEffect(() => {
        logoutRef.current = logout;
    });

    useEffect(() => {
        if (!isAuthenticated) {
            setRemaining(null);
            return;
        }

        const tick = () => {
            const ms = getTimeUntilAbsoluteExpiry();
            setRemaining(ms);
            // Ceiling reached: refresh can't help, so sign out (redirects to /login).
            if (ms !== null && ms <= 0) {
                void logoutRef.current();
            }
        };

        tick();
        const interval = setInterval(tick, 1000);
        return () => clearInterval(interval);
    }, [isAuthenticated]);

    // Hide unless authenticated, a ceiling exists, we're inside the warning
    // window, the deadline hasn't passed, and the user hasn't dismissed it.
    if (!isAuthenticated || remaining === null || remaining <= 0 || remaining > warningTimeMs || dismissed) {
        return null;
    }

    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    const countdown = `${minutes}:${seconds.toString().padStart(2, '0')}`;

    return (
        <div
            className="fixed top-0 left-0 right-0 z-50 border-b px-4 py-3"
            role="alert"
            style={{ backgroundColor: 'rgba(245,158,11,0.12)', borderColor: 'var(--border)' }}
        >
            <div className="mx-auto flex max-w-5xl items-center gap-3">
                <ExclamationTriangleIcon className="h-5 w-5 shrink-0" style={{ color: '#f59e0b' }} />
                <p className="flex-1 text-sm" style={{ color: 'var(--text-primary)' }}>
                    Your session ends in <span className="font-semibold">{countdown}</span> and can&rsquo;t be extended.
                    Sign in again to keep working without losing access.
                </p>
                <button
                    type="button"
                    onClick={() => {
                        void logout();
                    }}
                    className="rounded-md px-3 py-1.5 text-sm font-medium focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                    style={{ backgroundColor: 'var(--accent)', color: '#ffffff' }}
                    onMouseEnter={(e) =>
                        ((e.currentTarget as HTMLElement).style.backgroundColor = 'var(--accent-hover)')
                    }
                    onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.backgroundColor = 'var(--accent)')}
                >
                    Sign in again
                </button>
                <button
                    type="button"
                    onClick={() => setDismissed(true)}
                    className="rounded-md p-1 focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                    style={{ color: 'var(--text-muted)' }}
                    aria-label="Dismiss"
                    onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                    onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                >
                    <XMarkIcon className="h-5 w-5" />
                </button>
            </div>
        </div>
    );
};
