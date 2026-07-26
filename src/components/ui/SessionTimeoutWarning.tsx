import React, { useEffect, useState } from 'react';
import { ExclamationTriangleIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useAuth } from '../../features/auth';

interface SessionTimeoutWarningProps {
    onExtendSession?: () => void;
    onLogout?: () => void;
}

// Purely presentational: the countdown itself is owned by useAuth()
// (sessionTimeLeftMs), which is the single source of truth for the inactivity
// deadline — this component no longer runs its own independent timer/activity
// listeners, so the warning window can't drift out of sync with the real
// SESSION_TIMEOUT-driven logout.
export const SessionTimeoutWarning: React.FC<SessionTimeoutWarningProps> = ({ onExtendSession, onLogout }) => {
    const { isAuthenticated, sessionTimeLeftMs, logout, refreshToken } = useAuth();
    const [isExtending, setIsExtending] = useState(false);
    const [dismissed, setDismissed] = useState(false);

    const showWarning = isAuthenticated && sessionTimeLeftMs !== null && !dismissed;

    // Re-arm dismissal once the user leaves the warning window (activity reset
    // the deadline), so the next inactivity cycle can warn again.
    useEffect(() => {
        if (sessionTimeLeftMs === null && dismissed) setDismissed(false);
    }, [sessionTimeLeftMs, dismissed]);

    const handleExtendSession = async () => {
        setIsExtending(true);
        try {
            await refreshToken();
            onExtendSession?.();
        } catch {
            await handleLogout();
        } finally {
            setIsExtending(false);
        }
    };

    const handleLogout = async () => {
        await logout();
        onLogout?.();
    };

    const formatTime = (ms: number) => {
        const m = Math.floor(ms / 60000);
        const s = Math.floor((ms % 60000) / 1000);
        return `${m}:${s.toString().padStart(2, '0')}`;
    };

    if (!showWarning) return null;

    return (
        <div className="fixed inset-0 z-50 overflow-y-auto" role="dialog" aria-modal="true">
            <div className="fixed inset-0 bg-black bg-opacity-50 transition-opacity" />
            <div className="flex min-h-full items-center justify-center p-4">
                <div
                    className="relative rounded-lg shadow-xl max-w-md w-full border"
                    style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                >
                    <button
                        type="button"
                        className="absolute top-4 right-4 rounded-md transition-colors focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                        style={{ color: 'var(--text-muted)' }}
                        onClick={() => setDismissed(true)}
                        aria-label="Close"
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                    >
                        <XMarkIcon className="h-6 w-6" />
                    </button>
                    <div className="p-6">
                        <div
                            className="mx-auto flex items-center justify-center h-12 w-12 rounded-full mb-4"
                            style={{ backgroundColor: 'rgba(245,158,11,0.12)' }}
                        >
                            <ExclamationTriangleIcon className="h-6 w-6" style={{ color: '#f59e0b' }} />
                        </div>
                        <div className="text-center">
                            <h3 className="text-lg font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
                                Session Expiring
                            </h3>
                            <p className="text-sm mb-4" style={{ color: 'var(--text-secondary)' }}>
                                Your session will expire soon due to inactivity. Would you like to extend your session?
                            </p>
                            <div className="text-2xl font-bold mb-6" style={{ color: '#f87171' }}>
                                {formatTime(sessionTimeLeftMs ?? 0)}
                            </div>
                            <div className="flex space-x-3">
                                <button
                                    type="button"
                                    onClick={handleExtendSession}
                                    disabled={isExtending}
                                    className="flex-1 px-4 py-2 text-sm font-medium rounded-md focus:outline-hidden focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
                                    style={
                                        isExtending
                                            ? {
                                                  backgroundColor: 'var(--bg-muted)',
                                                  color: 'var(--text-muted)',
                                                  cursor: 'not-allowed',
                                              }
                                            : { backgroundColor: 'var(--accent)', color: '#ffffff' }
                                    }
                                    onMouseEnter={(e) => {
                                        if (!isExtending)
                                            (e.currentTarget as HTMLElement).style.backgroundColor =
                                                'var(--accent-hover)';
                                    }}
                                    onMouseLeave={(e) => {
                                        if (!isExtending)
                                            (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--accent)';
                                    }}
                                >
                                    {isExtending ? (
                                        <div className="flex items-center justify-center">
                                            <svg
                                                className="animate-spin -ml-1 mr-2 h-4 w-4"
                                                style={{ color: 'var(--text-muted)' }}
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
                                            Loading...
                                        </div>
                                    ) : (
                                        'Extend Session'
                                    )}
                                </button>
                                <button
                                    type="button"
                                    onClick={handleLogout}
                                    className="flex-1 px-4 py-2 text-sm font-medium rounded-md border focus:outline-hidden focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
                                    style={{
                                        backgroundColor: 'var(--bg-surface)',
                                        color: 'var(--text-secondary)',
                                        borderColor: 'var(--border-strong)',
                                    }}
                                    onMouseEnter={(e) =>
                                        ((e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)')
                                    }
                                    onMouseLeave={(e) =>
                                        ((e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-surface)')
                                    }
                                >
                                    Logout
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};
