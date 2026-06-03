import React, { useState, useEffect, useRef } from 'react';
import { ExclamationTriangleIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useAuth } from '../../features/auth';

interface SessionTimeoutWarningProps {
    warningTimeMs?: number;
    onExtendSession?: () => void;
    onLogout?: () => void;
}

export const SessionTimeoutWarning: React.FC<SessionTimeoutWarningProps> = ({
    warningTimeMs = 5 * 60 * 1000,
    onExtendSession,
    onLogout,
}) => {
    const { isAuthenticated, logout, refreshToken } = useAuth();
    const [showWarning, setShowWarning] = useState(false);
    const [timeLeft, setTimeLeft] = useState(0);
    const [isExtending, setIsExtending] = useState(false);

    // Always points at the latest handleLogout so the inactivity timer can call it
    // without re-subscribing the effect (which would re-register listeners/timers).
    const handleLogoutRef = useRef<(() => void) | null>(null);

    useEffect(() => {
        if (!isAuthenticated) { setShowWarning(false); return; }

        let warningTimeout: ReturnType<typeof setTimeout>;
        let countdownInterval: ReturnType<typeof setInterval>;

        const setupWarning = () => {
            if (warningTimeout) clearTimeout(warningTimeout);
            if (countdownInterval) clearInterval(countdownInterval);
            warningTimeout = setTimeout(() => {
                setShowWarning(true);
                setTimeLeft(warningTimeMs);
                countdownInterval = setInterval(() => {
                    setTimeLeft((prev) => {
                        if (prev <= 1000) { handleLogoutRef.current?.(); return 0; }
                        return prev - 1000;
                    });
                }, 1000);
            }, warningTimeMs);
        };

        const resetWarning = () => { setShowWarning(false); if (countdownInterval) clearInterval(countdownInterval); setupWarning(); };
        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
        events.forEach(event => document.addEventListener(event, resetWarning, true));
        setupWarning();

        return () => {
            if (warningTimeout) clearTimeout(warningTimeout);
            if (countdownInterval) clearInterval(countdownInterval);
            events.forEach(event => document.removeEventListener(event, resetWarning, true));
        };
    }, [isAuthenticated, warningTimeMs]);

    useEffect(() => { handleLogoutRef.current = handleLogout; });

    const handleExtendSession = async () => {
        setIsExtending(true);
        try {
            await refreshToken();
            setShowWarning(false);
            onExtendSession?.();
        } catch {
            handleLogout();
        } finally {
            setIsExtending(false);
        }
    };

    const handleLogout = async () => {
        setShowWarning(false);
        await logout();
        onLogout?.();
    };

    const formatTime = (ms: number) => {
        const m = Math.floor(ms / 60000);
        const s = Math.floor((ms % 60000) / 1000);
        return `${m}:${s.toString().padStart(2, '0')}`;
    };

    if (!showWarning || !isAuthenticated) return null;

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
                        onClick={() => setShowWarning(false)}
                        aria-label="Close"
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-primary)'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)'}
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
                                {formatTime(timeLeft)}
                            </div>
                            <div className="flex space-x-3">
                                <button
                                    type="button"
                                    onClick={handleExtendSession}
                                    disabled={isExtending}
                                    className="flex-1 px-4 py-2 text-sm font-medium rounded-md focus:outline-hidden focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
                                    style={isExtending
                                        ? { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)', cursor: 'not-allowed' }
                                        : { backgroundColor: 'var(--accent)', color: '#ffffff' }
                                    }
                                    onMouseEnter={e => { if (!isExtending) (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--accent-hover)'; }}
                                    onMouseLeave={e => { if (!isExtending) (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--accent)'; }}
                                >
                                    {isExtending ? (
                                        <div className="flex items-center justify-center">
                                            <svg className="animate-spin -ml-1 mr-2 h-4 w-4" style={{ color: 'var(--text-muted)' }} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                            </svg>
                                            Loading...
                                        </div>
                                    ) : 'Extend Session'}
                                </button>
                                <button
                                    type="button"
                                    onClick={handleLogout}
                                    className="flex-1 px-4 py-2 text-sm font-medium rounded-md border focus:outline-hidden focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
                                    style={{ backgroundColor: 'var(--bg-surface)', color: 'var(--text-secondary)', borderColor: 'var(--border-strong)' }}
                                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)'}
                                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-surface)'}
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
