import React, { useState, useEffect } from 'react';
import { ExclamationTriangleIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useAuth } from '../../hooks/useAuth';
import { cn } from '../../utils';

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
                        if (prev <= 1000) { handleLogout(); return 0; }
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
                <div className="relative bg-white rounded-lg shadow-xl max-w-md w-full">
                    <button
                        type="button"
                        className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
                        onClick={() => setShowWarning(false)}
                        aria-label="Close"
                    >
                        <XMarkIcon className="h-6 w-6" />
                    </button>
                    <div className="p-6">
                        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-yellow-100 mb-4">
                            <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600" />
                        </div>
                        <div className="text-center">
                            <h3 className="text-lg font-medium text-gray-900 mb-2">Session Expiring</h3>
                            <p className="text-sm text-gray-600 mb-4">
                                Your session will expire soon due to inactivity. Would you like to extend your session?
                            </p>
                            <div className="text-2xl font-bold text-red-600 mb-6">{formatTime(timeLeft)}</div>
                            <div className="flex space-x-3">
                                <button
                                    type="button"
                                    onClick={handleExtendSession}
                                    disabled={isExtending}
                                    className={cn(
                                        'flex-1 px-4 py-2 text-sm font-medium rounded-md',
                                        'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500',
                                        isExtending
                                            ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                                            : 'bg-blue-600 text-white hover:bg-blue-700'
                                    )}
                                >
                                    {isExtending ? (
                                        <div className="flex items-center justify-center">
                                            <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
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
                                    className="flex-1 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
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
