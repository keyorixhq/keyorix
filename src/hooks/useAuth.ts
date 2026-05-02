import { useEffect } from 'react';
import { useAuthStore } from '../store/authStore';
import { getEnvConfig } from '../utils';

const config = getEnvConfig();

export const useAuth = () => {
    const {
        user,
        token,
        isAuthenticated,
        isLoading,
        error,
        login,
        logout,
        refreshToken,
        checkAuth,
        clearError,
        setError,
    } = useAuthStore();

    // Run auth check once on mount only - wait for persist hydration first
    useEffect(() => {
        const init = async () => {
            // Wait for Zustand persist to hydrate from localStorage
            await useAuthStore.persist.rehydrate();
            const state = useAuthStore.getState();
            if (!state.isAuthenticated) {
                await checkAuth();
            }
        };
        init();
    }, []); // Empty dependency array - run once only

    // Session timeout handling
    useEffect(() => {
        let timeoutId: ReturnType<typeof setTimeout>;

        if (isAuthenticated) {
            const handleSessionTimeout = () => {
                logout();
                setError('Your session has expired due to inactivity. Please log in again.');
            };

            const resetTimeout = () => {
                if (timeoutId) clearTimeout(timeoutId);
                timeoutId = setTimeout(handleSessionTimeout, config.SESSION_TIMEOUT);
            };

            // Reset timeout on user activity
            const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
            const resetTimeoutHandler = () => resetTimeout();

            events.forEach(event => {
                document.addEventListener(event, resetTimeoutHandler, true);
            });

            // Initial timeout setup
            resetTimeout();

            return () => {
                if (timeoutId) clearTimeout(timeoutId);
                events.forEach(event => {
                    document.removeEventListener(event, resetTimeoutHandler, true);
                });
            };
        }

        return () => { }; // Return empty cleanup function if not authenticated
    }, [isAuthenticated, logout, setError]);

    return {
        // State
        user,
        token,
        isAuthenticated,
        isLoading,
        error,

        // Actions
        login,
        logout,
        refreshToken,
        checkAuth,
        clearError,

        // Computed values
        isAdmin: user?.role === 'admin',
        permissions: user?.permissions || [],
        hasPermission: (permission: string) => user?.permissions?.includes(permission) || false,
    };
};