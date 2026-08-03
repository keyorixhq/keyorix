import { useEffect, useState } from 'react';
import { useAuthStore } from '../../store/authStore';
import { getEnvConfig } from '../../utils';
import { userIsAdmin } from './roles';

const config = getEnvConfig();

// How long before the inactivity timeout to start warning the user
// (SessionTimeoutWarning shows once this many ms remain). Kept here so there is
// a single source of truth for "when does the countdown start" — previously
// SessionTimeoutWarning ran its own independent 5-minute timer with no relation
// to this hook's actual SESSION_TIMEOUT, so the two could disagree.
const SESSION_TIMEOUT_WARNING_MS = 5 * 60 * 1000;

// Module-level flag: the initial checkAuth/rehydrate must run exactly once per
// page load, not once per component that calls useAuth(). Without this, every
// component whose parent shows a loading spinner (PublicRoute, ProtectedRoute)
// unmounts its children when isLoading=true and remounts them when it goes
// false — each remount re-fires the effect and triggers another checkAuth,
// creating an infinite loop. Module scope resets on full navigation (logout
// does window.location.href) so re-login always gets a fresh init.
let didInit = false;

export const useAuth = () => {
    const {
        user,
        isAuthenticated,
        isLoading,
        hasCheckedAuth,
        error,
        login,
        logout,
        refreshToken,
        checkAuth,
        clearError,
        setError,
    } = useAuthStore();

    // Run auth check once on mount only - wait for persist hydration first.
    // Always revalidate against the server here, even if hydration already set
    // isAuthenticated from a persisted session — that flag is stale, client-editable
    // state, not proof the session is still valid server-side (a revoked session,
    // disabled account, or role change wouldn't otherwise be caught until some other
    // request happens to 401). checkAuth() always attempts the profile fetch (there's
    // no client-visible token to check first under cookie auth) and cleanly clears
    // state if there's no valid session cookie, so this is safe to call unconditionally.
    useEffect(() => {
        if (didInit) return;
        didInit = true;
        const init = async () => {
            await useAuthStore.persist.rehydrate();
            await checkAuth();
        };
        init();
        // mount-only bootstrap; checkAuth is a stable zustand action and this effect is intentionally not reactive.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Session timeout handling. Tracks a single deadline (now + SESSION_TIMEOUT,
    // reset on activity) and exposes the remaining time once it enters the
    // warning window, so SessionTimeoutWarning can render off this instead of
    // running its own separate timer. Avoids a per-second re-render for the
    // entire authenticated session by only switching to 1s ticks once inside
    // the warning window; outside it, a single setTimeout fires exactly when
    // the warning window is entered (or session-timeout time changes).
    const [sessionTimeLeftMs, setSessionTimeLeftMs] = useState<number | null>(null);

    useEffect(() => {
        if (!isAuthenticated) {
            setSessionTimeLeftMs(null);
            return;
        }

        let deadline = Date.now() + config.SESSION_TIMEOUT;
        let handle: ReturnType<typeof setTimeout>;

        const schedule = () => {
            const remaining = deadline - Date.now();
            if (remaining <= 0) {
                setSessionTimeLeftMs(null);
                logout();
                setError('Your session has expired due to inactivity. Please log in again.');
                return;
            }
            if (remaining > SESSION_TIMEOUT_WARNING_MS) {
                setSessionTimeLeftMs(null);
                handle = setTimeout(schedule, remaining - SESSION_TIMEOUT_WARNING_MS);
            } else {
                setSessionTimeLeftMs(remaining);
                handle = setTimeout(schedule, 1000);
            }
        };

        const resetDeadline = () => {
            clearTimeout(handle);
            deadline = Date.now() + config.SESSION_TIMEOUT;
            schedule();
        };

        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
        events.forEach((event) => document.addEventListener(event, resetDeadline, true));
        schedule();

        return () => {
            clearTimeout(handle);
            events.forEach((event) => document.removeEventListener(event, resetDeadline, true));
        };
    }, [isAuthenticated, logout, setError]);

    return {
        // State
        user,
        isAuthenticated,
        isLoading,
        hasCheckedAuth,
        error,
        // Non-null only once inside the SESSION_TIMEOUT_WARNING_MS window before
        // an inactivity-triggered logout; null the rest of the session.
        sessionTimeLeftMs,

        // Actions
        login,
        logout,
        refreshToken,
        checkAuth,
        clearError,

        // Computed values
        isAdmin: userIsAdmin(user),
        roles: user?.roles || [],
        permissions: user?.permissions || [],
        hasPermission: (permission: string) => user?.permissions?.includes(permission) || false,
    };
};
