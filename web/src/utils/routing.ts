import { storage } from './index';
import { ROUTES } from '../constants';
import { ADMIN_ROLES } from '../features/auth/roles';

const INTENDED_ROUTE_KEY = 'intendedRoute';

// react-router's navigate() can't currently be turned into an open redirect to
// another origin (browsers reject a cross-origin pushState), but a stored
// intended-route path still ends up passed straight to <Navigate> after
// login, so require it to look like an in-app relative path as
// defense-in-depth: a single leading '/' (not '//' or '/\', both of which
// some browsers treat as protocol-relative). Shared with the SSO `return_to`
// flow (see SSOCompletePage.tsx) so both post-login redirect paths apply the
// same rule instead of maintaining it twice.
export const isSafeReturnTo = (path: string): boolean => /^\/(?![/\\])/.test(path);

/**
 * Stores the intended route for redirect after authentication
 */
export const storeIntendedRoute = (path: string): void => {
    // Don't store login or other auth-related routes
    if (path === ROUTES.LOGIN || path.startsWith('/auth')) {
        return;
    }

    // Don't store a protocol-relative (or otherwise unsafe) path — see
    // isSafeReturnTo. Silently drop it rather than store something a later
    // getPostLoginRedirect() caller could hand to <Navigate>/window.location.
    if (!isSafeReturnTo(path)) {
        return;
    }

    storage.set(INTENDED_ROUTE_KEY, path);
};

/**
 * Gets and clears the intended route
 */
export const getAndClearIntendedRoute = (): string | null => {
    const intendedRoute = storage.get<string>(INTENDED_ROUTE_KEY);

    if (intendedRoute) {
        storage.remove(INTENDED_ROUTE_KEY);
        return intendedRoute;
    }

    return null;
};

/**
 * Clears the intended route without returning it
 */
export const clearIntendedRoute = (): void => {
    storage.remove(INTENDED_ROUTE_KEY);
};

/**
 * Gets the redirect path after successful authentication
 */
export const getPostLoginRedirect = (defaultPath: string = ROUTES.DASHBOARD): string => {
    const intendedRoute = getAndClearIntendedRoute();
    // Re-validate defense-in-depth: storeIntendedRoute already rejects an
    // unsafe path, but this guards any stale/pre-fix value already sitting in
    // storage, or a future write path that bypasses storeIntendedRoute.
    if (intendedRoute && isSafeReturnTo(intendedRoute)) {
        return intendedRoute;
    }
    return defaultPath;
};

/**
 * Checks whether `path` is `route` itself or a sub-route of it (i.e. `route`
 * followed by a `/` segment boundary). Plain `startsWith` would also match
 * unrelated sibling paths that merely share a prefix (e.g. `/login-help`
 * against `/login`), so callers should use this instead.
 */
const matchesRoutePrefix = (path: string, route: string): boolean => path === route || path.startsWith(`${route}/`);

/**
 * Checks if a route requires authentication
 */
export const isProtectedRoute = (path: string): boolean => {
    const publicRoutes = [ROUTES.LOGIN, '/auth', '/forgot-password', '/reset-password'];

    return !publicRoutes.some((route) => matchesRoutePrefix(path, route));
};

/**
 * Checks if a route is admin-only
 */
export const isAdminRoute = (path: string): boolean => {
    return matchesRoutePrefix(path, ROUTES.ADMIN);
};

/**
 * Gets the appropriate fallback route based on user role
 */
export const getFallbackRoute = (userRole?: string): string => {
    if (ADMIN_ROLES.includes(userRole ?? '')) {
        return ROUTES.ADMIN;
    }

    return ROUTES.DASHBOARD;
};

/**
 * Validates if a user can access a specific route
 */
export const canAccessRoute = (
    path: string,
    isAuthenticated: boolean,
    userRole?: string,
    _permissions: string[] = []
): { canAccess: boolean; redirectTo?: string } => {
    // Public routes are always accessible
    if (!isProtectedRoute(path)) {
        return { canAccess: true };
    }

    // Protected routes require authentication
    if (!isAuthenticated) {
        return { canAccess: false, redirectTo: ROUTES.LOGIN };
    }

    // Admin routes require an install-admin role (admin / system_admin / super_admin).
    if (isAdminRoute(path) && !ADMIN_ROLES.includes(userRole ?? '')) {
        return { canAccess: false, redirectTo: getFallbackRoute(userRole) };
    }

    // Add more specific permission checks here as needed
    // For now, authenticated users can access non-admin routes
    return { canAccess: true };
};

/**
 * Navigation helper that respects authentication state
 */
export const createAuthAwareNavigate = (
    navigate: (path: string) => void,
    isAuthenticated: boolean,
    userRole?: string,
    permissions: string[] = []
) => {
    return (path: string) => {
        const { canAccess, redirectTo } = canAccessRoute(path, isAuthenticated, userRole, permissions);

        if (canAccess) {
            navigate(path);
        } else if (redirectTo) {
            if (redirectTo === ROUTES.LOGIN) {
                storeIntendedRoute(path);
            }
            navigate(redirectTo);
        }
    };
};
