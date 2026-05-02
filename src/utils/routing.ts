import { storage } from './index';
import { ROUTES } from '../constants';

const INTENDED_ROUTE_KEY = 'intendedRoute';

/**
 * Stores the intended route for redirect after authentication
 */
export const storeIntendedRoute = (path: string): void => {
    // Don't store login or other auth-related routes
    if (path === ROUTES.LOGIN || path.startsWith('/auth')) {
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
    return intendedRoute || defaultPath;
};

/**
 * Checks if a route requires authentication
 */
export const isProtectedRoute = (path: string): boolean => {
    const publicRoutes = [
        ROUTES.LOGIN,
        '/auth',
        '/forgot-password',
        '/reset-password',
    ];

    return !publicRoutes.some(route => path.startsWith(route));
};

/**
 * Checks if a route is admin-only
 */
export const isAdminRoute = (path: string): boolean => {
    return path.startsWith(ROUTES.ADMIN);
};

/**
 * Gets the appropriate fallback route based on user role
 */
export const getFallbackRoute = (userRole?: string): string => {
    if (userRole === 'admin') {
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

    // Admin routes require admin role
    if (isAdminRoute(path) && userRole !== 'admin') {
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