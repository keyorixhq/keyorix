import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../features/auth';
import { userIsAdmin } from '../../features/auth/roles';
import { ROUTES } from '../../constants';
import { storeIntendedRoute } from '../../utils/routing';

interface ProtectedRouteProps {
    children: React.ReactNode;
    requiredPermissions?: string[];
    requiredRole?: string;
    adminOnly?: boolean;
    fallbackPath?: string;
    redirectOnFailure?: boolean;
}

const AccessDenied: React.FC<{ detail: React.ReactNode }> = ({ detail }) => (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
            <h1 className="text-2xl font-bold text-gray-900 mb-4">Access Denied</h1>
            <p className="text-gray-600 mb-4">You don't have permission to access this page.</p>
            <p className="text-sm text-gray-500">{detail}</p>
        </div>
    </div>
);

const denyOrRedirect = (redirectOnFailure: boolean, detail: React.ReactNode): React.ReactElement => {
    if (redirectOnFailure) {
        return <Navigate to={ROUTES.DASHBOARD} replace />;
    }
    return <AccessDenied detail={detail} />;
};

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
    children,
    requiredPermissions = [],
    requiredRole,
    adminOnly = false,
    fallbackPath = ROUTES.LOGIN,
    redirectOnFailure = true,
}) => {
    const { isAuthenticated, isLoading, user, hasPermission } = useAuth();
    const location = useLocation();

    // Show loading while checking authentication
    if (isLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                    <p className="text-gray-600">Loading...</p>
                </div>
            </div>
        );
    }

    // Redirect to login if not authenticated
    if (!isAuthenticated) {
        // Store the intended route for redirect after login
        storeIntendedRoute(location.pathname + location.search);

        return <Navigate to={fallbackPath} state={{ from: location }} replace />;
    }

    // Admin-only gate: any install-admin role (admin / system_admin / super_admin).
    if (adminOnly && !userIsAdmin(user)) {
        return denyOrRedirect(redirectOnFailure, 'Administrator access required.');
    }

    // Check role requirement
    if (requiredRole && user?.role !== requiredRole) {
        return denyOrRedirect(redirectOnFailure, `Required role: ${requiredRole}`);
    }

    // Check permission requirements
    if (requiredPermissions.length > 0) {
        const missingPermissions = requiredPermissions.filter((permission) => !hasPermission(permission));

        if (missingPermissions.length > 0) {
            return denyOrRedirect(redirectOnFailure, `Missing permissions: ${missingPermissions.join(', ')}`);
        }
    }

    return <>{children}</>;
};
