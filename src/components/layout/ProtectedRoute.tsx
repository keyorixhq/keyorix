import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { ROUTES } from '../../constants';
import { storeIntendedRoute } from '../../utils/routing';

interface ProtectedRouteProps {
    children: React.ReactNode;
    requiredPermissions?: string[];
    requiredRole?: string;
    fallbackPath?: string;
    redirectOnFailure?: boolean;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
    children,
    requiredPermissions = [],
    requiredRole,
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

        return (
            <Navigate
                to={fallbackPath}
                state={{ from: location }}
                replace
            />
        );
    }

    // Check role requirement
    if (requiredRole && user?.role !== requiredRole) {
        if (redirectOnFailure) {
            return (
                <Navigate
                    to={ROUTES.DASHBOARD}
                    replace
                />
            );
        } else {
            return (
                <div className="min-h-screen flex items-center justify-center bg-gray-50">
                    <div className="text-center">
                        <h1 className="text-2xl font-bold text-gray-900 mb-4">Access Denied</h1>
                        <p className="text-gray-600 mb-4">You don't have permission to access this page.</p>
                        <p className="text-sm text-gray-500">Required role: {requiredRole}</p>
                    </div>
                </div>
            );
        }
    }

    // Check permission requirements
    if (requiredPermissions.length > 0) {
        const hasAllPermissions = requiredPermissions.every(permission =>
            hasPermission(permission)
        );

        if (!hasAllPermissions) {
            if (redirectOnFailure) {
                return (
                    <Navigate
                        to={ROUTES.DASHBOARD}
                        replace
                    />
                );
            } else {
                const missingPermissions = requiredPermissions.filter(permission =>
                    !hasPermission(permission)
                );

                return (
                    <div className="min-h-screen flex items-center justify-center bg-gray-50">
                        <div className="text-center">
                            <h1 className="text-2xl font-bold text-gray-900 mb-4">Access Denied</h1>
                            <p className="text-gray-600 mb-4">You don't have permission to access this page.</p>
                            <p className="text-sm text-gray-500">Missing permissions: {missingPermissions.join(', ')}</p>
                        </div>
                    </div>
                );
            }
        }
    }

    return <>{children}</>;
};