import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../features/auth';
import { ROUTES } from '../../constants';
import { getPostLoginRedirect } from '../../utils/routing';

interface PublicRouteProps {
    children: React.ReactNode;
    redirectTo?: string;
}

export const PublicRoute: React.FC<PublicRouteProps> = ({ children, redirectTo = ROUTES.DASHBOARD }) => {
    const { isAuthenticated, hasCheckedAuth } = useAuth();
    // const location = useLocation(); // Not needed for current implementation

    // Show loading only for the initial auth check — not every subsequent
    // login/logout isLoading flip, which would otherwise unmount this route's
    // children (e.g. LoginPage) mid-request on every login attempt.
    if (!hasCheckedAuth) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                    <p className="text-gray-600">Loading...</p>
                </div>
            </div>
        );
    }

    // Redirect to dashboard if already authenticated
    if (isAuthenticated) {
        // Check if there's an intended route to redirect to
        const redirectPath = getPostLoginRedirect(redirectTo);
        return <Navigate to={redirectPath} replace />;
    }

    return <>{children}</>;
};
