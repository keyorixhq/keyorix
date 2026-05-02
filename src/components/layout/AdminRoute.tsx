import React from 'react';
import { ProtectedRoute } from './ProtectedRoute';

interface AdminRouteProps {
    children: React.ReactNode;
    requiredPermissions?: string[];
}

export const AdminRoute: React.FC<AdminRouteProps> = ({
    children,
    requiredPermissions = [],
}) => {
    return (
        <ProtectedRoute
            requiredRole="admin"
            requiredPermissions={requiredPermissions}
        >
            {children}
        </ProtectedRoute>
    );
};