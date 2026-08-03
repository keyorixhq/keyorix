import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../features/auth';
import { ROUTES } from '../../constants';

interface RequirePasswordChangeProps {
    children: React.ReactNode;
}

/**
 * RequirePasswordChange confines an account that must change its password
 * (ADR-025: pending_first_login / password_reset_required, or an expired
 * password) to the profile page, where the Security tab lets them change it.
 * The backend enforces the same restriction (403 PasswordChangeRequired) — this
 * is the UX half that routes the user to the right place instead of bouncing
 * off every API call.
 */
export const RequirePasswordChange: React.FC<RequirePasswordChangeProps> = ({ children }) => {
    const { user } = useAuth();
    const location = useLocation();

    if (user?.passwordChangeRequired && !location.pathname.startsWith(ROUTES.PROFILE)) {
        return <Navigate to={ROUTES.PROFILE} replace />;
    }

    return <>{children}</>;
};
