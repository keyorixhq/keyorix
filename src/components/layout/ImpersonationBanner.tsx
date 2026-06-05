import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import { ROUTES } from '../../constants';

/**
 * ImpersonationBanner is a fixed warning bar shown while an admin is
 * impersonating another user. "End Impersonation" restores the admin's own
 * session (no re-authentication) and returns to the dashboard.
 */
export const ImpersonationBanner: React.FC = () => {
    const isImpersonating = useAuthStore((s) => s.isImpersonating);
    const user = useAuthStore((s) => s.user);
    const adminUser = useAuthStore((s) => s.adminUser);
    const endImpersonation = useAuthStore((s) => s.endImpersonation);
    const navigate = useNavigate();
    const [ending, setEnding] = useState(false);

    if (!isImpersonating) {
        return null;
    }

    const target = user?.displayName || user?.username || 'another user';
    const admin = adminUser?.displayName || adminUser?.username;

    const handleEnd = async () => {
        setEnding(true);
        try {
            await endImpersonation();
            navigate(ROUTES.DASHBOARD, { replace: true });
        } finally {
            setEnding(false);
        }
    };

    return (
        <div
            role="alert"
            className="flex items-center justify-center gap-4 px-4 py-2 text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--warning, #b45309)' }}
        >
            <span>
                Impersonating <strong>{target}</strong>
                {admin ? <> — signed in as {admin}</> : null}
            </span>
            <button
                onClick={handleEnd}
                disabled={ending}
                className="rounded-sm bg-white/20 px-3 py-1 font-semibold hover:bg-white/30 disabled:opacity-60"
            >
                {ending ? 'Ending…' : 'End Impersonation'}
            </button>
        </div>
    );
};
