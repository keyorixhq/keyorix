import React, { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';

// SSOCompletePage is the landing page the OIDC callback redirects the browser to.
// The backend delivers the session in the URL fragment (#token=…&expires_at=…) — the
// fragment, not the query, so the token never reaches a server log or the Referer
// header. We read it, complete the login (which loads the user via the profile
// endpoint), scrub the fragment, and navigate into the app — or back to /login with
// an error.
export const SSOCompletePage: React.FC = () => {
    const navigate = useNavigate();
    const completeSSOLogin = useAuthStore(s => s.completeSSOLogin);
    const ran = useRef(false);

    useEffect(() => {
        if (ran.current) return; // guard React 18 StrictMode double-invoke
        ran.current = true;

        const params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
        const error = params.get('error');
        if (error) {
            navigate('/login?sso_error=' + encodeURIComponent(error), { replace: true });
            return;
        }
        const token = params.get('token');
        if (!token) {
            navigate('/login?sso_error=' + encodeURIComponent('missing session token'), { replace: true });
            return;
        }
        const returnTo = params.get('return_to') || '/';

        (async () => {
            try {
                await completeSSOLogin(
                    token,
                    params.get('expires_at') || undefined,
                    params.get('absolute_expires_at') || undefined,
                );
                // Scrub the token from the address bar before navigating onward.
                window.history.replaceState(null, '', window.location.pathname);
                navigate(returnTo, { replace: true });
            } catch {
                navigate('/login?sso_error=' + encodeURIComponent('SSO sign-in failed'), { replace: true });
            }
        })();
    }, [completeSSOLogin, navigate]);

    return (
        <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--bg-app)' }}>
            <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
                <p style={{ color: 'var(--text-secondary)' }}>Signing you in…</p>
            </div>
        </div>
    );
};
