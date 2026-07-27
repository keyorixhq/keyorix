import React, { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';

// react-router's navigate() can't currently be turned into an open redirect to
// another origin (browsers reject a cross-origin pushState), but `return_to`
// still comes from the SSO redirect chain, so require it to look like an
// in-app relative path as defense-in-depth: a single leading '/' (not '//' or
// '/\', both of which some browsers treat as protocol-relative).
function isSafeReturnTo(path: string): boolean {
    return /^\/(?![/\\])/.test(path);
}

// SSOCompletePage is the landing page the OIDC callback redirects the browser to.
// The backend sets the session cookie directly on its own redirect response (see
// sso.go/saml.go) — the fragment only carries non-secret bookkeeping
// (expires_at, return_to, error), never the session credential itself. We load
// the profile (which relies on the cookie the redirect already set), scrub the
// fragment, and navigate into the app — or back to /login with an error.
export const SSOCompletePage: React.FC = () => {
    const navigate = useNavigate();
    const completeSSOLogin = useAuthStore((s) => s.completeSSOLogin);
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
        const requestedReturnTo = params.get('return_to');
        const returnTo = requestedReturnTo && isSafeReturnTo(requestedReturnTo) ? requestedReturnTo : '/';

        (async () => {
            try {
                await completeSSOLogin(
                    params.get('expires_at') || undefined,
                    params.get('absolute_expires_at') || undefined
                );
                // Scrub the fragment from the address bar before navigating onward.
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
