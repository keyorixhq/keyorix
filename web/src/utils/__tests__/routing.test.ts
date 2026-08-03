import { describe, it, expect, beforeEach, vi } from 'vitest';

// Back the storage layer with a simple in-memory map so we test routing logic
// in isolation (not localStorage/JSON serialization) — same pattern as
// src/utils/__tests__/auth.test.ts.
const { memStore } = vi.hoisted(() => {
    const map = new Map<string, unknown>();
    return {
        memStore: {
            map,
            get: <T>(key: string, def?: T): T | null => (map.has(key) ? (map.get(key) as T) : (def ?? null)),
            set: (key: string, value: unknown): void => {
                map.set(key, value);
            },
            remove: (key: string): void => {
                map.delete(key);
            },
        },
    };
});

vi.mock('../index', () => ({ storage: memStore }));

import {
    storeIntendedRoute,
    getAndClearIntendedRoute,
    clearIntendedRoute,
    getPostLoginRedirect,
    isProtectedRoute,
    isAdminRoute,
    getFallbackRoute,
    canAccessRoute,
    createAuthAwareNavigate,
} from '../routing';
import { ROUTES } from '../../constants';

beforeEach(() => {
    memStore.map.clear();
});

describe('storeIntendedRoute', () => {
    it('does not store the login route', () => {
        storeIntendedRoute(ROUTES.LOGIN);
        expect(getAndClearIntendedRoute()).toBeNull();
    });

    it('does not store any /auth-prefixed route', () => {
        storeIntendedRoute('/auth/callback');
        expect(getAndClearIntendedRoute()).toBeNull();
    });

    it('stores an ordinary path', () => {
        storeIntendedRoute('/projects/42/secrets');
        expect(getAndClearIntendedRoute()).toBe('/projects/42/secrets');
    });
});

describe('getAndClearIntendedRoute', () => {
    it('returns null when nothing is stored', () => {
        expect(getAndClearIntendedRoute()).toBeNull();
    });

    it('returns the stored route and clears it (one-shot read)', () => {
        storeIntendedRoute('/dashboard/widgets');
        expect(getAndClearIntendedRoute()).toBe('/dashboard/widgets');
        // second read finds nothing left
        expect(getAndClearIntendedRoute()).toBeNull();
    });

    it('treats an empty-string route as absent and leaves it un-cleared', () => {
        // storeIntendedRoute('') passes both guard checks ('' !== LOGIN and
        // ''.startsWith('/auth') is false) so it IS written to storage — but
        // getAndClearIntendedRoute's `if (intendedRoute)` check is falsy for
        // '', so it reports null on every read without ever removing the
        // value. Documenting this real (if minor) quirk rather than fixing it
        // per the coverage-only scope of this PR.
        storeIntendedRoute('');
        expect(getAndClearIntendedRoute()).toBeNull();
        expect(getAndClearIntendedRoute()).toBeNull();
    });
});

describe('clearIntendedRoute', () => {
    it('removes a stored route without returning it', () => {
        storeIntendedRoute('/audit');
        clearIntendedRoute();
        expect(getAndClearIntendedRoute()).toBeNull();
    });

    it('is a no-op when nothing is stored', () => {
        expect(() => clearIntendedRoute()).not.toThrow();
    });
});

describe('getPostLoginRedirect', () => {
    it('falls back to ROUTES.DASHBOARD by default when nothing is stored', () => {
        expect(getPostLoginRedirect()).toBe(ROUTES.DASHBOARD);
    });

    it('falls back to a supplied default when nothing is stored', () => {
        expect(getPostLoginRedirect('/custom-landing')).toBe('/custom-landing');
    });

    it('prefers the intended route over the default, and clears it after use', () => {
        storeIntendedRoute('/secrets/7');
        expect(getPostLoginRedirect('/custom-landing')).toBe('/secrets/7');
        // consumed: a second call falls through to the default again
        expect(getPostLoginRedirect('/custom-landing')).toBe('/custom-landing');
    });
});

describe('isProtectedRoute', () => {
    it('treats the known public routes as not protected', () => {
        expect(isProtectedRoute(ROUTES.LOGIN)).toBe(false);
        expect(isProtectedRoute('/auth')).toBe(false);
        expect(isProtectedRoute('/auth/callback')).toBe(false);
        expect(isProtectedRoute('/forgot-password')).toBe(false);
        expect(isProtectedRoute('/reset-password')).toBe(false);
        expect(isProtectedRoute('/reset-password/some-token')).toBe(false);
    });

    it('treats other routes as protected', () => {
        expect(isProtectedRoute(ROUTES.DASHBOARD)).toBe(true);
        expect(isProtectedRoute('/')).toBe(true);
        expect(isProtectedRoute(ROUTES.PROJECTS)).toBe(true);
    });

    it('requires a path-segment boundary, not just a shared prefix', () => {
        // A sibling path that merely begins with a public-route string (but
        // isn't that route or a sub-route of it) must NOT be misclassified as
        // public.
        expect(isProtectedRoute('/login-help')).toBe(true);
    });
});

describe('isAdminRoute', () => {
    it('is true for the admin route and its sub-routes', () => {
        expect(isAdminRoute(ROUTES.ADMIN)).toBe(true);
        expect(isAdminRoute('/admin/users')).toBe(true);
    });

    it('is false for non-admin routes', () => {
        expect(isAdminRoute(ROUTES.DASHBOARD)).toBe(false);
        expect(isAdminRoute('/')).toBe(false);
    });

    it('requires a path-segment boundary, not just a shared prefix', () => {
        // A sibling path that merely begins with the admin-route string (but
        // isn't that route or a sub-route of it) must NOT be misclassified as
        // an admin route.
        expect(isAdminRoute('/administration-guide')).toBe(false);
    });
});

describe('getFallbackRoute', () => {
    it('returns ROUTES.ADMIN for the literal "admin" role', () => {
        expect(getFallbackRoute('admin')).toBe(ROUTES.ADMIN);
    });

    it('returns ROUTES.DASHBOARD when no role is supplied', () => {
        expect(getFallbackRoute()).toBe(ROUTES.DASHBOARD);
    });

    it('returns ROUTES.DASHBOARD for a non-admin role', () => {
        expect(getFallbackRoute('viewer')).toBe(ROUTES.DASHBOARD);
    });

    it('returns ROUTES.ADMIN for every role in ADMIN_ROLES, not just the literal "admin"', () => {
        // ADMIN_ROLES (src/features/auth/roles.ts) is ['admin', 'system_admin',
        // 'super_admin'], and canAccessRoute's access check uses that whole
        // list, so getFallbackRoute must be consistent with it.
        expect(getFallbackRoute('system_admin')).toBe(ROUTES.ADMIN);
        expect(getFallbackRoute('super_admin')).toBe(ROUTES.ADMIN);
    });
});

describe('canAccessRoute', () => {
    it('always allows public routes, regardless of auth state', () => {
        expect(canAccessRoute(ROUTES.LOGIN, false)).toEqual({ canAccess: true });
        expect(canAccessRoute(ROUTES.LOGIN, true, 'admin')).toEqual({ canAccess: true });
    });

    it('denies protected routes to unauthenticated users, redirecting to LOGIN', () => {
        expect(canAccessRoute(ROUTES.DASHBOARD, false)).toEqual({
            canAccess: false,
            redirectTo: ROUTES.LOGIN,
        });
    });

    it('denies admin routes to authenticated non-admin users, redirecting to their fallback', () => {
        expect(canAccessRoute(ROUTES.ADMIN, true, 'viewer')).toEqual({
            canAccess: false,
            redirectTo: ROUTES.DASHBOARD,
        });
    });

    it('denies admin routes to authenticated users with no role set', () => {
        expect(canAccessRoute(ROUTES.ADMIN, true)).toEqual({
            canAccess: false,
            redirectTo: ROUTES.DASHBOARD,
        });
    });

    it('allows admin routes for every role in ADMIN_ROLES', () => {
        expect(canAccessRoute(ROUTES.ADMIN, true, 'admin')).toEqual({ canAccess: true });
        expect(canAccessRoute(ROUTES.ADMIN, true, 'system_admin')).toEqual({ canAccess: true });
        expect(canAccessRoute(ROUTES.ADMIN, true, 'super_admin')).toEqual({ canAccess: true });
    });

    it('allows authenticated users onto non-admin protected routes regardless of role', () => {
        expect(canAccessRoute(ROUTES.DASHBOARD, true, 'viewer')).toEqual({ canAccess: true });
        expect(canAccessRoute(ROUTES.DASHBOARD, true)).toEqual({ canAccess: true });
    });
});

describe('createAuthAwareNavigate', () => {
    it('navigates directly when the route is accessible', () => {
        const navigate = vi.fn();
        const guardedNavigate = createAuthAwareNavigate(navigate, true, 'viewer');

        guardedNavigate(ROUTES.DASHBOARD);

        expect(navigate).toHaveBeenCalledWith(ROUTES.DASHBOARD);
        expect(navigate).toHaveBeenCalledTimes(1);
    });

    it('stores the intended route and redirects to LOGIN when unauthenticated', () => {
        const navigate = vi.fn();
        const guardedNavigate = createAuthAwareNavigate(navigate, false);

        guardedNavigate('/secrets/9');

        expect(navigate).toHaveBeenCalledWith(ROUTES.LOGIN);
        // the attempted path was preserved for post-login redirect
        expect(getAndClearIntendedRoute()).toBe('/secrets/9');
    });

    it('redirects to the role fallback (without storing an intended route) when denied for role reasons', () => {
        const navigate = vi.fn();
        const guardedNavigate = createAuthAwareNavigate(navigate, true, 'viewer');

        guardedNavigate(ROUTES.ADMIN);

        expect(navigate).toHaveBeenCalledWith(ROUTES.DASHBOARD);
        expect(navigate).toHaveBeenCalledTimes(1);
        // no intended-route bookkeeping for non-LOGIN redirects
        expect(getAndClearIntendedRoute()).toBeNull();
    });

    it('defaults permissions to an empty array when omitted', () => {
        const navigate = vi.fn();
        const guardedNavigate = createAuthAwareNavigate(navigate, true, 'admin');

        guardedNavigate(ROUTES.ADMIN);

        expect(navigate).toHaveBeenCalledWith(ROUTES.ADMIN);
    });

    // Coverage note: createAuthAwareNavigate's `else if (redirectTo)` guard has a
    // false-side (canAccess is false but redirectTo is falsy) that is NOT
    // reachable through the public API. canAccessRoute's every `canAccess: false`
    // return (unauthenticated -> LOGIN, wrong role on an admin route -> fallback)
    // always sets redirectTo alongside it; there's no code path back to
    // `{ canAccess: false }` alone. The test below pins that invariant down, so
    // if canAccessRoute is ever changed to violate it, this test — not a
    // silently-never-taken branch in createAuthAwareNavigate — is what catches
    // it. Deliberately left uncovered rather than faked: the only way to
    // actually execute the false side would be to mock canAccessRoute itself,
    // which is called as a same-module, non-injected reference from
    // createAuthAwareNavigate and so cannot be substituted from outside without
    // changing production code.
    it('invariant: whenever canAccessRoute denies access, it always supplies a redirectTo', () => {
        const denials = [
            canAccessRoute(ROUTES.DASHBOARD, false),
            canAccessRoute(ROUTES.ADMIN, true, 'viewer'),
            canAccessRoute(ROUTES.ADMIN, true),
            canAccessRoute('/projects/1', false),
        ];

        for (const denial of denials) {
            expect(denial.canAccess).toBe(false);
            expect(denial.redirectTo).toBeTruthy();
        }
    });
});
