// INV-WEB-03 (#2529): the session credential rides an httpOnly cookie — web/src must never
// write its value to localStorage or sessionStorage, where any XSS could read it.
//
// This is NOT vacuous by construction: the real backend DOES hand the credential to the
// browser in the JSON body — POST /auth/login and POST /auth/refresh both return
// `"token": session.SessionToken` (server/http/handlers/auth.go; the CLI is a bearer
// client and reads it). The web app's safety rests entirely on every code path that sees
// that body choosing not to persist it. A future `...response` spread into the user
// object (which zustand `persist` writes to `auth-storage`) would leak it silently.
//
// So the fixture mirrors that real response shape and the flow runs through the REAL
// authStore → authService → authApi axios instance; only the XMLHttpRequest transport is
// faked. Every storage write is recorded — including ones later removed — and each value
// is scanned for (a) the exact session token, and (b) anything JWT-shaped.
//
// Not covered: IndexedDB, Cache Storage, and document.cookie (the browser makes the
// httpOnly cookie unreadable to JS, so there is nothing for this layer to leak there).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '../authStore';
import type { LoginResponse } from '../../types';

// A realistic JWT-shaped value (header.payload.signature, base64url). Used as BOTH the
// body `token` and the Set-Cookie value, so a leak of either source is caught.
const SESSION_TOKEN =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiJzZXNzLTQyIiwidWlkIjo3fQ.c2lnbmF0dXJlLW9mLXRoZS1zZXNzaW9u';
const REFRESHED_TOKEN =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiJzZXNzLTQzIiwidWlkIjo3fQ.cm90YXRlZC1zZXNzaW9uLXNpZ25hdHVyZQ';
const JWT_SHAPE = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/;

const future = (mins: number) => new Date(Date.now() + mins * 60_000).toISOString();

const loginBody = () => ({
    success: true,
    data: {
        token: SESSION_TOKEN,
        expires_at: future(60),
        absolute_expires_at: future(600),
        user_id: 7,
        username: 'alice',
        email: 'alice@example.com',
        display_name: 'Alice',
        role: 'admin',
        roles: ['admin'],
        permissions: ['secrets.read'],
    },
});

function routeResponse(method: string, url: string): { status: number; body: unknown; token: string } {
    const path = new URL(url, 'http://localhost').pathname;
    if (method === 'POST' && path === '/auth/login') return { status: 200, body: loginBody(), token: SESSION_TOKEN };
    if (method === 'POST' && path === '/auth/refresh') {
        return {
            status: 200,
            body: { success: true, data: { token: REFRESHED_TOKEN, expires_at: future(60) } },
            token: REFRESHED_TOKEN,
        };
    }
    if (method === 'GET' && path === '/api/v1/auth/profile') {
        return {
            status: 200,
            body: {
                success: true,
                data: { id: 7, username: 'alice', email: 'alice@example.com', role: 'admin', token: SESSION_TOKEN },
            },
            token: SESSION_TOKEN,
        };
    }
    return { status: 404, body: { error: 'not found' }, token: '' };
}

// Minimal XMLHttpRequest stand-in covering exactly the members axios's xhr adapter uses.
class FakeXHR {
    readyState = 0;
    status = 0;
    statusText = '';
    responseText = '';
    response: unknown = '';
    responseType = '';
    responseURL = '';
    timeout = 0;
    withCredentials = false;
    upload = { addEventListener: () => undefined };
    onloadend: (() => void) | null = null;
    onreadystatechange: (() => void) | null = null;
    onabort: (() => void) | null = null;
    onerror: (() => void) | null = null;
    ontimeout: (() => void) | null = null;
    private method = 'GET';
    private url = '';
    private headers = '';
    open(method: string, url: string) {
        this.method = method.toUpperCase();
        this.url = url;
        this.readyState = 1;
    }
    setRequestHeader() {
        return undefined;
    }
    addEventListener() {
        return undefined;
    }
    getAllResponseHeaders() {
        return this.headers;
    }
    abort() {
        return undefined;
    }
    send() {
        const { status, body, token } = routeResponse(this.method, this.url);
        setTimeout(() => {
            this.status = status;
            this.statusText = status === 200 ? 'OK' : 'Not Found';
            this.responseText = JSON.stringify(body);
            this.response = this.responseText;
            this.responseURL = this.url;
            this.headers =
                'content-type: application/json\r\n' +
                (token ? `set-cookie: keyorix_session=${token}; HttpOnly; Secure; SameSite=Strict\r\n` : '');
            this.readyState = 4;
            this.onreadystatechange?.();
            this.onloadend?.();
        }, 0);
    }
}

type Write = { area: 'localStorage' | 'sessionStorage'; key: string; value: string };

function installRecordingStorage(area: 'localStorage' | 'sessionStorage', writes: Write[]) {
    // src/test/setup.ts installs both storages as non-configurable objects of vi.fn()s,
    // so back those fns with a real Map rather than replacing the object.
    const backing = new Map<string, string>();
    const s = window[area] as unknown as Record<string, ReturnType<typeof vi.fn>>;
    s.getItem!.mockImplementation((k: string) => (backing.has(k) ? backing.get(k)! : null));
    s.setItem!.mockImplementation((k: string, v: string) => {
        writes.push({ area, key: String(k), value: String(v) });
        backing.set(String(k), String(v));
    });
    s.removeItem!.mockImplementation((k: string) => backing.delete(k));
    s.clear!.mockImplementation(() => backing.clear());
}

function leaks(writes: Write[]): Write[] {
    return writes.filter(
        (w) =>
            w.key.includes(SESSION_TOKEN) ||
            w.value.includes(SESSION_TOKEN) ||
            w.value.includes(REFRESHED_TOKEN) ||
            JWT_SHAPE.test(w.key) ||
            JWT_SHAPE.test(w.value)
    );
}

describe('INV-WEB-03: the session token never reaches localStorage/sessionStorage', () => {
    let writes: Write[];

    beforeEach(() => {
        writes = [];
        installRecordingStorage('localStorage', writes);
        installRecordingStorage('sessionStorage', writes);
        vi.stubGlobal('XMLHttpRequest', FakeXHR);
        useAuthStore.setState({ user: null, isAuthenticated: false, isLoading: false, error: null });
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('fixture self-check: the scanner flags a planted token (guards against a vacuous pass)', () => {
        localStorage.setItem('auth-storage', JSON.stringify({ state: { user: { token: SESSION_TOKEN } } }));
        sessionStorage.setItem('x', `Bearer ${REFRESHED_TOKEN}`);
        expect(leaks(writes)).toHaveLength(2);
    });

    it('login → refresh → checkAuth persists bookkeeping but never the credential', async () => {
        await useAuthStore.getState().login({ username: 'alice', password: 'pw', rememberMe: true });
        expect(useAuthStore.getState().isAuthenticated).toBe(true);

        await useAuthStore.getState().refreshToken();
        await useAuthStore.getState().checkAuth();
        expect(useAuthStore.getState().user?.username).toBe('alice');

        // Non-vacuity: the flow really did persist something (auth-storage + expiry keys),
        // so an empty `writes` can't be mistaken for "nothing leaked".
        const keys = new Set(writes.map((w) => w.key));
        expect(keys).toContain('auth-storage');
        expect(keys).toContain('tokenExpiresAt');

        expect(leaks(writes)).toEqual([]);
    });

    it('completeSetup (ADR-028 login-shaped response) never persists the credential', () => {
        const response = loginBody().data as LoginResponse & { token: string };
        useAuthStore.getState().completeSetup(response);
        expect(useAuthStore.getState().isAuthenticated).toBe(true);
        expect(writes.map((w) => w.key)).toContain('auth-storage');
        expect(leaks(writes)).toEqual([]);
    });
});
