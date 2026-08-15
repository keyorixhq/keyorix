import { useEffect, useRef } from 'react';

// Default idle window before an unattended revealed secret is auto-cleared.
export const DEFAULT_SENSITIVE_IDLE_MS = 60_000; // 1 minute

const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'] as const;

/**
 * useAutoClearOnIdle (G28 — secret plaintext lingers client-side with no auto-clear):
 * the shared "sensitive state" auto-clear primitive.
 *
 * Several web surfaces reveal decrypted secret plaintext (a secret's value, a
 * one-time dynamic-secret/machine-token credential, a federated Connect read, an
 * MFA recovery code, a personal access token) and, until this hook existed, relied
 * entirely on the user explicitly hiding/closing/navigating away to clear it — a
 * revealed value could otherwise sit in component state and on-screen indefinitely
 * if the user backgrounded the tab, stepped away, or simply forgot.
 *
 * Attach this hook alongside the piece of state that holds the revealed value.
 * While `active` is true it arms three independent triggers and calls `onClear()`
 * on whichever fires first:
 *   - idle timeout: no mouse/keyboard/touch/scroll activity for `idleMs`
 *   - tab backgrounding: the Page Visibility API (`document.visibilitychange`)
 *   - window blur: focus leaves the browser window entirely
 *
 * `onClear` should reset the revealed value back to its hidden/masked state (e.g.
 * `setShowValue(false)`, `setCredential(null)`) — the surface itself doesn't need
 * to unmount, so it stays usable and the value can be re-revealed on demand.
 *
 * No-op (and safely tears down its own listeners) when `active` is false, so it is
 * cheap to leave mounted for the component's whole lifetime.
 */
export function useAutoClearOnIdle(
    onClear: () => void,
    active: boolean,
    idleMs: number = DEFAULT_SENSITIVE_IDLE_MS
): void {
    // Keep the latest onClear without re-arming listeners every render.
    const onClearRef = useRef(onClear);
    useEffect(() => {
        onClearRef.current = onClear;
    }, [onClear]);

    useEffect(() => {
        if (!active) return undefined;

        let timer: ReturnType<typeof setTimeout>;
        const clear = () => onClearRef.current();
        const resetTimer = () => {
            clearTimeout(timer);
            timer = setTimeout(clear, idleMs);
        };
        const onVisibilityChange = () => {
            if (document.visibilityState === 'hidden') clear();
        };

        resetTimer();
        ACTIVITY_EVENTS.forEach((evt) => window.addEventListener(evt, resetTimer));
        document.addEventListener('visibilitychange', onVisibilityChange);
        window.addEventListener('blur', clear);

        return () => {
            clearTimeout(timer);
            ACTIVITY_EVENTS.forEach((evt) => window.removeEventListener(evt, resetTimer));
            document.removeEventListener('visibilitychange', onVisibilityChange);
            window.removeEventListener('blur', clear);
        };
    }, [active, idleMs]);
}
