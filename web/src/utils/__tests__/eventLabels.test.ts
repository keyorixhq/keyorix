import { describe, it, expect } from 'vitest';
import { eventLabel } from '../eventLabels';

describe('eventLabel', () => {
    it('labels auth.sso_login_session_failed in plain words', () => {
        expect(eventLabel('auth.sso_login_session_failed')).toBe('SSO login failed to start a session');
    });

    it('falls back to a humanized name, never a raw identifier', () => {
        expect(eventLabel('widget.frobnicated')).toBe('Widget frobnicated');
    });
});
