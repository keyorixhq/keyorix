import { describe, it, expect } from 'vitest';
import { API_ENDPOINTS, ROUTES } from '../constants';

// These constants are mostly exercised indirectly through services/pages that
// consume them. The id-parameterized builders below aren't called anywhere
// that's currently covered, so they're asserted directly here.

describe('API_ENDPOINTS', () => {
    it('builds the project detail endpoint', () => {
        expect(API_ENDPOINTS.PROJECTS.GET(7)).toBe('/api/v1/projects/7');
    });

    it('builds the project environments endpoint', () => {
        expect(API_ENDPOINTS.PROJECTS.ENVIRONMENTS(7)).toBe('/api/v1/projects/7/environments');
    });
});

describe('ROUTES', () => {
    it('builds the secret detail route', () => {
        expect(ROUTES.SECRET_DETAIL(3)).toBe('/secrets/3');
    });

    it('builds the edit secret route', () => {
        expect(ROUTES.EDIT_SECRET(3)).toBe('/secrets/3/edit');
    });

    it('builds the project secrets route', () => {
        expect(ROUTES.PROJECT_SECRETS(3)).toBe('/projects/3/secrets');
    });

    it('builds the project members route', () => {
        expect(ROUTES.PROJECT_MEMBERS(3)).toBe('/projects/3/members');
    });

    it('builds the project activity route', () => {
        expect(ROUTES.PROJECT_ACTIVITY(3)).toBe('/projects/3/activity');
    });

    it('builds the project settings route', () => {
        expect(ROUTES.PROJECT_SETTINGS(3)).toBe('/projects/3/settings');
    });
});
