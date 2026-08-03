import { test, expect } from '@playwright/test';
import {
    mockApiCatchAll,
    mockAuthenticated,
    mockUnauthenticated,
    mockLoginSuccess,
    mockLoginFailure,
    mockLogoutSuccess,
    mockDashboardData,
} from './mocks';

test.describe('Authentication', () => {
    test.beforeEach(async ({ page }) => {
        await mockApiCatchAll(page);
    });

    test('redirects to login when not authenticated', async ({ page }) => {
        await mockUnauthenticated(page);
        await page.goto('/');

        await expect(page).toHaveURL('/login');
        await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    });

    test('shows validation errors on empty submit', async ({ page }) => {
        await mockUnauthenticated(page);
        await page.goto('/login');

        await page.getByTestId('login-button').click();

        await expect(page.getByText('Username is required')).toBeVisible();
        await expect(page.getByText('Password must be at least 6 characters')).toBeVisible();
    });

    test('shows a server error message on invalid credentials', async ({ page }) => {
        await mockUnauthenticated(page);
        await mockLoginFailure(page, 'Invalid credentials');
        await page.goto('/login');

        await page.getByTestId('username-input').fill('admin');
        await page.getByTestId('password-input').fill('wrongpassword');
        await page.getByTestId('login-button').click();

        await expect(page.getByText('Invalid credentials')).toBeVisible();
        await expect(page).toHaveURL('/login');
    });

    test('logs in successfully and lands on the dashboard', async ({ page }) => {
        await mockUnauthenticated(page);
        await mockLoginSuccess(page);
        await mockDashboardData(page);
        await page.goto('/login');

        await page.getByTestId('username-input').fill('admin');
        await page.getByTestId('password-input').fill('password123');
        // Once logged in, the app re-checks /auth/profile — switch that mock
        // over to "authenticated" before submitting so the redirect resolves.
        await mockAuthenticated(page);
        await page.getByTestId('login-button').click();

        await expect(page).toHaveURL('/dashboard');
        await expect(page.getByText('Total Secrets')).toBeVisible();
    });

    test('logs out and returns to the login page', async ({ page }) => {
        await mockAuthenticated(page);
        await mockDashboardData(page);
        await mockLogoutSuccess(page);
        await page.goto('/dashboard');

        await expect(page).toHaveURL('/dashboard');
        // Logout does a hard reload, which re-runs the initial auth check —
        // reflect the session actually being gone so it doesn't just bounce
        // back to /dashboard.
        await mockUnauthenticated(page);
        await page.getByTestId('user-menu-button').click();
        await page.getByRole('menuitem', { name: 'Sign out' }).click();

        await page.waitForURL('/login');
        await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    });
});
