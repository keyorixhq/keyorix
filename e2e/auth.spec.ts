import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto('/');
    });

    test('should redirect to login when not authenticated', async ({ page }) => {
        await expect(page).toHaveURL('/login');
        await expect(page.getByText('Sign In')).toBeVisible();
    });

    test('should login with valid credentials', async ({ page }) => {
        await page.fill('[data-testid="email-input"]', 'admin@example.com');
        await page.fill('[data-testid="password-input"]', 'password123');
        await page.click('[data-testid="login-button"]');

        await expect(page).toHaveURL('/dashboard');
        await expect(page.getByText('Dashboard')).toBeVisible();
    });

    test('should show error with invalid credentials', async ({ page }) => {
        await page.fill('[data-testid="email-input"]', 'admin@example.com');
        await page.fill('[data-testid="password-input"]', 'wrongpassword');
        await page.click('[data-testid="login-button"]');

        await expect(page.getByText('Invalid credentials')).toBeVisible();
        await expect(page).toHaveURL('/login');
    });

    test('should logout successfully', async ({ page }) => {
        // Login first
        await page.fill('[data-testid="email-input"]', 'admin@example.com');
        await page.fill('[data-testid="password-input"]', 'password123');
        await page.click('[data-testid="login-button"]');

        await expect(page).toHaveURL('/dashboard');

        // Logout
        await page.click('[data-testid="user-menu-button"]');
        await page.click('[data-testid="logout-button"]');

        await expect(page).toHaveURL('/login');
        await expect(page.getByText('Sign In')).toBeVisible();
    });

    test('should handle session timeout', async ({ page }) => {
        // Login first
        await page.fill('[data-testid="email-input"]', 'admin@example.com');
        await page.fill('[data-testid="password-input"]', 'password123');
        await page.click('[data-testid="login-button"]');

        await expect(page).toHaveURL('/dashboard');

        // Mock expired session by clearing cookies
        await page.context().clearCookies();

        // Try to navigate to a protected page
        await page.goto('/secrets');

        await expect(page).toHaveURL('/login');
        await expect(page.getByText('Your session has expired')).toBeVisible();
    });

    test('should remember login state across browser sessions', async ({ page, context }) => {
        // Login with remember me
        await page.fill('[data-testid="email-input"]', 'admin@example.com');
        await page.fill('[data-testid="password-input"]', 'password123');
        await page.check('[data-testid="remember-me-checkbox"]');
        await page.click('[data-testid="login-button"]');

        await expect(page).toHaveURL('/dashboard');

        // Create new page in same context (simulates new tab)
        const newPage = await context.newPage();
        await newPage.goto('/');

        // Should be automatically logged in
        await expect(newPage).toHaveURL('/dashboard');
    });

    test('should validate form fields', async ({ page }) => {
        // Try to submit empty form
        await page.click('[data-testid="login-button"]');

        await expect(page.getByText('Email is required')).toBeVisible();
        await expect(page.getByText('Password is required')).toBeVisible();

        // Test invalid email format
        await page.fill('[data-testid="email-input"]', 'invalid-email');
        await page.blur('[data-testid="email-input"]');

        await expect(page.getByText('Please enter a valid email')).toBeVisible();
    });

    test('should handle password reset flow', async ({ page }) => {
        await page.click('[data-testid="forgot-password-link"]');

        await expect(page).toHaveURL('/forgot-password');
        await expect(page.getByText('Reset Password')).toBeVisible();

        await page.fill('[data-testid="email-input"]', 'admin@example.com');
        await page.click('[data-testid="reset-button"]');

        await expect(page.getByText('Password reset email sent')).toBeVisible();
    });
});