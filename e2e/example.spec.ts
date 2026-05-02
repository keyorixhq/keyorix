import { test, expect } from '@playwright/test';

test.describe('Basic Application Tests', () => {
    test('should load the application', async ({ page }) => {
        await page.goto('/');

        // Wait for the page to load
        await page.waitForLoadState('networkidle');

        // Check that the page title is set
        await expect(page).toHaveTitle(/Keyorix/);
    });

    test('should have proper meta tags', async ({ page }) => {
        await page.goto('/');

        // Check for viewport meta tag (responsive design)
        const viewportMeta = page.locator('meta[name="viewport"]');
        await expect(viewportMeta).toHaveAttribute('content', /width=device-width/);
    });

    test('should be accessible', async ({ page }) => {
        await page.goto('/');

        // Basic accessibility check - ensure main content has proper structure
        const main = page.locator('main, [role="main"], #root');
        await expect(main).toBeVisible();
    });
});