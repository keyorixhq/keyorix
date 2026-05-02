import { test, expect } from '@playwright/test';

test.describe('Secret Management', () => {
    test.beforeEach(async ({ page }) => {
        // Login before each test
        await page.goto('/login');
        await page.fill('[data-testid="email-input"]', 'admin@example.com');
        await page.fill('[data-testid="password-input"]', 'password123');
        await page.click('[data-testid="login-button"]');
        await expect(page).toHaveURL('/dashboard');
    });

    test('should display secrets list', async ({ page }) => {
        await page.goto('/secrets');

        await expect(page.getByText('Secrets')).toBeVisible();
        await expect(page.getByTestId('secrets-table')).toBeVisible();
        await expect(page.getByTestId('create-secret-button')).toBeVisible();
    });

    test('should create a new secret', async ({ page }) => {
        await page.goto('/secrets');
        await page.click('[data-testid="create-secret-button"]');

        await expect(page.getByText('Create Secret')).toBeVisible();

        // Fill in the form
        await page.fill('[data-testid="secret-name-input"]', 'test-secret');
        await page.selectOption('[data-testid="secret-type-select"]', 'password');
        await page.fill('[data-testid="secret-value-input"]', 'my-secret-password');
        await page.fill('[data-testid="secret-namespace-input"]', 'production');
        await page.fill('[data-testid="secret-tags-input"]', 'test,automation');

        await page.click('[data-testid="create-secret-submit"]');

        await expect(page.getByText('Secret created successfully')).toBeVisible();
        await expect(page).toHaveURL('/secrets');
        await expect(page.getByText('test-secret')).toBeVisible();
    });

    test('should validate secret form', async ({ page }) => {
        await page.goto('/secrets');
        await page.click('[data-testid="create-secret-button"]');

        // Try to submit empty form
        await page.click('[data-testid="create-secret-submit"]');

        await expect(page.getByText('Name is required')).toBeVisible();
        await expect(page.getByText('Value is required')).toBeVisible();

        // Test invalid name format
        await page.fill('[data-testid="secret-name-input"]', 'Invalid Name!');
        await page.blur('[data-testid="secret-name-input"]');

        await expect(page.getByText(/Name must contain only/)).toBeVisible();
    });

    test('should edit an existing secret', async ({ page }) => {
        await page.goto('/secrets');

        // Click edit button for first secret
        await page.click('[data-testid="secret-edit-button"]:first-child');

        await expect(page.getByText('Edit Secret')).toBeVisible();

        // Update the value
        await page.fill('[data-testid="secret-value-input"]', 'updated-password');
        await page.click('[data-testid="update-secret-submit"]');

        await expect(page.getByText('Secret updated successfully')).toBeVisible();
        await expect(page).toHaveURL('/secrets');
    });

    test('should view secret details', async ({ page }) => {
        await page.goto('/secrets');

        // Click on first secret name
        await page.click('[data-testid="secret-name-link"]:first-child');

        await expect(page.getByText('Secret Details')).toBeVisible();
        await expect(page.getByTestId('secret-value-masked')).toBeVisible();

        // Reveal secret value
        await page.click('[data-testid="reveal-secret-button"]');
        await expect(page.getByTestId('secret-value-revealed')).toBeVisible();

        // Hide secret value
        await page.click('[data-testid="hide-secret-button"]');
        await expect(page.getByTestId('secret-value-masked')).toBeVisible();
    });

    test('should copy secret to clipboard', async ({ page }) => {
        await page.goto('/secrets');
        await page.click('[data-testid="secret-name-link"]:first-child');

        // Grant clipboard permissions
        await page.context().grantPermissions(['clipboard-write']);

        await page.click('[data-testid="copy-secret-button"]');
        await expect(page.getByText('Copied to clipboard')).toBeVisible();
    });

    test('should delete a secret', async ({ page }) => {
        await page.goto('/secrets');

        // Click delete button for first secret
        await page.click('[data-testid="secret-delete-button"]:first-child');

        // Confirm deletion in modal
        await expect(page.getByText('Delete Secret')).toBeVisible();
        await page.click('[data-testid="confirm-delete-button"]');

        await expect(page.getByText('Secret deleted successfully')).toBeVisible();
    });

    test('should search and filter secrets', async ({ page }) => {
        await page.goto('/secrets');

        // Search by name
        await page.fill('[data-testid="search-input"]', 'test');
        await expect(page.getByText('test-secret')).toBeVisible();

        // Filter by namespace
        await page.selectOption('[data-testid="namespace-filter"]', 'production');
        await page.waitForTimeout(500); // Wait for filter to apply

        // Filter by type
        await page.selectOption('[data-testid="type-filter"]', 'password');
        await page.waitForTimeout(500);

        // Clear filters
        await page.click('[data-testid="clear-filters-button"]');
        await expect(page.getByTestId('secrets-table')).toBeVisible();
    });

    test('should handle pagination', async ({ page }) => {
        await page.goto('/secrets');

        // Check if pagination is visible (assuming there are enough secrets)
        const nextButton = page.getByTestId('pagination-next');
        if (await nextButton.isVisible()) {
            await nextButton.click();
            await expect(page.getByText('Page 2')).toBeVisible();

            // Go back to first page
            await page.click('[data-testid="pagination-prev"]');
            await expect(page.getByText('Page 1')).toBeVisible();
        }
    });

    test('should handle bulk operations', async ({ page }) => {
        await page.goto('/secrets');

        // Select multiple secrets
        await page.check('[data-testid="select-secret-checkbox"]:first-child');
        await page.check('[data-testid="select-secret-checkbox"]:nth-child(2)');

        await expect(page.getByText('2 selected')).toBeVisible();

        // Test bulk delete
        await page.click('[data-testid="bulk-delete-button"]');
        await expect(page.getByText('Delete Selected Secrets')).toBeVisible();
        await page.click('[data-testid="confirm-bulk-delete"]');

        await expect(page.getByText('Secrets deleted successfully')).toBeVisible();
    });
});