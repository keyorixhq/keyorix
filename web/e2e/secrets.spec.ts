import { test, expect } from '@playwright/test';
import {
    mockApiCatchAll,
    mockAuthenticated,
    mockSecretsList,
    mockSecretsPolicy,
    mockProjectsAndEnvironments,
    mockSecretCreateSuccess,
    mockSecretCreateFailure,
} from './mocks';

test.describe('Secret Management', () => {
    test.beforeEach(async ({ page }) => {
        await mockApiCatchAll(page);
        await mockAuthenticated(page);
    });

    test('displays the secrets list', async ({ page }) => {
        await mockSecretsList(page, [
            { id: 1, name: 'test-secret', type: 'password', environment_name: 'production', status: 'active' },
        ]);
        await page.goto('/secrets');

        await expect(page.getByTestId('secrets-table')).toBeVisible();
        await expect(page.getByText('test-secret')).toBeVisible();
    });

    test('shows an empty state when there are no secrets', async ({ page }) => {
        await mockSecretsList(page, []);
        await page.goto('/secrets');

        await expect(page.getByText('No secrets found')).toBeVisible();
    });

    test('creates a new secret', async ({ page }) => {
        await mockSecretsList(page, []);
        await mockSecretsPolicy(page);
        await mockProjectsAndEnvironments(page);
        await mockSecretCreateSuccess(page, {
            id: 2,
            name: 'my-new-secret',
            type: 'password',
            environment_name: 'production',
            status: 'active',
        });
        await page.goto('/secrets');

        await page.getByTestId('create-secret-button').first().click();
        await page.locator('#create-secret-name').fill('my-new-secret');
        await page.locator('#create-secret-value').fill('super-secret-value');
        await page.locator('#create-secret-type').selectOption('password');
        await page.locator('#create-secret-project').selectOption('1');
        await page.locator('#create-secret-environment').selectOption('1');

        // The list refetches on success — swap in a list containing the new
        // secret so we can assert the round trip actually landed.
        await mockSecretsList(page, [
            { id: 2, name: 'my-new-secret', type: 'password', environment_name: 'production', status: 'active' },
        ]);
        await page.getByTestId('create-secret-submit').click();

        await expect(page.getByTestId('create-secret-submit')).toBeHidden();
        await expect(page.getByText('my-new-secret')).toBeVisible();
    });

    test('shows an error message when secret creation fails', async ({ page }) => {
        await mockSecretsList(page, []);
        await mockSecretsPolicy(page);
        await mockProjectsAndEnvironments(page);
        await mockSecretCreateFailure(page, 'A secret with this name already exists.');
        await page.goto('/secrets');

        await page.getByTestId('create-secret-button').first().click();
        await page.locator('#create-secret-name').fill('duplicate-secret');
        await page.locator('#create-secret-value').fill('super-secret-value');
        await page.locator('#create-secret-project').selectOption('1');
        await page.locator('#create-secret-environment').selectOption('1');
        await page.getByTestId('create-secret-submit').click();

        await expect(page.getByText('A secret with this name already exists.')).toBeVisible();
    });
});
