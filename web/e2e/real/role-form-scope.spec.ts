// web/e2e/real/role-form-scope.spec.ts — E2E-ROLE-SCOPE-1 (#3546 Phase 2), against a real server.
// The role form's "Can be granted" selector (assignable scope):
//   1. the New Role form and a new custom role default to "Per project only";
//   2. widening it to "Install-wide or per project" is saved and audited (role.updated);
//   3. a built-in role's scope cannot be changed: the server refuses (403) and the stored scope stays.
import { test, expect, request as apiRequestFactory, type APIRequestContext } from '@playwright/test';
import { randomInt } from 'node:crypto';
import { ADMIN_PASSWORD, ADMIN_USERNAME, BACKEND_URL, apiLogin, realLogin } from './helpers';

interface RoleRow {
    id: number;
    name: string;
    description: string;
    assignable_scope: string;
}

async function listRoles(api: APIRequestContext): Promise<RoleRow[]> {
    const res = await api.get('/api/v1/roles');
    expect(res.ok(), await res.text()).toBeTruthy();
    const data = (await res.json()).data;
    return Array.isArray(data) ? data : data.roles;
}

test('the role form: new roles default to project, widening is audited, built-ins are fixed', async ({ page }) => {
    const stamp = randomInt(1_000_000);
    const roleName = `rf-role-${stamp}`;
    const token = await apiLogin(ADMIN_USERNAME!, ADMIN_PASSWORD!);
    const api = await apiRequestFactory.newContext({
        baseURL: BACKEND_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` },
    });
    try {
        await realLogin(page, ADMIN_USERNAME!, ADMIN_PASSWORD!);
        await page.goto('/admin/roles');

        // 1. The New Role form offers "Per project only" by default. (Saving from this form is not
        // driven here: it never sends the permissions the server requires, so Create answers 400 --
        // see the report. The role is created through the API, whose own default is also project.)
        await page.getByRole('button', { name: 'New Role' }).click();
        await expect(page.getByRole('dialog').getByLabel('Can be granted')).toHaveValue('project');
        await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
        const createdRes = await api.post('/api/v1/roles', {
            data: { name: roleName, description: 'role form e2e', permissions: ['secrets.read'] },
        });
        expect(createdRes.status(), await createdRes.text()).toBe(201);
        const created = (await listRoles(api)).find((r) => r.name === roleName);
        expect(created, 'the role exists').toBeTruthy();
        expect(created!.assignable_scope, 'a new custom role defaults to project').toBe('project');
        await page.reload();

        // 2. Widening to "any" is saved and audited. (Sent through the API for the same reason as
        // step 1: the edit form's Save sends `permissions: []`, which the server rejects with 400.)
        const widen = await api.put(`/api/v1/roles/${created!.id}`, {
            data: { name: roleName, description: 'role form e2e', assignable_scope: 'any' },
        });
        expect(widen.status(), await widen.text()).toBe(200);
        expect((await listRoles(api)).find((r) => r.name === roleName)!.assignable_scope).toBe('any');
        const audit = await api.get('/api/v1/audit/logs?action=role.updated&page_size=50');
        expect(audit.ok(), await audit.text()).toBeTruthy();
        const descriptions: string[] = (await audit.json()).data.logs.map(
            (l: { description: string }) => l.description
        );
        expect(descriptions).toContain(
            `role "${roleName}" (id ${created!.id}) updated (assignable_scope project -> any)`
        );
        await page.reload();
        const card = page.locator('div.rounded-xl', { has: page.getByRole('heading', { name: roleName }) });
        await expect(card.getByText('Install-wide or per project')).toBeVisible({ timeout: 15_000 });
        await card.getByTitle('Edit role').click();
        await expect(page.getByRole('dialog').getByLabel('Can be granted')).toHaveValue('any');
        await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

        // 3. A built-in role's scope is not editable: the server refuses (403) and project_viewer stays
        // project-only; the form shows its stored scope.
        const builtIn = (await listRoles(api)).find((r) => r.name === 'project_viewer')!;
        expect(builtIn.assignable_scope).toBe('project');
        const direct = await api.put(`/api/v1/roles/${builtIn.id}`, {
            data: { name: builtIn.name, description: builtIn.description, assignable_scope: 'any' },
        });
        expect(direct.status()).toBe(403);
        expect((await listRoles(api)).find((r) => r.name === 'project_viewer')!.assignable_scope).toBe('project');
        const builtInCard = page.locator('div.rounded-xl', {
            has: page.getByRole('heading', { name: 'project_viewer' }),
        });
        await expect(builtInCard.getByText('Per project only')).toBeVisible();
        await builtInCard.getByTitle('Edit role').click();
        await expect(page.getByRole('dialog').getByLabel('Can be granted')).toHaveValue('project');
    } finally {
        await api.dispose();
    }
});

// Blocked by a web defect found by this spec (see SESSION-E2E-ROLE-SCOPE-1): the role form's Create and
// Save send `permissions: []` (and Create may send an empty description), which POST/PUT /api/v1/roles
// answer with 400, so "Failed to create role" / "Failed to update role" shows for every role. Un-fixme
// this when the form sends the role's permissions.
test.fixme('saving the role form changes the scope (create defaults to project, widen to any)', async ({ page }) => {
    await realLogin(page, ADMIN_USERNAME!, ADMIN_PASSWORD!);
    await page.goto('/admin/roles');
    await page.getByRole('button', { name: 'New Role' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Name', { exact: true }).fill(`rf-ui-${randomInt(1_000_000)}`);
    await dialog.getByLabel('Description').fill('role form e2e');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog).toBeHidden({ timeout: 15_000 });
});
