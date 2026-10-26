// web/e2e/real/role-form-scope.spec.ts — E2E-ROLE-SCOPE-1 (#3546 Phase 2), against a real server.
// The role form's "Can be granted" selector (assignable scope):
//   1. the New Role form and a new custom role default to "Per project only";
//   2. widening it to "Install-wide or per project" is saved and audited (role.updated);
//   3. a built-in role's scope cannot be changed: the form disables the selector, the server refuses (403)
//      and the stored scope stays;
//   4. the form itself creates and edits a role: Create/Save send the ticked permissions and the
//      description, and a refusal shows the server's own message.
import { test, expect, request as apiRequestFactory, type APIRequestContext } from '@playwright/test';
import { randomInt } from 'node:crypto';
import { ADMIN_PASSWORD, ADMIN_USERNAME, BACKEND_URL, apiLogin, realLogin } from './helpers';

interface RolePermissionsBody {
    data: { permissions: { name: string }[] };
}

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

        // 1. The New Role form offers "Per project only" by default. (Saving from the form is driven in
        // the last test; this one creates the role through the API, whose own default is also project.)
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

        // 2. Widening to "any" is saved and audited.
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
        // project-only; the form shows its stored scope in a disabled selector, with the reason.
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
        await expect(page.getByRole('dialog').getByLabel('Can be granted')).toBeDisabled();
        await expect(
            page.getByRole('dialog').getByText('Built-in roles cannot change where they can be granted.')
        ).toBeVisible();
    } finally {
        await api.dispose();
    }
});

// The form's own Create and Save (WEB-ROLE-FORM-1). They used to send `permissions: []` and answer 400
// for every role; the form now collects permissions and a description and sends them.
test('the role form creates and edits a role, and shows the server refusal', async ({ page }) => {
    const roleName = `rf-ui-${randomInt(1_000_000)}`;
    const token = await apiLogin(ADMIN_USERNAME!, ADMIN_PASSWORD!);
    const api = await apiRequestFactory.newContext({
        baseURL: BACKEND_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` },
    });
    try {
        await realLogin(page, ADMIN_USERNAME!, ADMIN_PASSWORD!);
        await page.goto('/admin/roles');
        await page.getByRole('button', { name: 'New Role' }).click();
        const dialog = page.getByRole('dialog');
        const create = dialog.getByRole('button', { name: 'Create' });

        // Create stays disabled until the server's three required inputs are there.
        await dialog.getByLabel('Name', { exact: true }).fill(roleName);
        await expect(create).toBeDisabled();
        await dialog.getByLabel('Description').fill('role form e2e');
        await expect(create).toBeDisabled();
        await dialog.getByText('secrets.read', { exact: true }).click();
        await expect(create).toBeEnabled();
        await create.click();
        await expect(dialog).toBeHidden({ timeout: 15_000 });

        const created = (await listRoles(api)).find((r) => r.name === roleName);
        expect(created, 'the role was created from the form').toBeTruthy();
        expect(created!.assignable_scope, 'the form default is project').toBe('project');
        expect(created!.description).toBe('role form e2e');
        const perms = (await (await api.get(`/api/v1/roles/${created!.id}/permissions`)).json()) as RolePermissionsBody;
        expect(perms.data.permissions.map((p) => p.name)).toContain('secrets.read');

        // Edit -> Save: a new description and a widened scope, permissions left alone.
        const card = page.locator('div.rounded-xl', { has: page.getByRole('heading', { name: roleName }) });
        await card.getByTitle('Edit role').click();
        await dialog.getByLabel('Description').fill('role form e2e, edited');
        await dialog.getByLabel('Can be granted').selectOption('any');
        await dialog.getByRole('button', { name: 'Save' }).click();
        await expect(dialog).toBeHidden({ timeout: 15_000 });
        const edited = (await listRoles(api)).find((r) => r.name === roleName)!;
        expect(edited.description).toBe('role form e2e, edited');
        expect(edited.assignable_scope).toBe('any');
        const kept = (await (await api.get(`/api/v1/roles/${created!.id}/permissions`)).json()) as RolePermissionsBody;
        expect(kept.data.permissions.map((p) => p.name)).toContain('secrets.read');

        // A refusal shows the server's reason, not the generic text: a name that is too short.
        await page.getByRole('button', { name: 'New Role' }).click();
        await dialog.getByLabel('Name', { exact: true }).fill('ab');
        await dialog.getByLabel('Description').fill('too short');
        await dialog.getByText('secrets.read', { exact: true }).click();
        await dialog.getByRole('button', { name: 'Create' }).click();
        await expect(dialog.getByText('Failed to create role. Please try again.')).toHaveCount(0);
        await expect(dialog.locator('p.text-red-600')).toBeVisible({ timeout: 15_000 });
    } finally {
        await api.dispose();
    }
});
