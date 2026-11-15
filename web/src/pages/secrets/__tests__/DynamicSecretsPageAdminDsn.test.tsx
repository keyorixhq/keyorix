import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router';
import { AxiosError } from 'axios';
import DynamicSecretsPage from '../DynamicSecretsPage';
import { NO_CAN } from '../../../test/can';

// Real hooks and a real QueryClient (so the cache can be inspected); only the service layer,
// the project pickers and the permission gate are stubbed.
const SECRET_DSN = 'postgres://admin:hunter2-s3cret@db.internal:5432/app';

let canWrite = true;

vi.mock('../../../features/projects', () => ({
    useProjects: () => ({ data: [{ id: 1, name: 'platform' }] }),
    useProjectEnvironments: () => ({ data: [{ id: 2, name: 'prod' }] }),
}));

vi.mock('../../../features/auth/useCan', () => ({
    useCan: () => ({ ...NO_CAN, writeSecrets: canWrite }),
}));

vi.mock('../../../features/dynamic-secrets/LeasesPanel', () => ({ LeasesPanel: () => null }));

vi.mock('../../../services/dynamicSecrets', async (importActual) => {
    const actual = await importActual<typeof import('../../../services/dynamicSecrets')>();
    return {
        ...actual,
        dynamicSecretsApi: {
            list: vi.fn(),
            classify: vi.fn(),
            create: vi.fn(),
            listRefusedAdminDsn: vi.fn(),
            updateAdminDsn: vi.fn(),
        },
    };
});

import { dynamicSecretsApi, AdminDsnUpdateError, ADMIN_DSN_FORBIDDEN_MESSAGE } from '../../../services/dynamicSecrets';

const api = dynamicSecretsApi as unknown as {
    list: ReturnType<typeof vi.fn>;
    listRefusedAdminDsn: ReturnType<typeof vi.fn>;
    updateAdminDsn: ReturnType<typeof vi.fn>;
};

const config = (id: number, name: string) => ({
    id,
    name,
    projectId: 1,
    environmentId: 2,
    backendType: 'postgres',
    creationTemplate: '',
    defaultTtlSeconds: 3600,
    maxTtlSeconds: 0,
    classification: '',
    createdBy: 'alice',
});

const refused = (id: number, name: string, refusedOptions: string[], liveLeases = 0) => ({
    id,
    name,
    projectId: 1,
    environmentId: 2,
    backendType: 'postgres',
    refusedOptions,
    liveLeases,
});

let queryClient: QueryClient;

const renderPage = () => {
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
        <QueryClientProvider client={queryClient}>
            <BrowserRouter>
                <DynamicSecretsPage />
            </BrowserRouter>
        </QueryClientProvider>
    );
};

const openFormFor = async (user: ReturnType<typeof userEvent.setup>, name: string) => {
    await user.click(await screen.findByRole('button', { name: `Replace admin DSN for ${name}` }));
    return screen.findByLabelText('New admin connection string');
};

beforeEach(() => {
    vi.clearAllMocks();
    canWrite = true;
    api.list.mockResolvedValue([config(5, 'analytics-ro'), config(6, 'billing-rw')]);
    api.listRefusedAdminDsn.mockResolvedValue({ configs: [], unreadable: 0 });
    api.updateAdminDsn.mockResolvedValue(undefined);
});

describe('DynamicSecretsPage: refused admin DSN banner', () => {
    it('lists the refused configs (name, option names, no DSN) and offers the replace form', async () => {
        api.listRefusedAdminDsn.mockResolvedValue({
            configs: [refused(5, 'analytics-ro', ['sslrootcert'], 2)],
            unreadable: 0,
        });
        renderPage();

        const banner = await screen.findByTestId('refused-admin-dsn-banner');
        expect(within(banner).getByText('1 config has a refused admin DSN')).toBeInTheDocument();
        expect(within(banner).getByText('analytics-ro')).toBeInTheDocument();
        expect(banner).toHaveTextContent('refused: sslrootcert');
        expect(banner).toHaveTextContent('2 active leases');
        expect(api.listRefusedAdminDsn).toHaveBeenCalledWith(1);

        const user = userEvent.setup();
        await user.click(within(banner).getByRole('button', { name: 'Fix admin DSN for analytics-ro' }));
        expect(await screen.findByLabelText('New admin connection string')).toBeInTheDocument();
        expect(screen.getByRole('dialog')).toHaveTextContent('Replace admin DSN for analytics-ro');
    });

    it('is absent when nothing is refused', async () => {
        renderPage();
        await screen.findByText('analytics-ro');
        await waitFor(() => expect(api.listRefusedAdminDsn).toHaveBeenCalled());
        expect(screen.queryByTestId('refused-admin-dsn-banner')).not.toBeInTheDocument();
    });

    it('notes configs that could not be checked', async () => {
        api.listRefusedAdminDsn.mockResolvedValue({ configs: [], unreadable: 2 });
        renderPage();
        const banner = await screen.findByTestId('refused-admin-dsn-banner');
        expect(banner).toHaveTextContent('2 configs could not be checked');
    });

    it('disappears once the replaced config is no longer reported', async () => {
        api.listRefusedAdminDsn
            .mockResolvedValueOnce({ configs: [refused(5, 'analytics-ro', ['sslrootcert'])], unreadable: 0 })
            .mockResolvedValue({ configs: [], unreadable: 0 });
        renderPage();
        const user = userEvent.setup();
        await screen.findByTestId('refused-admin-dsn-banner');

        await user.click(screen.getByRole('button', { name: 'Fix admin DSN for analytics-ro' }));
        await user.type(await screen.findByLabelText('New admin connection string'), SECRET_DSN);
        await user.click(screen.getByRole('button', { name: 'Replace admin DSN' }));

        await waitFor(() => expect(screen.queryByTestId('refused-admin-dsn-banner')).not.toBeInTheDocument());
        expect(api.listRefusedAdminDsn).toHaveBeenCalledTimes(2);
        expect(await screen.findByRole('status')).toHaveTextContent('Admin DSN replaced for analytics-ro.');
    });

    it('shows nothing for a 403 (a writer without admin authority), and a notice for other failures', async () => {
        const forbidden = new AxiosError('x', 'ERR_BAD_REQUEST', undefined, undefined, {
            status: 403,
            statusText: '',
            headers: {},
            config: {} as never,
            data: {},
        });
        api.listRefusedAdminDsn.mockRejectedValue(forbidden);
        renderPage();
        await screen.findByText('analytics-ro');
        await waitFor(() => expect(api.listRefusedAdminDsn).toHaveBeenCalled());
        expect(screen.queryByTestId('refused-admin-dsn-banner')).not.toBeInTheDocument();
        expect(screen.queryByText(/Could not check this project/)).not.toBeInTheDocument();

        cleanup();
        api.listRefusedAdminDsn.mockRejectedValue(new Error('boom'));
        renderPage();
        expect(await screen.findByText('Could not check this project for refused admin DSNs.')).toBeInTheDocument();
    });
});

describe('DynamicSecretsPage: permission gate', () => {
    it('hides the replace form and does not ask for the refused list when the role cannot manage configs', async () => {
        canWrite = false;
        renderPage();
        await screen.findByText('analytics-ro');

        expect(screen.queryByRole('button', { name: /Replace admin DSN/ })).not.toBeInTheDocument();
        expect(screen.queryByTestId('refused-admin-dsn-banner')).not.toBeInTheDocument();
        expect(api.listRefusedAdminDsn).not.toHaveBeenCalled();
    });

    it('offers one replace button per config to a role that can manage them', async () => {
        renderPage();
        expect(await screen.findByRole('button', { name: 'Replace admin DSN for analytics-ro' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Replace admin DSN for billing-rw' })).toBeInTheDocument();
    });
});

describe('DynamicSecretsPage: replace admin DSN form', () => {
    it('is a password input with autocomplete off', async () => {
        renderPage();
        const input = await openFormFor(userEvent.setup(), 'analytics-ro');
        expect(input).toHaveAttribute('type', 'password');
        expect(input).toHaveAttribute('autocomplete', 'off');
        expect(input).toHaveValue('');
    });

    it('sends the DSN once, empties the field at submit (before the request settles) and closes on success', async () => {
        let finish!: () => void;
        api.updateAdminDsn.mockImplementationOnce(() => new Promise<void>((resolve) => (finish = () => resolve())));
        renderPage();
        const user = userEvent.setup();
        const input = await openFormFor(user, 'analytics-ro');
        await user.type(input, SECRET_DSN);
        expect(input).toHaveValue(SECRET_DSN);

        await user.click(screen.getByRole('button', { name: 'Replace admin DSN' }));

        // In flight: the request has the value, the field no longer does.
        await waitFor(() => expect(api.updateAdminDsn).toHaveBeenCalledWith(5, SECRET_DSN));
        expect(input).toHaveValue('');
        expect(document.body.textContent).not.toContain('hunter2');
        expect(document.body.innerHTML).not.toContain('hunter2');

        finish();
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
        expect(document.body.textContent).not.toContain('hunter2');
        expect(api.updateAdminDsn).toHaveBeenCalledTimes(1);
    });

    it('clears the field on cancel, so reopening starts empty and nothing was sent', async () => {
        renderPage();
        const user = userEvent.setup();
        const input = await openFormFor(user, 'analytics-ro');
        await user.type(input, SECRET_DSN);

        await user.click(screen.getByRole('button', { name: 'Cancel' }));
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

        const reopened = await openFormFor(user, 'analytics-ro');
        expect(reopened).toHaveValue('');
        expect(api.updateAdminDsn).not.toHaveBeenCalled();
        expect(document.body.innerHTML).not.toContain('hunter2');
    });

    it('refuses an empty value without calling the API', async () => {
        renderPage();
        const user = userEvent.setup();
        await openFormFor(user, 'analytics-ro');
        await user.click(screen.getByRole('button', { name: 'Replace admin DSN' }));
        expect(await screen.findByText('The admin connection string is required.')).toBeInTheDocument();
        expect(api.updateAdminDsn).not.toHaveBeenCalled();
    });

    it.each([
        [
            'refused',
            400,
            'sslrootcert is not allowed',
            'The server refused this connection string. sslrootcert is not allowed',
        ],
        // A missing authority (403) and a missing config (404) read the same: INV-WEB-06.
        ['forbidden', 403, 'nope', ADMIN_DSN_FORBIDDEN_MESSAGE],
        ['forbidden', 404, 'config not found', ADMIN_DSN_FORBIDDEN_MESSAGE],
        ['conflict', 409, 'host differs', 'must name the same host(s). host differs'],
        ['audit_unavailable', 503, 'audit', 'The audit log is unavailable, so nothing was changed.'],
    ] as const)(
        'shows the %s failure (HTTP %i), keeps the form open and the DSN out of the DOM',
        async (kind, status, serverMessage, expected) => {
            api.updateAdminDsn.mockRejectedValueOnce(new AdminDsnUpdateError(kind, status, serverMessage));
            renderPage();
            const user = userEvent.setup();
            const input = await openFormFor(user, 'analytics-ro');
            await user.type(input, SECRET_DSN);
            await user.click(screen.getByRole('button', { name: 'Replace admin DSN' }));

            const dialog = await screen.findByRole('dialog');
            await waitFor(() => expect(dialog).toHaveTextContent(expected));
            expect(input).toHaveValue('');
            expect(document.body.textContent).not.toContain('hunter2');
            expect(screen.queryByRole('status')).not.toBeInTheDocument();
        }
    );

    it('never leaves the DSN in a query cache key or in the mutation cache once the form is gone', async () => {
        api.listRefusedAdminDsn.mockResolvedValue({
            configs: [refused(5, 'analytics-ro', ['sslrootcert'])],
            unreadable: 0,
        });
        renderPage();
        const user = userEvent.setup();
        await user.click(await screen.findByRole('button', { name: 'Fix admin DSN for analytics-ro' }));
        await user.type(await screen.findByLabelText('New admin connection string'), SECRET_DSN);
        await user.click(screen.getByRole('button', { name: 'Replace admin DSN' }));
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

        const queries = queryClient.getQueryCache().getAll();
        expect(queries.length).toBeGreaterThan(0);
        const keys = JSON.stringify(queries.map((q) => q.queryKey));
        expect(keys).not.toContain('hunter2');
        expect(keys).not.toContain('postgres://');
        // Cached responses hold config and option names only.
        expect(JSON.stringify(queries.map((q) => q.state.data))).not.toContain('hunter2');
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });
});
