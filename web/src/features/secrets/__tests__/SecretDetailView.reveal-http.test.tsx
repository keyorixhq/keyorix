import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { ALL_CAN } from '../../../test/can';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { SecretDetailView } from '../SecretDetailView';
import { apiClient } from '../../../services/client';
import { Secret } from '../../../types';

// #2450 at the HTTP boundary. SecretDetailView.test.tsx mocks the `../api` hooks, so it
// cannot tell where the revealed value comes from. These tests keep the real hooks and
// services and stub only the axios instance, serving exactly what the server serves:
//   GET /secrets/{id}/versions            -> version METADATA, never a value field
//   GET /secrets/{id}?include_value=true  -> {secret, value}, or a refusal (403/404/503)
// Everything else answers 404 so unrelated panels settle into their own error state.

vi.mock('../../auth/useCan', () => ({ useCan: () => ALL_CAN }));

const SECRET_ID = 7;

const makeSecret = (): Secret => ({
    id: SECRET_ID,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-14T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    classification: 'confidential',
});

const axiosError = (status: number, body: Record<string, unknown>): AxiosError => {
    const config = { headers: {} } as InternalAxiosRequestConfig;
    const response = { status, statusText: String(status), data: body, headers: {}, config } as AxiosResponse;
    return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, {}, response);
};

const ok = (data: unknown) => ({ data: { success: true, data } });

type ValueReply =
    | { kind: 'value'; value: string }
    | { kind: 'raw'; data: unknown }
    | { kind: 'refused'; status: number; body: Record<string, unknown> };

let valueReply: ValueReply;
let valueCalls: number;
let getSpy: ReturnType<typeof vi.spyOn>;

const route = async (url: string, config?: { params?: Record<string, unknown> }) => {
    if (url === `/api/v1/secrets/${SECRET_ID}/versions`) {
        // Real shape: metadata only. No value, no EncryptedValue.
        return ok({ versions: [{ VersionNumber: 1, CreatedAt: '2026-06-10T00:00:00Z' }] });
    }
    if (url === `/api/v1/secrets/${SECRET_ID}` && config?.params?.include_value === true) {
        valueCalls++;
        if (valueReply.kind === 'refused') throw axiosError(valueReply.status, valueReply.body);
        if (valueReply.kind === 'raw') return ok(valueReply.data);
        return ok({ secret: makeSecret(), value: valueReply.value });
    }
    throw axiosError(404, { error: 'NotFound', message: 'not found' });
};

const clickReveal = () => fireEvent.click(screen.getByRole('button', { name: /^Reveal$/i }));

describe('SecretDetailView Reveal against the real hooks (#2450)', () => {
    beforeEach(() => {
        valueCalls = 0;
        valueReply = { kind: 'value', value: 'sup3r-secret' };
        getSpy = vi.spyOn(apiClient, 'get').mockImplementation(route as never);
        vi.spyOn(apiClient, 'request').mockRejectedValue(axiosError(404, { error: 'NotFound' }));
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('reveals the plaintext from the include_value read when versions carry no value field', async () => {
        const atobSpy = vi.spyOn(globalThis, 'atob');
        render(<SecretDetailView secret={makeSecret()} />);

        expect(() => clickReveal()).not.toThrow();

        expect(await screen.findByText('sup3r-secret')).toBeInTheDocument();
        expect(getSpy).toHaveBeenCalledWith(`/api/v1/secrets/${SECRET_ID}`, { params: { include_value: true } });
        expect(atobSpy).not.toHaveBeenCalled();
        expect(screen.queryByText('Failed to load secret value')).not.toBeInTheDocument();
    });

    it('does not read the value until Reveal is clicked', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        expect(valueCalls).toBe(0);
        expect(screen.getByText(/Secret value is hidden/i)).toBeInTheDocument();
    });

    // The error component is the shared <Alert type="error"> with the server's own reason.
    const refusals: { name: string; status: number; body: Record<string, unknown>; reason: string }[] = [
        {
            name: '403 forbidden',
            status: 403,
            body: { error: 'Forbidden', message: 'you may not read this secret' },
            reason: 'you may not read this secret',
        },
        {
            name: '404 not found',
            status: 404,
            body: { error: 'NotFound', message: 'secret not found' },
            reason: 'secret not found',
        },
        {
            name: '503 unavailable',
            status: 503,
            body: { error: 'Unavailable', message: 'audit log unavailable' },
            reason: 'audit log unavailable',
        },
    ];

    describe.each(refusals)('when the value read answers $name', ({ status, body, reason }) => {
        beforeEach(() => {
            valueReply = { kind: 'refused', status, body };
        });

        it('shows the inline error with the server reason and no value', async () => {
            render(<SecretDetailView secret={makeSecret()} />);
            clickReveal();

            expect(await screen.findByText('Failed to load secret value')).toBeInTheDocument();
            expect(screen.getByText(reason)).toBeInTheDocument();
            expect(screen.queryByText('sup3r-secret')).not.toBeInTheDocument();
        });
    });
});
