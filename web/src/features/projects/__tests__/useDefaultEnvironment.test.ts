import { describe, it, expect, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { pickDefaultEnvironment, useDefaultEnvironment } from '../useDefaultEnvironment';

const { listMock } = vi.hoisted(() => ({ listMock: vi.fn() }));
vi.mock('../../../services/secrets', () => ({ secretsApi: { list: listMock } }));

const envs = [
    { id: 1, name: 'development', projectId: 9 },
    { id: 2, name: 'staging', projectId: 9 },
    { id: 3, name: 'production', projectId: 9 },
];

describe('pickDefaultEnvironment', () => {
    it('keeps production when production has secrets', () => {
        expect(pickDefaultEnvironment(envs, [1, 0, 4])).toBe('production');
    });

    it('lands on the environment that has the secrets when production is empty (DEMO-WALK-3 #6/#36)', () => {
        expect(pickDefaultEnvironment(envs, [1, 0, 0])).toBe('development');
        expect(pickDefaultEnvironment(envs, [0, 2, 0])).toBe('staging');
    });

    it('falls back to production when nothing has secrets or a count could not be read', () => {
        expect(pickDefaultEnvironment(envs, [0, 0, 0])).toBe('production');
        expect(pickDefaultEnvironment(envs, [null, null, null])).toBe('production');
    });

    it('falls back to the first environment when there is no production', () => {
        expect(pickDefaultEnvironment([envs[0]!, envs[1]!], [0, 0])).toBe('development');
        expect(pickDefaultEnvironment([], [])).toBe('production');
    });
});

function wrapper() {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client }, children);
}

describe('useDefaultEnvironment', () => {
    it('is undecided (null) while counts load, then picks the environment with the secret', async () => {
        listMock.mockImplementation(async (p: { environment_id: number }) => ({
            total: p.environment_id === 1 ? 1 : 0,
        }));
        const { result } = renderHook(() => useDefaultEnvironment(9, envs, true), { wrapper: wrapper() });
        expect(result.current.name).toBeNull();
        await waitFor(() => expect(result.current.name).toBe('development'));
        expect(listMock).toHaveBeenCalledWith(expect.objectContaining({ project_id: 9, pageSize: 1 }));
    });

    it('does not query at all when the URL already names an environment', () => {
        listMock.mockClear();
        const { result } = renderHook(() => useDefaultEnvironment(9, envs, false), { wrapper: wrapper() });
        expect(result.current.name).toBe('production');
        expect(listMock).not.toHaveBeenCalled();
    });

    it('a failing count lookup falls back to production instead of blocking the tab', async () => {
        listMock.mockRejectedValue(new Error('403'));
        const { result } = renderHook(() => useDefaultEnvironment(9, envs, true), { wrapper: wrapper() });
        await waitFor(() => expect(result.current.name).toBe('production'));
    });
});
