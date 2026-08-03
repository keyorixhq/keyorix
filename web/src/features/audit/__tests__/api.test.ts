import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/client', () => ({
    apiClient: {
        get: vi.fn(),
    },
}));

import { apiClient } from '../../../services/client';
import { useAuditLog } from '../api';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
};

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client: queryClient }, children);
    };
}

beforeEach(() => vi.clearAllMocks());

describe('useAuditLog', () => {
    it('requests page 1 / pageSize 100 by default and maps the response', async () => {
        mock.get.mockResolvedValueOnce({
            data: { data: { logs: [{ id: 1 }], total: 1, page: 1, page_size: 100, total_pages: 1 } },
        });

        const { result } = renderHook(() => useAuditLog(), { wrapper: createWrapper() });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.get).toHaveBeenCalledWith('/api/v1/audit/logs', {
            params: { page: 1, page_size: 100 },
        });
        expect(result.current.data).toEqual({
            data: [{ id: 1 }],
            total: 1,
            page: 1,
            pageSize: 100,
            totalPages: 1,
        });
    });

    it('forwards optional filters using their snake_case param names', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { logs: [], total: 0 } } });

        const { result } = renderHook(
            () =>
                useAuditLog({
                    page: 2,
                    pageSize: 25,
                    action: 'secret.read',
                    projectId: 7,
                    actor: 'alice',
                    dateFrom: '2026-01-01',
                    dateTo: '2026-01-31',
                }),
            { wrapper: createWrapper() }
        );
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mock.get).toHaveBeenCalledWith('/api/v1/audit/logs', {
            params: {
                page: 2,
                page_size: 25,
                action: 'secret.read',
                project_id: 7,
                actor: 'alice',
                date_from: '2026-01-01',
                date_to: '2026-01-31',
            },
        });
    });

    it('defaults data/total/page/pageSize/totalPages when the response omits them', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: {} } });

        const { result } = renderHook(() => useAuditLog(), { wrapper: createWrapper() });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(result.current.data).toEqual({ data: [], total: 0, page: 1, pageSize: 100, totalPages: 1 });
    });
});
