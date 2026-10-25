import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/cryptoInventory', () => ({
    cryptoInventoryApi: { get: vi.fn() },
}));

import { cryptoInventoryApi } from '../../../services/cryptoInventory';
import { CryptoInventoryPanel } from '../CryptoInventoryPanel';

const get = cryptoInventoryApi.get as unknown as ReturnType<typeof vi.fn>;

const renderPanel = () =>
    render(
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
            <CryptoInventoryPanel />
        </QueryClientProvider>
    );

const inventory = {
    generatedAt: '2026-10-23T12:00:00Z',
    horizon: '2035-01-01T00:00:00Z',
    assets: [
        {
            id: 'tls.http',
            name: 'TLS certificate (http)',
            algorithm: 'ECDSA-P256',
            keySizeBits: 256,
            expiresAt: '2026-12-31T00:00:00Z',
            storage: 'certificate /etc/k/tls.pem',
            risk: { score: 60, level: 'medium', quantumVulnerable: true, reasons: [] },
        },
        {
            id: 'dek',
            name: 'Data encryption key (DEK)',
            algorithm: 'AES-256-GCM',
            keySizeBits: 256,
            storage: 'file dek.key',
            risk: { score: 5, level: 'low', quantumVulnerable: false, reasons: [] },
        },
    ],
    summary: { total: 2, high: 0, medium: 1, low: 1, quantumVulnerable: 1 },
    warnings: ['TLS certificate "grpc" could not be inspected'],
};

beforeEach(() => vi.clearAllMocks());

describe('CryptoInventoryPanel', () => {
    it('lists assets and flags only the classical key as quantum-vulnerable', async () => {
        get.mockResolvedValueOnce(inventory);
        renderPanel();
        expect(await screen.findByText('Crypto inventory')).toBeTruthy();
        expect(screen.getByText('ECDSA-P256')).toBeTruthy();
        expect(screen.getByText('AES-256-GCM')).toBeTruthy();
        expect(screen.getAllByText('Quantum-vulnerable')).toHaveLength(1);
        expect(screen.getByText(/could not be inspected/)).toBeTruthy();
        expect(screen.getByText(/2035-01-01/)).toBeTruthy();
    });

    it('renders nothing when the caller lacks audit.read (request fails)', async () => {
        get.mockRejectedValueOnce(new Error('403'));
        const { container } = renderPanel();
        await vi.waitFor(() => expect(get).toHaveBeenCalled());
        expect(container.textContent).toBe('');
    });
});
