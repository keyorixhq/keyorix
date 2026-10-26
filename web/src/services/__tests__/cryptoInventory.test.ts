import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: { get: vi.fn() },
}));

import { apiClient } from '../client';
import { cryptoInventoryApi } from '../cryptoInventory';

const mock = apiClient as unknown as { get: ReturnType<typeof vi.fn> };

beforeEach(() => vi.clearAllMocks());

describe('cryptoInventoryApi.get', () => {
    it('requests the JSON inventory and normalizes snake_case fields', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                data: {
                    generated_at: '2026-10-23T12:00:00Z',
                    policy: { horizon: '2035-01-01T00:00:00Z', migration_years: 3, unbounded_lifetime_years: 10 },
                    assets: [
                        {
                            id: 'tls.http',
                            name: 'TLS certificate (http)',
                            class: 'tls-certificate',
                            algorithm: 'ECDSA-P256',
                            key_size_bits: 256,
                            expires_at: '2026-12-31T00:00:00Z',
                            storage: 'certificate /etc/k/tls.pem',
                            risk: { score: 60, level: 'medium', quantum_vulnerable: true, reasons: ['r'] },
                        },
                    ],
                    summary: { total: 1, high: 0, medium: 1, low: 0, quantum_vulnerable: 1 },
                    warnings: ['w'],
                },
            },
        });
        const inv = await cryptoInventoryApi.get();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/compliance/crypto-inventory', { params: { format: 'json' } });
        expect(inv.horizon).toBe('2035-01-01T00:00:00Z');
        expect(inv.assets[0]).toMatchObject({
            id: 'tls.http',
            keySizeBits: 256,
            expiresAt: '2026-12-31T00:00:00Z',
            risk: { score: 60, level: 'medium', quantumVulnerable: true },
        });
        expect(inv.summary.quantumVulnerable).toBe(1);
        expect(inv.warnings).toEqual(['w']);
    });

    it('tolerates missing optional fields', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { assets: [{ id: 'dek', risk: {} }] } } });
        const inv = await cryptoInventoryApi.get();
        expect(inv.assets[0].risk.quantumVulnerable).toBe(false);
        expect(inv.assets[0].expiresAt).toBeUndefined();
        expect(inv.warnings).toEqual([]);
    });
});
