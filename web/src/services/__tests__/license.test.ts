import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { licenseApi } from '../license';

const mock = apiClient as unknown as { get: ReturnType<typeof vi.fn> };

beforeEach(() => vi.clearAllMocks());

describe('licenseApi.getStatus', () => {
    it('normalizes a full snake_case status payload', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                data: {
                    state: 'active',
                    licensee: 'ACME GmbH',
                    plan: 'enterprise',
                    features: ['billing'],
                    grants: true,
                    expires_at: '2027-01-01T00:00:00Z',
                    max_seats: 50,
                    reason: '',
                },
            },
        });

        const status = await licenseApi.getStatus();

        expect(mock.get).toHaveBeenCalledWith('/api/v1/license/status');
        expect(status).toEqual({
            state: 'active',
            licensee: 'ACME GmbH',
            plan: 'enterprise',
            features: ['billing'],
            grants: true,
            expiresAt: '2027-01-01T00:00:00Z',
            maxSeats: 50,
            reason: '',
        });
    });

    it('defaults to the community-baseline shape when fields are absent', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { state: 'none', features: [], grants: false } } });

        const status = await licenseApi.getStatus();

        expect(status.licensee).toBe('');
        expect(status.plan).toBe('');
        expect(status.expiresAt).toBe('');
        expect(status.maxSeats).toBe(0);
        expect(status.features).toEqual([]);
    });

    it('defaults state to "none" and features to [] when the fields are missing entirely', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: {} } });

        const status = await licenseApi.getStatus();

        expect(status.state).toBe('none');
        expect(status.features).toEqual([]);
    });

    it('unwraps a payload that is not itself wrapped in an envelope data field', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                state: 'expired',
                licensee: 'Direct Co',
                plan: 'community',
                features: [],
                grants: false,
                expires_at: '2025-01-01T00:00:00Z',
                max_seats: 5,
                reason: 'past due',
            },
        });

        const status = await licenseApi.getStatus();

        expect(status).toEqual({
            state: 'expired',
            licensee: 'Direct Co',
            plan: 'community',
            features: [],
            grants: false,
            expiresAt: '2025-01-01T00:00:00Z',
            maxSeats: 5,
            reason: 'past due',
        });
    });
});
