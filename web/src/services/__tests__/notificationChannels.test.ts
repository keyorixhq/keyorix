import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { notificationChannelsApi } from '../notificationChannels';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

const channel = {
    id: 1,
    name: 'platform-alerts',
    type: 'webhook',
    enabled: true,
    url: 'https://hooks.example.com/platform',
    events: 'secret.rotated',
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
};

describe('notificationChannelsApi.list', () => {
    it('fetches and unwraps the channels array', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: { channels: [channel] } } });
        const out = await notificationChannelsApi.list();
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/notification-channels');
        expect(out).toEqual([channel]);
    });
});

describe('notificationChannelsApi.get', () => {
    it('fetches a single channel by id', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: channel } });
        const out = await notificationChannelsApi.get(1);
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/notification-channels/1');
        expect(out).toEqual(channel);
    });
});

describe('notificationChannelsApi.create', () => {
    it('posts the payload and returns the created channel', async () => {
        mocked.post.mockResolvedValueOnce({ data: { data: channel } });
        const payload = { name: 'platform-alerts', type: 'webhook', events: 'secret.rotated' };
        const out = await notificationChannelsApi.create(payload);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/notification-channels', payload);
        expect(out).toEqual(channel);
    });
});

describe('notificationChannelsApi.update', () => {
    it('sends PUT with the updated payload', async () => {
        mocked.put.mockResolvedValueOnce({ data: { data: channel } });
        const payload = { name: 'platform-alerts-v2', type: 'webhook', events: 'secret.rotated' };
        const out = await notificationChannelsApi.update(1, payload);
        expect(mocked.put).toHaveBeenCalledWith('/api/v1/notification-channels/1', payload);
        expect(out).toEqual(channel);
    });
});

describe('notificationChannelsApi.delete', () => {
    it('sends DELETE to the channel endpoint', async () => {
        mocked.delete.mockResolvedValueOnce({});
        await notificationChannelsApi.delete(1);
        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/notification-channels/1');
    });
});

describe('notificationChannelsApi.getRetryPolicy', () => {
    it('fetches the retry policy for a channel', async () => {
        const policy = { channel_id: 1, max_retries: 3, retry_backoff_ms: 1000 };
        mocked.get.mockResolvedValueOnce({ data: { data: policy } });
        const out = await notificationChannelsApi.getRetryPolicy(1);
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/notification-channels/1/retry-policy');
        expect(out).toEqual(policy);
    });
});

describe('notificationChannelsApi.setRetryPolicy', () => {
    it('sends PUT with the retry policy body', async () => {
        const policy = { channel_id: 1, max_retries: 5, retry_backoff_ms: 2000 };
        mocked.put.mockResolvedValueOnce({ data: { data: policy } });
        const out = await notificationChannelsApi.setRetryPolicy(1, { max_retries: 5, retry_backoff_ms: 2000 });
        expect(mocked.put).toHaveBeenCalledWith('/api/v1/notification-channels/1/retry-policy', {
            max_retries: 5,
            retry_backoff_ms: 2000,
        });
        expect(out).toEqual(policy);
    });
});
