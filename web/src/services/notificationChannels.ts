import { apiClient } from './client';
import { ApiResponse } from '../types';

// "webhook" | "slack" | "teams" | "email" — kept as a plain string on the wire
// (matches the backend's NotificationChannel.Type), not a union, since the
// server is the source of truth for valid values.
export interface NotificationChannel {
    id: number;
    name: string;
    type: string;
    enabled: boolean;
    url?: string;
    email?: string;
    // Comma-separated event types, e.g. "secret.rotated,anomaly.detected".
    events: string;
    created_by: string;
    created_at: string;
    updated_at: string;
}

export interface NotificationChannelPayload {
    name: string;
    type: string;
    enabled?: boolean;
    url?: string;
    email?: string;
    events: string;
}

export interface NotificationRetryPolicy {
    channel_id: number;
    max_retries: number;
    retry_backoff_ms: number;
}

export const notificationChannelsApi = {
    async list(): Promise<NotificationChannel[]> {
        const res = await apiClient.get<ApiResponse<{ channels: NotificationChannel[] }>>(
            '/api/v1/notification-channels'
        );
        return res.data.data.channels;
    },

    async get(id: number): Promise<NotificationChannel> {
        const res = await apiClient.get<ApiResponse<NotificationChannel>>(`/api/v1/notification-channels/${id}`);
        return res.data.data;
    },

    async create(body: NotificationChannelPayload): Promise<NotificationChannel> {
        const res = await apiClient.post<ApiResponse<NotificationChannel>>('/api/v1/notification-channels', body);
        return res.data.data;
    },

    async update(id: number, body: NotificationChannelPayload): Promise<NotificationChannel> {
        const res = await apiClient.put<ApiResponse<NotificationChannel>>(`/api/v1/notification-channels/${id}`, body);
        return res.data.data;
    },

    async delete(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/notification-channels/${id}`);
    },

    async getRetryPolicy(id: number): Promise<NotificationRetryPolicy> {
        const res = await apiClient.get<ApiResponse<NotificationRetryPolicy>>(
            `/api/v1/notification-channels/${id}/retry-policy`
        );
        return res.data.data;
    },

    async setRetryPolicy(
        id: number,
        body: { max_retries: number; retry_backoff_ms: number }
    ): Promise<NotificationRetryPolicy> {
        const res = await apiClient.put<ApiResponse<NotificationRetryPolicy>>(
            `/api/v1/notification-channels/${id}/retry-policy`,
            body
        );
        return res.data.data;
    },
};
