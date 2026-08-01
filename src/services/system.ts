import { apiClient } from './client';
import { ApiResponse } from '../types';

// Mirrors server/http/handlers/system.go's PoolInfo/DatabaseInfo/SecurityInfo/SystemInfo.
export interface SystemPoolInfo {
    max_connections: number;
    active_connections: number;
    idle_connections: number;
}

export interface SystemDatabaseInfo {
    type: string;
    connected: boolean;
    version: string;
    pool: SystemPoolInfo;
}

export interface SystemSecurityInfo {
    tls_enabled: boolean;
    auth_enabled: boolean;
    encryption_method: string;
    audit_enabled: boolean;
}

export interface SystemInfo {
    version: string;
    build_time: string;
    git_commit: string;
    go_version: string;
    os: string;
    arch: string;
    uptime: string;
    environment: string;
    features: Record<string, boolean | undefined>;
    database: SystemDatabaseInfo;
    security: SystemSecurityInfo;
}

// Mirrors server/http/handlers/system.go's SystemMetrics and its nested types.
export interface SystemHttpMetrics {
    requests_total: number;
    requests_per_sec: number;
    avg_response_time: number;
    error_rate: number;
    active_connections: number;
}

export interface SystemDatabaseMetrics {
    queries_total: number;
    queries_per_sec: number;
    avg_query_time: number;
    slow_queries: number;
    connections_active: number;
    connections_idle: number;
}

export interface SystemMetrics {
    memory: Record<string, number>;
    goroutines: number;
    gc: Record<string, unknown>;
    http: SystemHttpMetrics;
    database: SystemDatabaseMetrics;
    secrets: Record<string, number>;
    uptime: string;
    timestamp: string;
}

export const systemApi = {
    async getInfo(): Promise<SystemInfo> {
        const response = await apiClient.get<ApiResponse<SystemInfo>>('/api/v1/system/info');
        return response.data.data;
    },

    async getMetrics(): Promise<SystemMetrics> {
        const response = await apiClient.get<ApiResponse<SystemMetrics>>('/api/v1/system/metrics');
        return response.data.data;
    },
};
