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
// NOTE: as of writing, HTTP/Database/Secrets counters below are NOT
// instrumented server-side — GetMetrics returns them as zero-valued structs
// (see the handler's own comment: "not instrumented in the HTTP handler
// path... left at their zero value here rather than fabricated values").
// Don't build UI that presents these as live monitored data until that
// changes on the backend.
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

export interface SystemSecretsMetrics {
    total_secrets: number;
    active_secrets: number;
    expired_secrets: number;
    secrets_created_24h: number;
    secrets_accessed_24h: number;
    encryption_ops_24h: number;
    decryption_ops_24h: number;
}

// Mirrors MemoryMetrics — populated from runtime.MemStats, genuinely live.
export interface SystemMemoryMetrics {
    alloc: number;
    total_alloc: number;
    sys: number;
    lookups: number;
    mallocs: number;
    frees: number;
    heap_alloc: number;
    heap_sys: number;
    heap_idle: number;
    heap_inuse: number;
    heap_released: number;
    heap_objects: number;
    stack_inuse: number;
    stack_sys: number;
}

// Mirrors GCMetrics — genuinely live.
export interface SystemGCMetrics {
    num_gc: number;
    pause_total: number;
    pause_ns: number[];
    next_gc: number;
    last_gc: number;
    gc_cpu_fraction: number;
}

export interface SystemMetrics {
    memory: SystemMemoryMetrics;
    goroutines: number;
    gc: SystemGCMetrics;
    http: SystemHttpMetrics;
    database: SystemDatabaseMetrics;
    secrets: SystemSecretsMetrics;
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
