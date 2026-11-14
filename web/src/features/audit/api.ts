import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { apiClient } from '../../services/client';

export interface AuditLogEntry {
    id: number;
    event_type: string;
    actor: string;
    actor_type: string; // 'user' | 'machine_identity' | 'system' (ADR-023)
    description: string;
    timestamp: string;
}

export const useAuditLog = (params?: {
    page?: number;
    pageSize?: number;
    action?: string;
    projectId?: number;
    actor?: string;
    dateFrom?: string;
    dateTo?: string;
}) => {
    return useQuery({
        queryKey: ['audit-log', params],
        queryFn: async () => {
            const response = await apiClient.get('/api/v1/audit/logs', {
                params: {
                    page: params?.page ?? 1,
                    page_size: params?.pageSize ?? 100,
                    ...(params?.action ? { action: params.action } : {}),
                    ...(params?.projectId ? { project_id: params.projectId } : {}),
                    ...(params?.actor ? { actor: params.actor } : {}),
                    ...(params?.dateFrom ? { date_from: params.dateFrom } : {}),
                    ...(params?.dateTo ? { date_to: params.dateTo } : {}),
                },
            });
            const data = response.data.data;
            return {
                data: (data.logs ?? []) as AuditLogEntry[],
                total: data.total ?? 0,
                page: data.page ?? 1,
                pageSize: data.page_size ?? 100,
                totalPages: data.total_pages ?? 1,
            };
        },
    });
};

interface AuditFeedPage {
    logs: AuditLogEntry[];
    total?: number | undefined;
    totalExact?: boolean;
    nextCursor?: string;
}

/**
 * The audit list as a "load more" feed: the first page, then each further page
 * after the previous page's next_cursor (keyset paging, newest first; see
 * docs/specs/audit-list-keyset.md). Only the first page carries the total,
 * which is exact up to 10,000 and capped there (totalExact false).
 */
export interface AuditFeedParams {
    pageSize?: number;
    projectId?: number;
    /** Actor-name search (username or machine-identity name), done by the server (#4185). */
    actor?: string;
    /** 'user' | 'machine_identity' | 'system': the server's actor_type filter. */
    actorType?: string;
    /** Exact event type (the server's `action`). */
    eventType?: string;
}

export const useAuditLogFeed = (params?: AuditFeedParams) => {
    const query = useInfiniteQuery({
        queryKey: ['audit-log-feed', params],
        initialPageParam: '',
        queryFn: async ({ pageParam }): Promise<AuditFeedPage> => {
            // The filters are the server's, so a match is found however far back it is,
            // not only among the newest page loaded (#4185). The actor-name search lives
            // on /audit/search (it takes `actor`, not `actor_type`; the list endpoint
            // takes `actor_type`, not `actor`): pick the endpoint by the filters set.
            const byActor = !!params?.actor;
            const response = await apiClient.get(byActor ? '/api/v1/audit/search' : '/api/v1/audit/logs', {
                params: {
                    ...(byActor ? { limit: params?.pageSize ?? 100 } : { page_size: params?.pageSize ?? 100 }),
                    ...(params?.projectId ? { project_id: params.projectId } : {}),
                    ...(byActor ? { actor: params?.actor } : {}),
                    ...(!byActor && params?.actorType ? { actor_type: params.actorType } : {}),
                    ...(params?.eventType ? { action: params.eventType } : {}),
                    ...(pageParam ? { cursor: pageParam } : {}),
                },
            });
            const data = response.data.data ?? {};
            let logs = (data.logs ?? data.events ?? []) as AuditLogEntry[];
            // /audit/search has no actor_type parameter: that one is applied to the
            // already name-filtered rows (a small set), not to the newest page.
            if (byActor && params?.actorType) logs = logs.filter((e) => e.actor_type === params.actorType);
            return {
                logs,
                total: data.total,
                totalExact: data.total_exact,
                nextCursor: data.next_cursor ?? undefined,
            };
        },
        getNextPageParam: (last) => last.nextCursor || undefined,
        // Bounds what one tab keeps in memory: 100 pages (10,000 events at the
        // default page size). Beyond that the oldest pages loaded are dropped.
        maxPages: 100,
    });
    const pages = query.data?.pages ?? [];
    return {
        entries: pages.flatMap((p) => p.logs),
        total: pages[0]?.total,
        totalExact: pages[0]?.totalExact ?? true,
        isLoading: query.isLoading,
        error: query.error,
        isError: query.isError,
        hasNextPage: query.hasNextPage,
        isFetchingNextPage: query.isFetchingNextPage,
        fetchNextPage: query.fetchNextPage,
    };
};
