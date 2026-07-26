import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { secretsApi } from '../../services/secrets';
import { useDashboardStats, useAnomalyAlerts } from '../dashboard';
import { useRotationStatus } from './useRotationPolicies';
import { AnomalyAlert } from '../../types';

export function useSecretsHealth() {
    const {
        data: secretsData,
        isLoading: secretsLoading,
        error: secretsError,
    } = useQuery({
        queryKey: ['secrets', 'health-all'],
        queryFn: () => secretsApi.list({ pageSize: 500 }),
        staleTime: 2 * 60 * 1000,
    });

    const { data: stats, isLoading: statsLoading, error: statsError } = useDashboardStats();
    const { data: anomalyData, isLoading: anomalyLoading } = useAnomalyAlerts(true);
    const { entries: rotationEntries, isLoading: rotationLoading } = useRotationStatus();

    const metrics = useMemo(() => {
        const secrets = secretsData?.data ?? [];
        const total = secrets.length;
        const now = new Date();

        // ── Expiry ────────────────────────────────────────────────────────
        const expired = secrets.filter((s) => {
            if (!s.Expiration) return false;
            return new Date(s.Expiration) < now;
        }).length;

        const expiring7d = secrets.filter((s) => {
            if (!s.Expiration) return false;
            const d = Math.ceil((new Date(s.Expiration).getTime() - now.getTime()) / 86_400_000);
            return d >= 0 && d <= 7;
        }).length;

        const expiring30d = secrets.filter((s) => {
            if (!s.Expiration) return false;
            const d = Math.ceil((new Date(s.Expiration).getTime() - now.getTime()) / 86_400_000);
            return d > 7 && d <= 30;
        }).length;

        const healthyExpiry = total - expired - expiring7d - expiring30d;
        const expiryPct = total === 0 ? 100 : Math.round(((total - expired) / total) * 100);

        // ── Rotation ──────────────────────────────────────────────────────
        // Backed by the rotation-status endpoint (every policy-covered secret,
        // classified overdue/due_soon/ok). Unavailable only when no rotation
        // policy covers any secret, in which case it stays neutral in the score.
        const rotationCovered = rotationEntries.length;
        const rotationOverdue = rotationEntries.filter((e) => e.status === 'overdue').length;
        const rotationDueSoon = rotationEntries.filter((e) => e.status === 'due_soon').length;
        const rotationOk = rotationEntries.filter((e) => e.status === 'ok').length;
        const rotationAvailable = rotationCovered > 0;
        const rotationPct = rotationAvailable ? Math.round((rotationOk / rotationCovered) * 100) : 100; // neutral weight when no policy covers anything

        // ── Access ────────────────────────────────────────────────────────
        // Approximate: reads in last 30d vs total secrets count
        const reads30d = stats?.auditSecretReads30d ?? 0;
        const accessPct = total === 0 ? 100 : Math.min(100, Math.round((reads30d / total) * 100));

        // ── Overall score ─────────────────────────────────────────────────
        const score = Math.round(expiryPct * 0.4 + rotationPct * 0.3 + accessPct * 0.3);

        // ── Anomalies ─────────────────────────────────────────────────────
        const anomalyItems: AnomalyAlert[] = anomalyData?.data?.alerts ?? [];

        return {
            score,
            total,
            expiry: {
                expired,
                expiring7d,
                expiring30d,
                healthy: healthyExpiry,
                pct: expiryPct,
            },
            rotation: {
                available: rotationAvailable,
                pct: rotationPct,
                covered: rotationCovered,
                overdue: rotationOverdue,
                dueSoon: rotationDueSoon,
                ok: rotationOk,
                items: rotationEntries,
            },
            access: {
                reads30d,
                failedAuth24h: stats?.failedAuthAttempts24h ?? 0,
                inactiveUsers: stats?.inactiveUsers ?? 0,
                pct: accessPct,
            },
            anomalies: {
                count: anomalyItems.length,
                items: anomalyItems,
            },
        };
    }, [secretsData, stats, anomalyData, rotationEntries]);

    return {
        ...metrics,
        isLoading: secretsLoading || statsLoading || anomalyLoading || rotationLoading,
        error: secretsError ?? statsError ?? null,
    };
}
