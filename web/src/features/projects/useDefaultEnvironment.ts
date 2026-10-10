import { useQueries } from '@tanstack/react-query';
import { secretsApi } from '../../services/secrets';
import type { ProjectEnvironment } from '../../services/projects';

// Which environment a project's Secrets tab opens on when the URL names none.
//
// The old rule was "production, else the first": a project whose only secret lives
// in development opened on "No secrets in production / Create your first secret"
// (DEMO-WALK-3 findings 6 and 36), while the project list said "1 secret". The API
// has no per-environment counts, so ask for one row per environment and pick the
// first environment (production first, then the project's own order) that has any.
// If no environment has a secret, or a count could not be read, production stays the
// default, so a failing lookup can only fall back to the old behaviour.

const preferenceOrder = (envs: ProjectEnvironment[]): ProjectEnvironment[] => {
    const prod = envs.filter((e) => e.name.toLowerCase() === 'production');
    return [...prod, ...envs.filter((e) => e.name.toLowerCase() !== 'production')];
};

export interface DefaultEnvironment {
    /** The environment name to open on, or null while the counts are still loading. */
    name: string | null;
}

export function pickDefaultEnvironment(envs: ProjectEnvironment[], totals: (number | null)[]): string {
    const ordered = preferenceOrder(envs);
    const totalOf = new Map(envs.map((e, i) => [e.id, totals[i] ?? null] as const));
    const withSecrets = ordered.find((e) => (totalOf.get(e.id) ?? 0) > 0);
    return (withSecrets ?? ordered[0])?.name ?? 'production';
}

export function useDefaultEnvironment(
    projectId: number,
    environments: ProjectEnvironment[],
    enabled: boolean
): DefaultEnvironment {
    const results = useQueries({
        queries: environments.map((env) => ({
            queryKey: ['project-env-secret-count', projectId, env.id],
            queryFn: async () => {
                const page = await secretsApi.list({
                    page: 1,
                    pageSize: 1,
                    project_id: projectId,
                    environment_id: env.id,
                });
                return page.total;
            },
            enabled: enabled && projectId > 0,
            staleTime: 30_000,
            retry: false,
        })),
    });

    if (environments.length === 0) return { name: null };
    if (!enabled) return { name: pickDefaultEnvironment(environments, []) };
    if (results.some((r) => r.isLoading)) return { name: null };
    const totals = results.map((r) => (r.isSuccess ? r.data : null));
    return { name: pickDefaultEnvironment(environments, totals) };
}
