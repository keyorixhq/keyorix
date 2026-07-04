import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient, useMutation, useQuery } from '@tanstack/react-query';
import { TrashIcon, PlusIcon, ArrowPathIcon, ArrowUpOnSquareIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';
import { useProject, useProjectEnvironments, useRestoreEnvironment, PROJECT_KEYS } from '../../features/projects/api';
import { apiClient } from '../../services/client';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { ROUTES } from '../../constants';

interface ProjectSettingsTabProps {
    projectId: number;
}

interface Env { id: number; name: string; deleted?: boolean; }

export const ProjectSettingsTab: React.FC<ProjectSettingsTabProps> = ({ projectId }) => {
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { data: project, isLoading: projectLoading } = useProject(projectId);
    // Include soft-deleted environments here so they can be restored.
    const { data: environments = [], isLoading: envsLoading } = useProjectEnvironments(projectId, true);
    const restoreEnvMutation = useRestoreEnvironment(projectId);

    // ── General ───────────────────────────────────────────────────────────
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [nameError, setNameError] = useState('');

    React.useEffect(() => {
        if (project) { setName(project.name); setDescription(project.description ?? ''); }
    }, [project]);

    const updateMutation = useMutation({
        mutationFn: (body: { name: string; description?: string }) =>
            apiClient.put(`/api/v1/projects/${projectId}`, body),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
        },
    });

    const handleSave = () => {
        if (!name.trim()) { setNameError('Name is required.'); return; }
        setNameError('');
        updateMutation.mutate({ name: name.trim(), ...(description.trim() ? { description: description.trim() } : {}) });
    };

    // ── Environments ──────────────────────────────────────────────────────
    const [newEnvName, setNewEnvName] = useState('');
    const [addEnvError, setAddEnvError] = useState('');
    const [envToDelete, setEnvToDelete] = useState<Env | null>(null);
    const [deleteEnvError, setDeleteEnvError] = useState('');

    const addEnvMutation = useMutation({
        mutationFn: (envName: string) =>
            apiClient.post(`/api/v1/projects/${projectId}/environments`, { name: envName }),
        onSuccess: () => {
            setNewEnvName(''); setAddEnvError('');
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
        },
        onError: (err: any) => {
            setAddEnvError(err?.response?.data?.error ?? err?.response?.data?.message ?? 'Failed to create environment.');
        },
    });

    const deleteEnvMutation = useMutation({
        mutationFn: (envId: number) => apiClient.delete(`/api/v1/environments/${envId}`),
        onSuccess: () => {
            setEnvToDelete(null); setDeleteEnvError('');
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
        onError: (err: any) => {
            setDeleteEnvError(
                err?.response?.data?.error ?? err?.response?.data?.message ?? 'Failed to delete environment.'
            );
        },
    });

    const closeDeleteEnvModal = () => {
        setEnvToDelete(null);
        setDeleteEnvError('');
        deleteEnvMutation.reset();
    };

    // Promote: bulk-copy every secret from one environment into another, same project
    // (e.g. seed production from staging). Name clashes are skipped, never clobbered (server #363).
    const [promoteMsg, setPromoteMsg] = useState('');
    const promoteEnvMutation = useMutation({
        mutationFn: (vars: { sourceId: number; targetId: number }) =>
            apiClient.post(`/api/v1/projects/${projectId}/environments/${vars.sourceId}/copy-secrets`, {
                target_environment_id: vars.targetId,
            }),
        onSuccess: (res: any) => {
            const d = res?.data?.data ?? {};
            setPromoteMsg(`Promoted: ${d.copied ?? 0} copied, ${d.skipped ?? 0} skipped (name clashes).`);
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
        onError: (err: any) => {
            setPromoteMsg(err?.response?.data?.error ?? err?.response?.data?.message ?? 'Failed to promote environment.');
        },
    });

    const handlePromote = (source: Env) => {
        const raw = window.prompt(
            `Promote all secrets from "${source.name}" into which environment?\nEnter the target environment ID (same project):`
        );
        if (raw == null) return;
        const targetId = parseInt(raw.trim(), 10);
        if (!Number.isInteger(targetId) || targetId <= 0) {
            setPromoteMsg('Enter a valid environment ID.');
            return;
        }
        if (targetId === source.id) {
            setPromoteMsg('Source and target environments must differ.');
            return;
        }
        setPromoteMsg('');
        promoteEnvMutation.mutate({ sourceId: source.id, targetId });
    };

    // Compliance: download the project's secret asset inventory as CSV (metadata only,
    // never values — ISO 27001 A.5.9). Authed blob fetch → object URL → download (server #367).
    const [inventoryMsg, setInventoryMsg] = useState('');
    const [inventoryBusy, setInventoryBusy] = useState(false);
    const handleExportInventory = async () => {
        setInventoryMsg('');
        setInventoryBusy(true);
        try {
            const res = await apiClient.get(`/api/v1/projects/${projectId}/secrets/inventory.csv`, { responseType: 'blob' });
            const url = URL.createObjectURL(res.data as Blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `secret-inventory-project-${projectId}.csv`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (err: any) {
            setInventoryMsg(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Failed to export inventory.');
        } finally {
            setInventoryBusy(false);
        }
    };

    // ── Project deletion ──────────────────────────────────────────────────
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [deleteConfirm, setDeleteConfirm] = useState('');

    const deleteProjectMutation = useMutation({
        mutationFn: () => apiClient.delete(`/api/v1/projects/${projectId}`),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: PROJECT_KEYS.all });
            navigate(ROUTES.PROJECTS);
        },
    });

    // Incident-response: freeze / thaw every secret in the project (server #317).
    const [freezeMsg, setFreezeMsg] = useState('');
    const suspendAllMutation = useMutation({
        mutationFn: () => apiClient.post(`/api/v1/projects/${projectId}/secrets/suspend-all`, {}),
        onSuccess: (res: any) => {
            setFreezeMsg(`Froze ${res?.data?.data?.suspended ?? 0} secret(s) — value reads are blocked.`);
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
    });
    const resumeAllMutation = useMutation({
        mutationFn: () => apiClient.post(`/api/v1/projects/${projectId}/secrets/resume-all`, {}),
        onSuccess: (res: any) => {
            setFreezeMsg(`Resumed ${res?.data?.data?.resumed ?? 0} secret(s) — value reads are restored.`);
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
    });

    // Hygiene posture: one-call counts of the project's cleanup signals (server #338).
    interface Hygiene { orphaned_secrets: number; unused_secrets: number; expiring_secrets: number; stale_machine_identities: number; rotation_overdue: number; }
    const { data: hygiene } = useQuery<Hygiene>({
        queryKey: ['project-hygiene', projectId],
        queryFn: async () => {
            const res = await apiClient.get(`/api/v1/projects/${projectId}/hygiene`);
            return res?.data?.data ?? { orphaned_secrets: 0, unused_secrets: 0, expiring_secrets: 0, stale_machine_identities: 0, rotation_overdue: 0 };
        },
    });

    // Expiring secrets: expiring/expired within the window, soonest-first (server #343).
    interface ExpiringSecret { id: number; name: string; type: string; expiration?: string; expired: boolean; }
    const { data: expiringSecrets = [] } = useQuery<ExpiringSecret[]>({
        queryKey: ['project-expiring-secrets', projectId],
        queryFn: async () => {
            const res = await apiClient.get(`/api/v1/projects/${projectId}/secrets/expiring`);
            return res?.data?.data?.expiring ?? [];
        },
    });
    // Bulk-renew: push out the expiry of every expiring/expired secret in one call (server #368).
    const [extendMsg, setExtendMsg] = useState('');
    const extendExpiringMutation = useMutation({
        mutationFn: () => apiClient.post(`/api/v1/projects/${projectId}/secrets/extend-expiring`, {}),
        onSuccess: (res: any) => {
            setExtendMsg(`Renewed ${res?.data?.data?.extended ?? 0} secret(s) for 90 days.`);
            queryClient.invalidateQueries({ queryKey: ['project-expiring-secrets', projectId] });
            queryClient.invalidateQueries({ queryKey: ['project-hygiene', projectId] });
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
    });

    // Naming-policy conformance: live secrets whose names violate the current naming
    // policy (server #371). The policy is enforced only at create, so tightening it
    // later leaves stragglers — surface them for renaming. Empty when policy is off.
    interface NameViolation { id: number; name: string; type: string; reason: string; }
    interface NameConformance { policy_enabled: boolean; total_secrets: number; violations: NameViolation[]; }
    const { data: nameConformance } = useQuery<NameConformance>({
        queryKey: ['project-name-conformance', projectId],
        queryFn: async () => {
            const res = await apiClient.get(`/api/v1/projects/${projectId}/secrets/name-conformance`);
            return res?.data?.data ?? { policy_enabled: false, total_secrets: 0, violations: [] };
        },
    });
    const nameViolations = nameConformance?.violations ?? [];

    // Rename violators toward conformance (server #386). Each row gets an editable name
    // input (prefilled with the current name); "Apply renames" POSTs only the edited
    // rows. The server validates each new name against the policy and skips any that
    // still don't conform (or collide), reporting a reason — surfaced back here.
    const [renameInputs, setRenameInputs] = useState<Record<number, string>>({});
    const [bulkRenameMsg, setBulkRenameMsg] = useState('');
    const bulkRenameMutation = useMutation({
        mutationFn: (renames: Array<{ id: number; new_name: string }>) =>
            apiClient.post(`/api/v1/projects/${projectId}/secrets/bulk-rename`, { renames, dry_run: false }),
        onSuccess: (res: any) => {
            const d = res?.data?.data ?? {};
            const skips = (d.outcomes ?? []).filter((o: any) => o.status === 'skipped');
            const detail = skips.length
                ? ` Skipped: ${skips.map((o: any) => `${o.old_name || o.id} (${o.reason})`).join('; ')}.`
                : '';
            setBulkRenameMsg(`Renamed ${d.renamed ?? 0} secret(s), ${d.skipped ?? 0} skipped.${detail}`);
            setRenameInputs({});
            queryClient.invalidateQueries({ queryKey: ['project-name-conformance', projectId] });
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
        onError: (err: any) => {
            setBulkRenameMsg(`Error: ${err?.response?.data?.error ?? err?.message ?? 'Failed to rename.'}`);
        },
    });
    // The rows whose name input has actually been changed to a non-empty new value.
    const pendingRenames = nameViolations
        .map(v => ({ id: v.id, old_name: v.name, new_name: (renameInputs[v.id] ?? v.name).trim() }))
        .filter(r => r.new_name !== '' && r.new_name !== r.old_name)
        .map(({ id, new_name }) => ({ id, new_name }));

    // Recycle bin: soft-deleted (restorable) secrets in this project (server #323).
    interface DeletedSecret { id: number; name: string; type: string; classification?: string; deleted_at?: string; }
    const { data: deletedSecrets = [] } = useQuery<DeletedSecret[]>({
        queryKey: ['project-deleted-secrets', projectId],
        queryFn: async () => {
            const res = await apiClient.get(`/api/v1/projects/${projectId}/secrets/deleted`);
            return res?.data?.data?.deleted ?? [];
        },
    });
    const restoreSecretMutation = useMutation({
        mutationFn: (secretId: number) => apiClient.post(`/api/v1/secrets/${secretId}/restore`, {}),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['project-deleted-secrets', projectId] });
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
    });

    // Orphaned secrets: live secrets whose owner is no longer a live user (server #326).
    interface OrphanedSecret { id: number; name: string; type: string; classification?: string; owner_id: number; }
    const { data: orphanedSecrets = [] } = useQuery<OrphanedSecret[]>({
        queryKey: ['project-orphaned-secrets', projectId],
        queryFn: async () => {
            const res = await apiClient.get(`/api/v1/projects/${projectId}/secrets/orphaned`);
            return res?.data?.data?.orphaned ?? [];
        },
    });
    const [reassignMsg, setReassignMsg] = useState('');
    const reassignOwnerMutation = useMutation({
        mutationFn: (vars: { from: number; to: number }) =>
            apiClient.post(`/api/v1/projects/${projectId}/secrets/reassign-owner`, { from_owner_id: vars.from, to_owner_id: vars.to }),
        onSuccess: (res: any) => {
            setReassignMsg(`Reassigned ${res?.data?.data?.reassigned ?? 0} secret(s).`);
            queryClient.invalidateQueries({ queryKey: ['project-orphaned-secrets', projectId] });
            queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
        },
    });
    // Distinct former owners across the orphaned secrets, for the per-owner "Reassign all".
    const orphanedOwners = Array.from(new Set(orphanedSecrets.map(s => s.owner_id)));

    if (projectLoading) {
        return (
            <div className="space-y-3 animate-pulse">
                {[1, 2].map(i => (
                    <div key={i} className="h-12 rounded-lg" style={{ backgroundColor: 'var(--bg-muted)' }} />
                ))}
            </div>
        );
    }

    return (
        <div className="space-y-8 max-w-2xl">

            {/* ── Hygiene posture ── */}
            {hygiene && (
                <section>
                    <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Hygiene</h2>
                    <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                        Outstanding cleanup signals for this project. Zero across the board is healthy.
                    </p>
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                        {([
                            ['Orphaned secrets', hygiene.orphaned_secrets],
                            ['Unused secrets', hygiene.unused_secrets],
                            ['Expiring secrets', hygiene.expiring_secrets],
                            ['Stale machine IDs', hygiene.stale_machine_identities],
                            ['Rotation overdue', hygiene.rotation_overdue],
                        ] as [string, number][]).map(([label, count]) => (
                            <div
                                key={label}
                                className="rounded-lg border p-3"
                                style={{
                                    borderColor: count > 0 ? 'var(--warning, #d97706)' : 'var(--border)',
                                    backgroundColor: count > 0 ? 'var(--warning-subtle, #fffbeb)' : 'var(--bg-surface)',
                                }}
                            >
                                <div className="text-2xl font-semibold" style={{ color: count > 0 ? 'var(--warning, #92400e)' : 'var(--text-primary)' }}>
                                    {count}
                                </div>
                                <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{label}</div>
                            </div>
                        ))}
                    </div>
                </section>
            )}

            {/* ── General ── */}
            <section>
                <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>General</h2>
                <div className="rounded-lg border p-5 space-y-4"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    {updateMutation.isError && (
                        <Alert type="error" title="Failed to update" message="Could not save project settings." />
                    )}
                    {updateMutation.isSuccess && (
                        <Alert type="success" title="Saved" message="Project settings updated." />
                    )}
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            Project name <span style={{ color: 'var(--error)' }}>*</span>
                        </label>
                        <input type="text" value={name} onChange={e => setName(e.target.value)}
                            className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                color: 'var(--text-primary)',
                                borderColor: nameError ? 'var(--error)' : 'var(--border)',
                            }} />
                        {nameError && <p className="text-xs mt-1" style={{ color: 'var(--error)' }}>{nameError}</p>}
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            Description
                        </label>
                        <input type="text" value={description} onChange={e => setDescription(e.target.value)}
                            placeholder="Optional"
                            className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
                            style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }} />
                    </div>
                    <div className="flex justify-end">
                        <Button onClick={handleSave} disabled={updateMutation.isPending}>
                            {updateMutation.isPending ? 'Saving…' : 'Save'}
                        </Button>
                    </div>
                </div>
            </section>

            {/* ── Environments ── */}
            <section>
                <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Environments</h2>
                <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                    Environments group secrets by deployment stage. An environment with active secrets cannot be
                    deleted — move or delete its secrets first.
                </p>
                <div className="rounded-lg border"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>

                    {/* Environment list */}
                    {envsLoading ? (
                        <div className="p-4 animate-pulse space-y-2">
                            {[1, 2, 3].map(i => (
                                <div key={i} className="h-8 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                            ))}
                        </div>
                    ) : environments.length === 0 ? (
                        <div className="px-4 py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                            No environments yet. Add one below.
                        </div>
                    ) : (
                        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                            {(environments as Env[]).map(env => {
                                const isDefault = ['development', 'staging', 'production'].includes(
                                    env.name.toLowerCase()
                                );
                                return (
                                    <li key={env.id} className="flex items-center justify-between px-4 py-3 group"
                                        style={{ opacity: env.deleted ? 0.7 : 1 }}>
                                        <div className="flex items-center gap-2">
                                            <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
                                                {env.name.charAt(0).toUpperCase() + env.name.slice(1)}
                                            </span>
                                            {env.deleted ? (
                                                <span className="text-[10px] px-1.5 py-0.5 rounded-sm font-semibold uppercase tracking-wide"
                                                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}>
                                                    deleted
                                                </span>
                                            ) : isDefault && (
                                                <span className="text-xs px-1.5 py-0.5 rounded-sm"
                                                    style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-muted)' }}>
                                                    default
                                                </span>
                                            )}
                                        </div>
                                        {env.deleted ? (
                                            <button
                                                type="button"
                                                onClick={() => restoreEnvMutation.mutate(env.id)}
                                                disabled={restoreEnvMutation.isPending}
                                                className="flex items-center gap-1 p-1.5 rounded-sm text-sm transition-opacity disabled:opacity-50"
                                                style={{ color: 'var(--accent)' }}
                                                title="Restore environment"
                                            >
                                                <ArrowPathIcon className="h-4 w-4" />Restore
                                            </button>
                                        ) : (
                                            <div className="flex items-center gap-1">
                                                <button
                                                    type="button"
                                                    onClick={() => handlePromote(env)}
                                                    disabled={promoteEnvMutation.isPending}
                                                    className="flex items-center gap-1 px-1.5 py-1 rounded-sm text-xs opacity-0 group-hover:opacity-100 transition-opacity disabled:opacity-50"
                                                    style={{ color: 'var(--accent)' }}
                                                    title="Promote — copy every secret in this environment into another"
                                                >
                                                    <ArrowUpOnSquareIcon className="h-4 w-4" />Promote
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => { setDeleteEnvError(''); setEnvToDelete(env); }}
                                                    className="p-1.5 rounded-sm opacity-0 group-hover:opacity-100 transition-opacity hover:bg-red-50"
                                                    style={{ color: 'var(--error)' }}
                                                    title="Delete environment"
                                                >
                                                    <TrashIcon className="h-4 w-4" />
                                                </button>
                                            </div>
                                        )}
                                    </li>
                                );
                            })}
                        </ul>
                    )}

                    {/* Add environment */}
                    <div className="border-t px-4 py-3" style={{ borderColor: 'var(--border)' }}>
                        {promoteMsg && (
                            <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>{promoteMsg}</p>
                        )}
                        {addEnvError && (
                            <p className="text-xs mb-2" style={{ color: 'var(--error)' }}>{addEnvError}</p>
                        )}
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={newEnvName}
                                onChange={e => { setNewEnvName(e.target.value); setAddEnvError(''); }}
                                onKeyDown={e => {
                                    if (e.key === 'Enter' && newEnvName.trim())
                                        addEnvMutation.mutate(newEnvName.trim());
                                }}
                                placeholder="New environment name…"
                                className="flex-1 rounded-lg border px-3 py-1.5 text-sm outline-hidden focus:ring-2 focus:ring-blue-500"
                                style={{
                                    backgroundColor: 'var(--bg-app)',
                                    color: 'var(--text-primary)',
                                    borderColor: 'var(--border)',
                                }}
                            />
                            <Button
                                size="sm"
                                onClick={() => newEnvName.trim() && addEnvMutation.mutate(newEnvName.trim())}
                                disabled={!newEnvName.trim() || addEnvMutation.isPending}
                            >
                                <PlusIcon className="h-4 w-4 mr-1" />Add
                            </Button>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── Compliance ── */}
            <section>
                <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Compliance</h2>
                <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                    Export an asset inventory of this project's secrets (metadata only — names, environments,
                    classification, owners, timestamps; never values) for audit hand-off (ISO 27001 A.5.9).
                </p>
                <div className="rounded-lg border p-4 flex items-center justify-between gap-3"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    <div className="min-w-0">
                        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Secret inventory (CSV)</p>
                        {inventoryMsg && <p className="text-xs mt-0.5" style={{ color: 'var(--error)' }}>{inventoryMsg}</p>}
                    </div>
                    <Button size="sm" variant="outline" onClick={handleExportInventory} disabled={inventoryBusy}>
                        <ArrowDownTrayIcon className="h-4 w-4 mr-1" />{inventoryBusy ? 'Exporting…' : 'Export inventory'}
                    </Button>
                </div>
            </section>

            {/* ── Incident response ── */}
            <section>
                <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Incident response</h2>
                <div className="rounded-lg border p-5 space-y-3"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Freeze blocks value reads of every secret in this project (versions and shares are
                        preserved); resume restores them. Use during incident response.
                    </p>
                    {(suspendAllMutation.isError || resumeAllMutation.isError) && (
                        <Alert type="error" title="Error" message="The action failed. Please try again." />
                    )}
                    {freezeMsg && <Alert type="success" title="Done" message={freezeMsg} />}
                    <div className="flex gap-2">
                        <Button
                            variant="outline"
                            disabled={suspendAllMutation.isPending}
                            onClick={() => {
                                if (window.confirm('Freeze ALL secrets in this project? Value reads will be blocked until you resume them.')) {
                                    setFreezeMsg('');
                                    suspendAllMutation.mutate();
                                }
                            }}
                        >
                            {suspendAllMutation.isPending ? 'Freezing…' : 'Freeze all secrets'}
                        </Button>
                        <Button
                            variant="outline"
                            disabled={resumeAllMutation.isPending}
                            onClick={() => { setFreezeMsg(''); resumeAllMutation.mutate(); }}
                        >
                            {resumeAllMutation.isPending ? 'Resuming…' : 'Resume all'}
                        </Button>
                    </div>
                </div>
            </section>

            {/* ── Orphaned secrets ── (only when present; it's an alert) */}
            {orphanedSecrets.length > 0 && (
                <section>
                    <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Orphaned secrets</h2>
                    <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                        These secrets are owned by a user who no longer exists (offboarded). Re-home a former
                        owner's secrets in bulk below, or open a secret to transfer it individually.
                    </p>
                    {reassignOwnerMutation.isError && (
                        <Alert type="error" title="Reassignment failed" message="Could not reassign ownership. Check the new owner's user ID." />
                    )}
                    {reassignMsg && <Alert type="success" title="Done" message={reassignMsg} />}
                    <div className="rounded-lg border"
                        style={{ borderColor: 'var(--warning, #a16207)', backgroundColor: 'var(--warning-subtle, #fef9c3)' }}>
                        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                            {orphanedSecrets.map(s => (
                                <li key={s.id} className="flex items-center justify-between px-4 py-3">
                                    <div className="min-w-0">
                                        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{s.name}</span>
                                        <span className="text-xs ml-2" style={{ color: 'var(--text-muted)' }}>
                                            {s.type} · former owner #{s.owner_id}
                                        </span>
                                    </div>
                                    {s.classification && (
                                        <span className="text-[10px] px-1.5 py-0.5 rounded-sm font-semibold uppercase tracking-wide"
                                            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-muted)' }}>
                                            {s.classification}
                                        </span>
                                    )}
                                </li>
                            ))}
                        </ul>
                        {/* Bulk re-home, one action per distinct former owner. */}
                        <div className="border-t px-4 py-3 space-y-2" style={{ borderColor: 'var(--border)' }}>
                            {orphanedOwners.map(ownerId => (
                                <button
                                    key={ownerId}
                                    type="button"
                                    disabled={reassignOwnerMutation.isPending}
                                    onClick={() => {
                                        const input = window.prompt(`Reassign all secrets from former owner #${ownerId} to which user ID?`);
                                        const to = Number(input);
                                        if (!input || !Number.isInteger(to) || to <= 0) return;
                                        setReassignMsg('');
                                        reassignOwnerMutation.mutate({ from: ownerId, to });
                                    }}
                                    className="flex items-center gap-1 text-sm font-medium disabled:opacity-50"
                                    style={{ color: 'var(--accent)' }}
                                >
                                    <ArrowPathIcon className="h-4 w-4" />Reassign all from former owner #{ownerId}…
                                </button>
                            ))}
                        </div>
                    </div>
                </section>
            )}

            {/* ── Expiring secrets ── (only when present) */}
            {expiringSecrets.length > 0 && (
                <section>
                    <div className="flex items-center justify-between mb-1">
                        <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Expiring secrets</h2>
                        <Button size="sm" variant="outline" onClick={() => { setExtendMsg(''); extendExpiringMutation.mutate(); }} disabled={extendExpiringMutation.isPending}>
                            <ArrowPathIcon className="h-4 w-4 mr-1" />{extendExpiringMutation.isPending ? 'Renewing…' : 'Extend all (90d)'}
                        </Button>
                    </div>
                    <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                        Secrets expiring soon or already expired — renew or rotate them before they lapse.
                    </p>
                    {extendMsg && <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>{extendMsg}</p>}
                    <div className="rounded-lg border"
                        style={{ borderColor: 'var(--warning, #a16207)', backgroundColor: 'var(--warning-subtle, #fef9c3)' }}>
                        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                            {expiringSecrets.map(s => (
                                <li key={s.id} className="flex items-center justify-between px-4 py-3">
                                    <div className="min-w-0">
                                        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{s.name}</span>
                                        <span className="text-xs ml-2" style={{ color: 'var(--text-muted)' }}>
                                            {s.type}{s.expiration ? ` · ${new Date(s.expiration).toLocaleDateString()}` : ''}
                                        </span>
                                    </div>
                                    <span className="text-[10px] px-1.5 py-0.5 rounded-sm font-semibold uppercase tracking-wide"
                                        style={s.expired
                                            ? { backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }
                                            : { backgroundColor: 'var(--bg-subtle)', color: 'var(--text-muted)' }}>
                                        {s.expired ? 'expired' : 'expiring'}
                                    </span>
                                </li>
                            ))}
                        </ul>
                    </div>
                </section>
            )}

            {/* ── Naming-policy violations ── (only when the policy flags existing names) */}
            {nameViolations.length > 0 && (
                <section>
                    <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Naming-policy violations</h2>
                    <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                        These secret names don't match the current naming policy. The policy is enforced when a
                        secret is created, so names from before it was added or tightened need renaming to conform.
                    </p>
                    <div className="rounded-lg border"
                        style={{ borderColor: 'var(--warning, #a16207)', backgroundColor: 'var(--warning-subtle, #fef9c3)' }}>
                        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                            {nameViolations.map(v => (
                                <li key={v.id} className="px-4 py-3">
                                    <div className="flex items-center justify-between gap-3">
                                        <div className="min-w-0 flex items-center gap-2">
                                            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{v.type}</span>
                                            <input
                                                type="text"
                                                aria-label={`New name for ${v.name}`}
                                                className="text-sm px-2 py-1 rounded-sm border w-56"
                                                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-base)', color: 'var(--text-primary)' }}
                                                value={renameInputs[v.id] ?? v.name}
                                                onChange={e => setRenameInputs(prev => ({ ...prev, [v.id]: e.target.value }))}
                                            />
                                        </div>
                                        <span className="text-xs ml-3 truncate" style={{ color: 'var(--error)' }}>{v.reason}</span>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    </div>
                    <div className="flex items-center gap-3 mt-3">
                        <Button
                            variant="secondary"
                            disabled={pendingRenames.length === 0 || bulkRenameMutation.isPending}
                            onClick={() => bulkRenameMutation.mutate(pendingRenames)}
                        >
                            {bulkRenameMutation.isPending ? 'Renaming…' : `Apply renames (${pendingRenames.length})`}
                        </Button>
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            Edit a name above, then apply. Names that still don't conform are skipped.
                        </span>
                    </div>
                    {bulkRenameMsg && (
                        <div className="mt-3">
                            <Alert
                                type={bulkRenameMsg.startsWith('Error') ? 'error' : 'success'}
                                title={bulkRenameMsg.startsWith('Error') ? 'Rename failed' : 'Done'}
                                message={bulkRenameMsg}
                            />
                        </div>
                    )}
                </section>
            )}

            {/* ── Recycle bin ── */}
            <section>
                <h2 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Recycle bin</h2>
                <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                    Deleted secrets stay restorable until the retention window expires. Restore one to return it
                    to the live list.
                </p>
                <div className="rounded-lg border"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                    {deletedSecrets.length === 0 ? (
                        <div className="px-4 py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                            Recycle bin is empty.
                        </div>
                    ) : (
                        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                            {deletedSecrets.map(s => (
                                <li key={s.id} className="flex items-center justify-between px-4 py-3">
                                    <div className="min-w-0">
                                        <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{s.name}</span>
                                        <span className="text-xs ml-2" style={{ color: 'var(--text-muted)' }}>
                                            {s.type}{s.deleted_at ? ` · deleted ${new Date(s.deleted_at).toLocaleDateString()}` : ''}
                                        </span>
                                    </div>
                                    <button
                                        type="button"
                                        onClick={() => restoreSecretMutation.mutate(s.id)}
                                        disabled={restoreSecretMutation.isPending}
                                        className="flex items-center gap-1 p-1.5 rounded-sm text-sm transition-opacity disabled:opacity-50"
                                        style={{ color: 'var(--accent)' }}
                                        title="Restore secret"
                                    >
                                        <ArrowPathIcon className="h-4 w-4" />Restore
                                    </button>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            </section>

            {/* ── Danger zone ── */}
            <section>
                <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--error)' }}>Danger Zone</h2>
                <div className="rounded-lg border p-5 flex items-center justify-between"
                    style={{ borderColor: 'var(--error)', backgroundColor: 'var(--error-subtle)' }}>
                    <div>
                        <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                            Delete this project
                        </p>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            Permanently deletes the project and all its secrets. This cannot be undone.
                        </p>
                    </div>
                    <Button variant="destructive" onClick={() => setShowDeleteModal(true)}>Delete Project</Button>
                </div>
            </section>

            {/* ── Delete environment modal ── */}
            <Modal
                isOpen={envToDelete !== null}
                onClose={closeDeleteEnvModal}
                title="Delete Environment"
                size="sm"
            >
                <div className="space-y-4">
                    {deleteEnvError ? (
                        <Alert type="error" title="Cannot delete environment" message={deleteEnvError} />
                    ) : (
                        <div className="space-y-2">
                            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                Delete environment{' '}
                                <span className="font-semibold">{envToDelete?.name}</span>?
                            </p>
                            {['development', 'staging', 'production'].includes(
                                envToDelete?.name?.toLowerCase() ?? ''
                            ) && (
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                    This is a default environment. It will be soft-deleted and can be
                                    recreated at any time.
                                </p>
                            )}
                        </div>
                    )}
                    <div className="flex justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button variant="outline" onClick={closeDeleteEnvModal}>
                            {deleteEnvError ? 'Close' : 'Cancel'}
                        </Button>
                        {!deleteEnvError && (
                            <Button
                                variant="destructive"
                                disabled={deleteEnvMutation.isPending}
                                onClick={() => envToDelete && deleteEnvMutation.mutate(envToDelete.id)}
                            >
                                {deleteEnvMutation.isPending ? 'Deleting…' : 'Delete'}
                            </Button>
                        )}
                    </div>
                </div>
            </Modal>

            {/* ── Delete project modal ── */}
            <Modal
                isOpen={showDeleteModal}
                onClose={() => { setShowDeleteModal(false); setDeleteConfirm(''); }}
                title="Delete Project"
                size="sm"
            >
                <div className="space-y-4">
                    {deleteProjectMutation.isError && (
                        <Alert type="error" title="Failed to delete"
                            message={(deleteProjectMutation.error as any)?.response?.data?.error
                                ?? (deleteProjectMutation.error as any)?.message
                                ?? 'Could not delete the project.'} />
                    )}
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Delete project <span className="font-semibold">{project?.name}</span>?
                        The project, its environments, and all its secrets will be soft-deleted.
                        Type the project name to confirm.
                    </p>
                    <input
                        type="text"
                        value={deleteConfirm}
                        onChange={e => setDeleteConfirm(e.target.value)}
                        placeholder={project?.name}
                        className="w-full rounded-lg border px-3 py-2 text-sm outline-hidden"
                        style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border)' }}
                    />
                    <div className="flex justify-end gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <Button variant="outline" onClick={() => { setShowDeleteModal(false); setDeleteConfirm(''); }}>
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            disabled={deleteConfirm !== project?.name || deleteProjectMutation.isPending}
                            onClick={() => deleteProjectMutation.mutate()}
                        >
                            {deleteProjectMutation.isPending ? 'Deleting…' : 'Delete'}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
