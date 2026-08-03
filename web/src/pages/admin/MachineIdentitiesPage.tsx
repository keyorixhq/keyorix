import React, { useState } from 'react';
import { CpuChipIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';
import { useMachineIdentitiesAuditReport } from '../../features/admin';
import { lastUsedLabel } from '../../features/admin/tokenUtils';
import { apiClient } from '../../services/client';
import { triggerBlobDownload, formatDateShort } from '../../utils';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';

// ── Summary stat ─────────────────────────────────────────────────────────────

const StatCard: React.FC<{ label: string; value: number; tone?: string | undefined }> = ({ label, value, tone }) => (
    <div
        className="rounded-lg border px-4 py-3"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="text-2xl font-semibold" style={{ color: tone ?? 'var(--text-primary)' }}>
            {value}
        </div>
        <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {label}
        </div>
    </div>
);

/**
 * ADR-023 install-level Machine Identities view under Access Control. This is
 * a read-only, deployment-wide inventory backed by the machine-audit report —
 * there's no backend endpoint for cross-project management (create, suspend,
 * revoke, project assignment all stay project-scoped, on each project's
 * Members tab). This page answers "how many machine identities exist across
 * the install, and which ones are stale or revoked" — a hygiene/inventory
 * surface, not a CRUD console.
 */
export const MachineIdentitiesPage: React.FC = () => {
    const { data, isLoading, isError } = useMachineIdentitiesAuditReport();
    const [exportError, setExportError] = useState('');
    const [exporting, setExporting] = useState(false);

    const machines = data?.machines ?? [];

    const handleExport = async () => {
        setExportError('');
        setExporting(true);
        try {
            const res = await apiClient.get('/api/v1/machine-identities/audit.csv', { responseType: 'blob' });
            triggerBlobDownload(res.data as Blob, 'machine-identities-audit.csv');
        } catch (err: any) {
            setExportError(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Failed to export.');
        } finally {
            setExporting(false);
        }
    };

    const statusLabel = (m: { is_revoked: boolean; is_stale: boolean }) => {
        if (m.is_revoked) return 'Revoked';
        if (m.is_stale) return 'Stale';
        return 'Active';
    };

    const statusTone = (m: { is_revoked: boolean; is_stale: boolean }) => {
        if (m.is_revoked) return { bg: 'var(--bg-muted)', text: 'var(--text-muted)' };
        if (m.is_stale) return { bg: 'var(--warning-subtle)', text: 'var(--warning)' };
        return { bg: 'var(--success-subtle)', text: 'var(--success)' };
    };

    let listContent: React.ReactNode = null;
    if (isLoading) {
        listContent = <Loading className="py-20" />;
    } else if (!isError) {
        listContent =
            machines.length === 0 ? (
                <div className="text-center py-20" style={{ color: 'var(--text-muted)' }}>
                    <CpuChipIcon className="h-12 w-12 mx-auto mb-3 opacity-40" />
                    <p className="text-sm">No machine identities yet.</p>
                </div>
            ) : (
                <div
                    className="rounded-lg border overflow-hidden"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                >
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y" style={{ borderColor: 'var(--border)' }}>
                            <thead style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                <tr>
                                    {['Name', 'Credentials', 'Last used', 'Status', 'Created'].map((h) => (
                                        <th
                                            key={h}
                                            className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider"
                                            style={{ color: 'var(--text-muted)' }}
                                        >
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                                {machines.map((m) => {
                                    const tone = statusTone(m);
                                    return (
                                        <tr key={m.machine_id}>
                                            <td className="px-4 py-3 whitespace-nowrap">
                                                <div>
                                                    <p
                                                        className="text-sm font-medium"
                                                        style={{ color: 'var(--text-primary)' }}
                                                    >
                                                        {m.name}
                                                    </p>
                                                    {m.description && (
                                                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                                            {m.description}
                                                        </p>
                                                    )}
                                                </div>
                                            </td>
                                            <td
                                                className="px-4 py-3 whitespace-nowrap text-sm"
                                                style={{ color: 'var(--text-secondary)' }}
                                            >
                                                {m.credential_count}
                                            </td>
                                            <td
                                                className="px-4 py-3 whitespace-nowrap text-sm"
                                                style={{ color: 'var(--text-secondary)' }}
                                            >
                                                {lastUsedLabel(m.last_used_at)}
                                            </td>
                                            <td className="px-4 py-3 whitespace-nowrap">
                                                <span
                                                    className="px-2 py-0.5 rounded-full text-xs font-medium"
                                                    style={{ backgroundColor: tone.bg, color: tone.text }}
                                                >
                                                    {statusLabel(m)}
                                                </span>
                                            </td>
                                            <td
                                                className="px-4 py-3 whitespace-nowrap text-sm"
                                                style={{ color: 'var(--text-muted)' }}
                                            >
                                                {m.created_at ? formatDateShort(m.created_at) : '—'}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            );
    }

    return (
        <div className="max-w-6xl mx-auto px-4 py-8">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                        <CpuChipIcon className="h-6 w-6" />
                        Machine Identities
                    </h1>
                    <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
                        Deployment-wide inventory of non-human identities (CI runners, k8s workloads, automation).
                        Manage an individual identity — role, tokens, suspend, revoke — from its project's Members tab.
                    </p>
                </div>
                <button
                    type="button"
                    onClick={handleExport}
                    disabled={exporting}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm shrink-0 border transition-opacity disabled:opacity-50"
                    style={{ borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                >
                    <ArrowDownTrayIcon className="h-4 w-4" />
                    {exporting ? 'Exporting…' : 'Export CSV'}
                </button>
            </div>

            {exportError && <Alert type="error" message={exportError} className="mb-4" />}

            {isError && (
                <Alert
                    type="error"
                    title="Failed to load machine identities"
                    message="Check that you have admin access and the server is running."
                    className="mb-4"
                />
            )}

            {!isError && data && (
                <div className="grid grid-cols-3 gap-3 mb-6 max-w-md">
                    <StatCard label="Total" value={data.total_count} />
                    <StatCard
                        label="Stale"
                        value={data.stale_count}
                        tone={data.stale_count > 0 ? 'var(--warning)' : undefined}
                    />
                    <StatCard
                        label="Revoked"
                        value={data.revoked_count}
                        tone={data.revoked_count > 0 ? 'var(--text-muted)' : undefined}
                    />
                </div>
            )}

            {listContent}
        </div>
    );
};
