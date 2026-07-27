import React, { useState } from 'react';
import { ArrowDownTrayIcon } from '@heroicons/react/24/outline';
import { apiClient } from '../../services/client';
import { triggerBlobDownload } from '../../utils';

/**
 * Org-wide secret asset-inventory export (#369), the deployment-wide counterpart to the
 * per-project "Export inventory" on Project Settings. Downloads a CSV manifest of every
 * secret across all projects (metadata only — never values, ISO 27001 A.5.9) via an
 * authed blob fetch → object URL. Lives on the admin page (deployment-wide system.read);
 * a non-admin's request 403s and surfaces the error.
 */
export const OrgInventoryExport: React.FC = () => {
    const [msg, setMsg] = useState('');
    const [busy, setBusy] = useState(false);

    const handleExport = async () => {
        setMsg('');
        setBusy(true);
        try {
            const res = await apiClient.get('/api/v1/secrets/inventory.csv', { responseType: 'blob' });
            triggerBlobDownload(res.data as Blob, 'secret-inventory-all-projects.csv');
        } catch (err: any) {
            setMsg(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Failed to export inventory.');
        } finally {
            setBusy(false);
        }
    };

    return (
        <div
            className="rounded-lg border mb-4 p-4 flex items-center justify-between gap-3"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div className="min-w-0">
                <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                    Secret asset inventory (all projects)
                </p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    CSV manifest of every secret's metadata — names, projects, environments, classification, owners,
                    timestamps. Never values. For audit hand-off (ISO 27001 A.5.9).
                </p>
                {msg && (
                    <p className="text-xs mt-1" style={{ color: 'var(--error)' }}>
                        {msg}
                    </p>
                )}
            </div>
            <button
                type="button"
                onClick={handleExport}
                disabled={busy}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm shrink-0 border transition-opacity disabled:opacity-50"
                style={{ borderColor: 'var(--border)', color: 'var(--text-primary)' }}
            >
                <ArrowDownTrayIcon className="h-4 w-4" />
                {busy ? 'Exporting…' : 'Export inventory'}
            </button>
        </div>
    );
};
