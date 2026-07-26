import React, { useState } from 'react';
import { BoltIcon } from '@heroicons/react/24/outline';
import { useRunAnomalyAlerts, useRunRotationReminders, useRunExpiryReminders, useRunComplianceDigest } from './api';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';

/**
 * Admin maintenance panel: dispatch the scheduled notification/alert jobs on demand
 * instead of waiting for the next background tick (server #394) — useful after an
 * incident or a config change. Lives inside the admin-only AdminPage; each button
 * POSTs to /api/v1/admin/jobs/* (system.write) and reports the result count.
 */
export const MaintenanceSection: React.FC = () => {
    const [note, setNote] = useState('');
    const [error, setError] = useState('');

    const anomaly = useRunAnomalyAlerts();
    const rotation = useRunRotationReminders();
    const expiry = useRunExpiryReminders();
    const compliance = useRunComplianceDigest();

    const run = (
        mutation: { mutate: (v: undefined, opts: object) => void; isPending: boolean },
        result: (r: any) => string
    ) => {
        setNote('');
        setError('');
        mutation.mutate(undefined, {
            onSuccess: (r: any) => setNote(result(r)),
            onError: (err: any) => setError(err?.response?.data?.error ?? err?.message ?? 'Job failed.'),
        });
    };

    const jobs = [
        { label: 'Anomaly alerts', m: anomaly, msg: (r: any) => `Broadcast ${r?.alerted ?? 0} anomaly alert(s).` },
        { label: 'Rotation reminders', m: rotation, msg: (r: any) => `Sent ${r?.sent ?? 0} rotation reminder(s).` },
        { label: 'Expiry reminders', m: expiry, msg: (r: any) => `Sent ${r?.sent ?? 0} expiry reminder(s).` },
        {
            label: 'Compliance digest',
            m: compliance,
            msg: (r: any) =>
                r?.sent ? 'Compliance digest sent.' : 'No compliance digest sent (no recipients/changes).',
        },
    ];

    return (
        <div
            className="rounded-lg border mb-4 p-4"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div className="flex items-center gap-2 mb-1">
                <BoltIcon className="h-5 w-5" style={{ color: 'var(--text-primary)' }} />
                <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Maintenance
                </h3>
            </div>
            <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
                Run a scheduled job now instead of waiting for its next tick.
            </p>

            {note && <Alert type="success" message={note} dismissible onDismiss={() => setNote('')} className="mb-3" />}
            {error && (
                <Alert type="error" message={error} dismissible onDismiss={() => setError('')} className="mb-3" />
            )}

            <div className="flex flex-wrap gap-2">
                {jobs.map(({ label, m, msg }) => (
                    <Button
                        key={label}
                        size="sm"
                        variant="outline"
                        loading={m.isPending}
                        disabled={m.isPending}
                        onClick={() => run(m, msg)}
                    >
                        {label}
                    </Button>
                ))}
            </div>
        </div>
    );
};
