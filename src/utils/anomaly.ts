// Shared helpers for rendering secret-access anomaly alerts.

const ALERT_TYPE_LABELS: Record<string, string> = {
    off_hours: 'Off-hours',
    new_ip: 'New IP',
    new_user: 'New user',
    frequency_spike: 'Frequency spike',
};

// humanizeAlertType turns a raw anomaly alert type (off_hours, frequency_spike, …)
// into a readable label; unknown types are Title-cased from their snake_case form.
export function humanizeAlertType(t: string): string {
    return (
        ALERT_TYPE_LABELS[t] ??
        t
            .split('_')
            .filter(Boolean)
            .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
            .join(' ')
    );
}
