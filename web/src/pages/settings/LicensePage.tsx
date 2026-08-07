import React from 'react';
import { useLicenseStatus } from '../../features/license';
import { Spinner } from '../../components/ui';
import type { LicenseState } from '../../services/license';

// Friendly labels for known commercial feature keys (internal/license/features.go).
// Falls back to the raw key for a feature this build doesn't recognize yet, so an
// unmapped future feature still renders instead of disappearing.
const FEATURE_LABELS: Record<string, string> = {
    airgap_updates: 'Air-gap update bundles',
    billing: 'FinOps billing reports',
};

const STATE_META: Record<LicenseState, { label: string; color: string; bg: string }> = {
    active: { label: 'Active', color: 'var(--success)', bg: 'var(--success-subtle)' },
    expiring_soon: { label: 'Expiring soon', color: 'var(--warning)', bg: 'var(--warning-subtle)' },
    expired: { label: 'Expired', color: 'var(--error)', bg: 'var(--error-subtle)' },
    invalid: { label: 'Invalid', color: 'var(--error)', bg: 'var(--error-subtle)' },
    none: { label: 'Community baseline', color: 'var(--text-muted)', bg: 'var(--bg-muted)' },
};

interface SectionProps {
    title: string;
    note?: string;
    children: React.ReactNode;
}

const Section: React.FC<SectionProps> = ({ title, note, children }) => (
    <div
        className="rounded-xl border overflow-hidden mb-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                {title}
            </h2>
        </div>
        <div className="px-6 py-5 space-y-3">
            {children}
            {note && (
                <p className="text-xs pt-1" style={{ color: 'var(--text-muted)' }}>
                    {note}
                </p>
            )}
        </div>
    </div>
);

const Row: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
    <div className="flex items-center justify-between gap-4">
        <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
            {label}
        </span>
        <span className="text-sm font-medium text-right" style={{ color: 'var(--text-primary)' }}>
            {value}
        </span>
    </div>
);

const StateBadge: React.FC<{ state: LicenseState }> = ({ state }) => {
    const meta = STATE_META[state] ?? STATE_META.none;
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
            style={{ color: meta.color, backgroundColor: meta.bg }}
        >
            {meta.label}
        </span>
    );
};

// Pinned to en-US/UTC rather than the browser's locale/timezone — this is an
// ops-facing entitlement date, and a stable rendering (independent of which
// admin's machine is viewing it) matters more than localization here.
const formatExpiry = (iso: string): string => {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
};

// ReasonBanner surfaces why the entitlement is degraded (expiring, expired, invalid,
// or no license installed) — mirrors the admin warning the server itself logs at
// startup. Hidden for a healthy Active license (Reason is empty).
const ReasonBanner: React.FC<{ state: LicenseState; reason: string }> = ({ state, reason }) => {
    if (!reason) return null;
    const tone = state === 'expiring_soon' ? 'warn' : 'error';
    return (
        <div
            className="rounded-xl border mb-6 px-4 py-3 text-sm"
            style={
                tone === 'warn'
                    ? {
                          borderColor: 'var(--warning)',
                          backgroundColor: 'var(--warning-subtle)',
                          color: 'var(--warning)',
                      }
                    : { borderColor: 'var(--error)', backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }
            }
        >
            {reason}
        </div>
    );
};

export const LicensePage: React.FC = () => {
    const { data: license, isLoading, isError } = useLicenseStatus();

    return (
        <div className="max-w-2xl mx-auto px-6 py-8">
            <div className="mb-8">
                <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                    License
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    The commercial license entitlement evaluated locally for this Keyorix server — read-only. Install or
                    renew a license by running <code>keyorix license install</code> on the server host.
                </p>
            </div>

            {isLoading && (
                <div className="flex justify-center py-12">
                    <Spinner />
                </div>
            )}

            {!isLoading && isError && (
                <div
                    className="rounded-xl border px-6 py-8 text-center text-sm"
                    style={{
                        borderColor: 'var(--border)',
                        backgroundColor: 'var(--bg-surface)',
                        color: 'var(--text-muted)',
                    }}
                >
                    Unable to load license status. This page requires administrator access, or the server may be
                    unreachable.
                </div>
            )}

            {!isLoading && !isError && license && (
                <>
                    <ReasonBanner state={license.state} reason={license.reason} />

                    <Section title="Entitlement">
                        <Row label="Status" value={<StateBadge state={license.state} />} />
                        <Row label="Licensee" value={license.licensee || '—'} />
                        <Row label="Plan" value={license.plan || '—'} />
                        <Row label="Expires" value={formatExpiry(license.expiresAt)} />
                        {license.maxSeats > 0 && <Row label="Max seats" value={license.maxSeats} />}
                    </Section>

                    <Section
                        title="Granted features"
                        note="A feature listed here is unlocked only while the entitlement above is Active or Expiring soon — a lapsed or invalid license degrades to the community baseline everywhere the feature is checked."
                    >
                        {license.features.length === 0 ? (
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                No commercial features granted — running the community baseline.
                            </p>
                        ) : (
                            <div className="flex flex-wrap gap-2">
                                {license.features.map((f) => (
                                    <span
                                        key={f}
                                        className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium"
                                        style={{ color: 'var(--accent-text)', backgroundColor: 'var(--accent-subtle)' }}
                                    >
                                        {FEATURE_LABELS[f] ?? f}
                                    </span>
                                ))}
                            </div>
                        )}
                    </Section>
                </>
            )}
        </div>
    );
};
