import React from 'react';
import { ShieldCheckIcon } from '@heroicons/react/24/outline';
import { useSecretCertificate } from './api';

interface CertificatePanelProps {
    secretId: number;
}

const fmtDate = (iso: string): string => {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
};

// expiryBadge classifies the certificate's validity for an at-a-glance status.
const expiryBadge = (isExpired: boolean, days: number): { cls: string; label: string } => {
    if (isExpired) {
        return { cls: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200', label: 'Expired' };
    }
    if (days <= 30) {
        return {
            cls: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200',
            label: `Expires in ${days}d`,
        };
    }
    return {
        cls: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-200',
        label: `Valid · ${days}d left`,
    };
};

const Row: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
    <div className="flex items-start gap-3 text-sm">
        <div className="w-28 shrink-0 text-gray-500 dark:text-gray-400">{label}</div>
        <div className="min-w-0 break-words text-gray-900 dark:text-white">{children}</div>
    </div>
);

/**
 * CertificatePanel surfaces a certificate-valued secret's public X.509 metadata
 * (ADR-054) on the secret detail page: subject, issuer, validity window with an
 * expiry status badge, and SANs. No secret value or private key is ever shown — the
 * server returns only the parsed public fields.
 */
export const CertificatePanel: React.FC<CertificatePanelProps> = ({ secretId }) => {
    const { data: cert, isLoading, isError } = useSecretCertificate(secretId);

    if (isLoading) {
        return (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <div className="h-4 w-32 mb-4 rounded bg-gray-100 dark:bg-gray-700 animate-pulse" />
                <div className="space-y-2">
                    {[1, 2, 3].map((i) => (
                        <div key={i} className="h-3 w-full rounded bg-gray-100 dark:bg-gray-700 animate-pulse" />
                    ))}
                </div>
            </div>
        );
    }

    // The value isn't a parseable certificate (the endpoint 400s) — show nothing rather
    // than an error, since this panel is best-effort for certificate-typed secrets.
    if (isError || !cert) return null;

    const badge = expiryBadge(cert.is_expired, cert.days_until_expiry);

    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                    <ShieldCheckIcon className="h-5 w-5 mr-2" />
                    Certificate
                </h3>
                <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${badge.cls}`}>{badge.label}</span>
            </div>

            <div className="space-y-2.5">
                <Row label="Subject">{cert.subject}</Row>
                <Row label="Issuer">
                    {cert.issuer}
                    {cert.self_signed && (
                        <span className="ml-2 text-xs text-gray-400 dark:text-gray-500">(self-signed)</span>
                    )}
                </Row>
                <Row label="Valid">
                    {fmtDate(cert.not_before)} → {fmtDate(cert.not_after)}
                </Row>
                {cert.dns_names && cert.dns_names.length > 0 && (
                    <Row label="SANs">
                        <span className="font-mono text-xs">{cert.dns_names.join(', ')}</span>
                    </Row>
                )}
                <Row label="Serial">
                    <span className="font-mono text-xs">{cert.serial_number}</span>
                </Row>
                <Row label="Type">
                    {cert.is_ca ? 'Certificate Authority' : 'Leaf certificate'} · {cert.signature_algorithm} /{' '}
                    {cert.public_key_algorithm}
                </Row>
            </div>
        </div>
    );
};
