import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { cryptoInventoryApi } from '../../services/cryptoInventory';

const LEVEL_COLOR: Record<string, string> = {
    high: 'var(--error)',
    medium: 'var(--warning)',
    low: 'var(--success)',
};

const day = (iso?: string): string => (iso ? iso.slice(0, 10) : '-');

// CryptoInventoryPanel is the read-only table of every key and certificate the
// server holds, with its quantum-risk score (GET /compliance/crypto-inventory).
// Like the other compliance panels it renders nothing when the request fails,
// which is what a caller without audit.read gets.
export const CryptoInventoryPanel: React.FC = () => {
    const { data: inv, isError } = useQuery({
        queryKey: ['compliance', 'crypto-inventory'],
        queryFn: () => cryptoInventoryApi.get(),
        staleTime: 60_000,
        retry: false,
    });
    if (isError || !inv) return null;

    return (
        <div
            className="rounded-xl border overflow-hidden mb-6"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
                <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                    Crypto inventory
                </h2>
                <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {inv.summary.total} keys and certificates, {inv.summary.quantumVulnerable} quantum-vulnerable.
                    Scored against a quantum horizon of {day(inv.horizon)}. Export a CBOM with{' '}
                    <code>keyorix crypto inventory --format cbom</code>.
                </p>
            </div>
            <div className="px-6 py-5 overflow-x-auto">
                <table className="w-full text-sm" style={{ color: 'var(--text-secondary)' }}>
                    <thead>
                        <tr className="text-left" style={{ color: 'var(--text-muted)' }}>
                            <th className="pr-4 pb-2">Asset</th>
                            <th className="pr-4 pb-2">Algorithm</th>
                            <th className="pr-4 pb-2">Size</th>
                            <th className="pr-4 pb-2">Expires</th>
                            <th className="pr-4 pb-2">Stored</th>
                            <th className="pb-2">Quantum risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {inv.assets.map((a) => (
                            <tr key={a.id} className="border-t" style={{ borderColor: 'var(--border)' }}>
                                <td className="pr-4 py-2">{a.name}</td>
                                <td className="pr-4 py-2">{a.algorithm}</td>
                                <td className="pr-4 py-2">{a.keySizeBits > 0 ? a.keySizeBits : '-'}</td>
                                <td className="pr-4 py-2">{day(a.expiresAt)}</td>
                                <td className="pr-4 py-2">{a.storage}</td>
                                <td className="py-2" title={a.risk.reasons.join('; ')}>
                                    <span style={{ color: LEVEL_COLOR[a.risk.level] ?? 'var(--text-muted)' }}>
                                        {a.risk.score} {a.risk.level}
                                    </span>
                                    {a.risk.quantumVulnerable && (
                                        <span className="ml-2 font-semibold" style={{ color: 'var(--error)' }}>
                                            Quantum-vulnerable
                                        </span>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                {inv.warnings.map((w) => (
                    <p key={w} className="mt-3 text-xs" style={{ color: 'var(--warning)' }}>
                        {w}
                    </p>
                ))}
            </div>
        </div>
    );
};
