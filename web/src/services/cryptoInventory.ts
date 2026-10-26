import { apiClient } from './client';

// The crypto inventory and quantum-risk scores (RD-CBOM-1), served by
// GET /api/v1/compliance/crypto-inventory (audit.read; every read is audited).
// Metadata only: the server never sends key material.
export interface CryptoAssetRisk {
    score: number;
    level: string;
    quantumVulnerable: boolean;
    reasons: string[];
}

export interface CryptoAsset {
    id: string;
    name: string;
    algorithm: string;
    keySizeBits: number;
    expiresAt?: string;
    storage: string;
    risk: CryptoAssetRisk;
}

export interface CryptoInventory {
    generatedAt: string;
    horizon: string;
    assets: CryptoAsset[];
    summary: { total: number; high: number; medium: number; low: number; quantumVulnerable: number };
    warnings: string[];
}

const num = (v: unknown): number => (typeof v === 'number' ? v : 0);

const normalizeAsset = (a: any): CryptoAsset => ({
    id: a.id ?? '',
    name: a.name ?? '',
    algorithm: a.algorithm ?? '',
    keySizeBits: num(a.key_size_bits),
    expiresAt: a.expires_at ?? undefined,
    storage: a.storage ?? '',
    risk: {
        score: num(a.risk?.score),
        level: a.risk?.level ?? 'low',
        quantumVulnerable: !!a.risk?.quantum_vulnerable,
        reasons: a.risk?.reasons ?? [],
    },
});

export const cryptoInventoryApi = {
    async get(): Promise<CryptoInventory> {
        const response = await apiClient.get('/api/v1/compliance/crypto-inventory', { params: { format: 'json' } });
        const d = response.data.data ?? response.data;
        return {
            generatedAt: d.generated_at ?? '',
            horizon: d.policy?.horizon ?? '',
            assets: (d.assets ?? []).map(normalizeAsset),
            summary: {
                total: num(d.summary?.total),
                high: num(d.summary?.high),
                medium: num(d.summary?.medium),
                low: num(d.summary?.low),
                quantumVulnerable: num(d.summary?.quantum_vulnerable),
            },
            warnings: d.warnings ?? [],
        };
    },
};
