// Time-bound (JIT) grant presets shared by role/share assignment UIs. 'never' = a
// permanent grant (no expiry sent); the rest are durations from now, resolved to an
// ISO timestamp at submit time.
export const EXPIRY_OPTIONS = [
    { value: 'never', label: 'Never (permanent)' },
    { value: '1h', label: '1 hour' },
    { value: '8h', label: '8 hours' },
    { value: '24h', label: '24 hours' },
    { value: '7d', label: '7 days' },
    { value: '30d', label: '30 days' },
];

const EXPIRY_MS: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '8h': 8 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
};

// expiresAtFromPreset resolves a preset key to an ISO timestamp, or undefined for a
// permanent grant (an unknown key is treated as permanent).
export const expiresAtFromPreset = (preset: string, now: number = Date.now()): string | undefined => {
    const ms = EXPIRY_MS[preset];
    return ms ? new Date(now + ms).toISOString() : undefined;
};
