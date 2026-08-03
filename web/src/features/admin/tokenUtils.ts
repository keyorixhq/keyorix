export function lastUsedLabel(iso?: string | null): string {
    if (!iso) return 'never used';
    const ms = Date.now() - new Date(iso).getTime();
    const days = Math.max(0, Math.floor(ms / (24 * 60 * 60 * 1000)));
    const plural = days === 1 ? '' : 's';
    return days === 0 ? 'used today' : `used ${days} day${plural} ago`;
}
