// ADR-022: the backend rejects an invite whose email domain isn't on the
// configured allowlist with a terse message ("email domain is not on the
// allowlist"). Recognize that specific case and show the ADR's suggested,
// more actionable copy instead of passing the raw backend string through.
const DOMAIN_NOT_ALLOWED = 'not on the allowlist';

export function inviteErrorMessage(err: any, fallback: string): string {
    const raw = err?.response?.data?.message ?? err?.response?.data?.error ?? fallback;
    if (typeof raw === 'string' && raw.toLowerCase().includes(DOMAIN_NOT_ALLOWED)) {
        return "This email domain isn't on the allowlist. Contact a system admin to update the allowlist, or use an allowed domain email.";
    }
    return raw;
}
