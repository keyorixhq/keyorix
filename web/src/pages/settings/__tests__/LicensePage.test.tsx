import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { LicensePage } from '../LicensePage';

const useLicenseStatus = vi.fn();

vi.mock('../../../features/license', () => ({
    useLicenseStatus: (...args: any[]) => useLicenseStatus(...args),
}));

const activeLicense = {
    state: 'active' as const,
    licensee: 'ACME GmbH',
    plan: 'enterprise',
    features: ['billing', 'airgap_updates'],
    grants: true,
    expiresAt: '2027-01-01T00:00:00Z',
    maxSeats: 50,
    reason: '',
};

beforeEach(() => {
    vi.clearAllMocks();
    useLicenseStatus.mockReturnValue({ data: activeLicense, isLoading: false, isError: false });
});

describe('LicensePage — loading and error states', () => {
    it('shows a spinner while data is loading', () => {
        useLicenseStatus.mockReturnValue({ data: undefined, isLoading: true, isError: false });
        render(<LicensePage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an error message when the fetch fails', () => {
        useLicenseStatus.mockReturnValue({ data: undefined, isLoading: false, isError: true });
        render(<LicensePage />);
        expect(screen.getByText(/Unable to load license status/)).toBeInTheDocument();
    });
});

describe('LicensePage — success state', () => {
    it('shows the entitlement details for an active license', () => {
        render(<LicensePage />);
        expect(screen.getByText('Active')).toBeInTheDocument();
        expect(screen.getByText('ACME GmbH')).toBeInTheDocument();
        expect(screen.getByText('enterprise')).toBeInTheDocument();
        expect(screen.getByText('January 1, 2027')).toBeInTheDocument();
        expect(screen.getByText('50')).toBeInTheDocument();
    });

    it('renders friendly labels for known feature keys', () => {
        render(<LicensePage />);
        expect(screen.getByText('FinOps billing reports')).toBeInTheDocument();
        expect(screen.getByText('Air-gap update bundles')).toBeInTheDocument();
    });

    it('falls back to the raw key for an unrecognized feature', () => {
        useLicenseStatus.mockReturnValue({
            data: { ...activeLicense, features: ['some_future_feature'] },
            isLoading: false,
            isError: false,
        });
        render(<LicensePage />);
        expect(screen.getByText('some_future_feature')).toBeInTheDocument();
    });

    it('does not show a reason banner for a healthy active license', () => {
        render(<LicensePage />);
        // The page's own static help text mentions "renew" too, so assert on the
        // absence of an actual reason message rather than that word alone.
        expect(
            screen.queryByText(/license expires on|license expired on|no license installed/i)
        ).not.toBeInTheDocument();
    });

    it('hides the max-seats row when unset', () => {
        useLicenseStatus.mockReturnValue({
            data: { ...activeLicense, maxSeats: 0 },
            isLoading: false,
            isError: false,
        });
        render(<LicensePage />);
        expect(screen.queryByText('Max seats')).not.toBeInTheDocument();
    });

    it('shows the community-baseline empty state when no features are granted', () => {
        useLicenseStatus.mockReturnValue({
            data: {
                state: 'none',
                licensee: '',
                plan: '',
                features: [],
                grants: false,
                expiresAt: '',
                maxSeats: 0,
                reason: 'no license installed — running the community baseline',
            },
            isLoading: false,
            isError: false,
        });
        render(<LicensePage />);
        expect(screen.getByText('Community baseline')).toBeInTheDocument();
        expect(
            screen.getByText('No commercial features granted — running the community baseline.')
        ).toBeInTheDocument();
        expect(screen.getAllByText('—')).toHaveLength(3); // licensee, plan, expiry all fall back
    });

    it('shows a warning-toned reason banner for an expiring-soon license', () => {
        useLicenseStatus.mockReturnValue({
            data: { ...activeLicense, state: 'expiring_soon', reason: 'license expires on 2026-09-01 — renew soon' },
            isLoading: false,
            isError: false,
        });
        render(<LicensePage />);
        expect(screen.getByText('Expiring soon')).toBeInTheDocument();
        expect(screen.getByText('license expires on 2026-09-01 — renew soon')).toBeInTheDocument();
    });

    it('shows an error-toned reason banner for an expired license', () => {
        useLicenseStatus.mockReturnValue({
            data: {
                ...activeLicense,
                state: 'expired',
                features: [],
                reason: 'license expired on 2026-01-01 — running the community baseline',
            },
            isLoading: false,
            isError: false,
        });
        render(<LicensePage />);
        expect(screen.getByText('Expired')).toBeInTheDocument();
        expect(screen.getByText('license expired on 2026-01-01 — running the community baseline')).toBeInTheDocument();
    });
});
