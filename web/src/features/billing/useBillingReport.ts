import { useQuery } from '@tanstack/react-query';
import { billingApi, BillingLicenseRequiredError, type BillingReportParams } from '../../services/billing';

// useBillingReport wraps GET /api/v1/admin/billing/report. retry:false because
// the two failure modes that matter here (no billing license, no system.read
// permission) are both permanent for the current session — retrying a 403
// three times before the page can render its explanation just delays it.
export function useBillingReport(params: BillingReportParams) {
    const { data, isLoading, isError, error } = useQuery({
        queryKey: ['billing', 'report', params.from, params.to, params.projectIds],
        queryFn: () => billingApi.getReport(params),
        staleTime: 60_000,
        retry: false,
    });

    return {
        report: data,
        isLoading,
        isError,
        error,
        isLicenseRequired: error instanceof BillingLicenseRequiredError,
    };
}
