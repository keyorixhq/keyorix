import { useQuery } from '@tanstack/react-query';
import { licenseApi } from '../../services/license';

export function useLicenseStatus(enabled = true) {
    return useQuery({
        queryKey: ['license', 'status'],
        queryFn: () => licenseApi.getStatus(),
        staleTime: 5 * 60 * 1000,
        enabled,
    });
}
