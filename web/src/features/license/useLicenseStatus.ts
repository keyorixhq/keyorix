import { useQuery } from '@tanstack/react-query';
import { licenseApi } from '../../services/license';

export function useLicenseStatus() {
    return useQuery({
        queryKey: ['license', 'status'],
        queryFn: () => licenseApi.getStatus(),
        staleTime: 5 * 60 * 1000,
    });
}
