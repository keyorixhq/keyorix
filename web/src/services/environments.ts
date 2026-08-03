import { apiClient } from './client';
import { API_ENDPOINTS } from '../constants';

export const environmentsApi = {
    async list(): Promise<{ id: number; name: string }[]> {
        const response = await apiClient.get(API_ENDPOINTS.ENVIRONMENTS.LIST);
        const envs = response.data.data?.environments ?? [];
        return envs.map((e: any) => ({ id: e.ID, name: e.Name }));
    },
};
