import { apiClient } from './client';

export const auditApi = {
    async getAnomalyAlerts(unacknowledgedOnly = true) {
        const response = await apiClient.get(
            `/api/v1/audit/anomalies${unacknowledgedOnly ? '?unacknowledged=true' : ''}`
        );
        return response.data;
    },

    async acknowledgeAnomalyAlert(id: number) {
        const response = await apiClient.post(`/api/v1/audit/anomalies/${id}/acknowledge`);
        return response.data;
    },
};
