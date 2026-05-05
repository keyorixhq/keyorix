// Transitional shim — services/api.ts is now assembled from per-domain modules.
// Existing callers that import apiService or apiClient from this path continue
// to work. Phase 3 will remove this file once all callers use feature hooks.
export { apiClient, makeAuthenticatedRequest, handleApiError } from './client';

import { secretsApi } from './secrets';
import { sharingApi } from './sharing';
import { environmentsApi } from './environments';
import { usersApi } from './users';
import { groupsApi } from './groups';
import { dashboardApi } from './dashboard';
import { systemApi } from './system';
import { adminApi } from './admin';
import { auditApi } from './audit';

export {
    secretsApi,
    sharingApi,
    environmentsApi,
    usersApi,
    groupsApi,
    dashboardApi,
    systemApi,
    adminApi,
    auditApi,
};

export const apiService = {
    secrets: secretsApi,
    sharing: sharingApi,
    environments: environmentsApi,
    users: usersApi,
    groups: groupsApi,
    dashboard: dashboardApi,
    system: systemApi,
    admin: adminApi,
    getAnomalyAlerts: (unacknowledgedOnly = true) => auditApi.getAnomalyAlerts(unacknowledgedOnly),
    acknowledgeAnomalyAlert: (id: number) => auditApi.acknowledgeAnomalyAlert(id),
    rotateSecret: (id: number, newValue: string) => secretsApi.rotate(id, newValue),
};

export { apiClient as default } from './client';
