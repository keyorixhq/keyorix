import type { Can } from '../features/auth/useCan';

// Shared useCan() fixtures for tests that mock the hook. Typed as Can so adding a field to
// Can fails `tsc` here (and in any test that lists the fields by hand) instead of leaving a
// test-local literal silently missing it. Spread these and override the field under test:
//   canState.value = { ...ALL_CAN, writeSecrets: false };

/** A session that holds every permission (an install admin). */
export const ALL_CAN: Can = {
    admin: true,
    writeSecrets: true,
    deleteSecrets: true,
    readAudit: true,
    manageMembers: true,
    readRoles: true,
};

/** A session that holds none (a project viewer with no extra role). */
export const NO_CAN: Can = {
    admin: false,
    writeSecrets: false,
    deleteSecrets: false,
    readAudit: false,
    manageMembers: false,
    readRoles: false,
};
