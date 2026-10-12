// web/e2e/real/dialog-inventory.ts -- WEB-SWEEP-1: the one list of every
// create/invite dialog in the app, shared by the real-backend specs that each
// check a different property of all of them (ui-dialogs.spec.ts: opens, closes
// on Escape, reopens clean; ui-dialog-viewport.spec.ts: fits and is operable at
// a real laptop viewport).
//
// Hand-maintained on purpose. A generic "click every button whose label looks
// like an opener" sweep was tried first and is the wrong tool: it cannot tell a
// control that legitimately is not a dialog (Export CSV, a tab) from one that
// is broken, so every such control lands in the results as an indistinguishable
// maybe. Naming each dialog makes the list itself the thing a reviewer can
// check against the pages, and makes a dialog that disappears from a page fail
// loudly instead of silently dropping out of coverage.
//
// Routes use the ids scripts/e2e/web-real-smoke.sh's seed_demo_data creates:
// project 2 (project 1 is the install's own default project).

export interface DialogCase {
    /** Route to open the dialog from. */
    page: string;
    /** Accessible name of the control that opens it (exact match). */
    opener: string;
    /** Substring of the dialog's own visible title. */
    title: string;
}

export const DIALOGS: DialogCase[] = [
    { page: '/secrets', opener: 'New Secret', title: 'Create New Secret' },
    { page: '/secrets/dynamic', opener: 'New config', title: 'New dynamic-secret config' },
    { page: '/secrets/rotation', opener: 'New Policy', title: 'New Rotation Policy' },
    { page: '/projects/2/secrets', opener: 'New Secret', title: 'New Secret' },
    { page: '/projects/2/members', opener: 'Invite by email', title: 'Invite to' },
    { page: '/admin/users', opener: 'New User', title: 'Create User' },
    { page: '/admin/users', opener: 'Invite User', title: 'Invite User' },
    { page: '/admin/roles', opener: 'New Role', title: 'New Role' },
    { page: '/admin/groups', opener: 'New Group', title: 'New Group' },
    { page: '/admin/notification-channels', opener: 'New Channel', title: 'New Channel' },
];
