package storage

import "errors"

// ErrUserNotFound is returned (wrapped) by GetUser when the user positively does not
// exist, as distinct from a transient retrieval failure. Callers that must fail
// closed on uncertainty — e.g. authorization decisions keyed on "is this account
// gone?" — should match it with errors.Is rather than treating any error as absence.
var ErrUserNotFound = errors.New("user not found")

// ErrRoleNotAssigned is returned (wrapped) by RemoveRole when the (user, role, scope)
// row positively does not exist — e.g. it already auto-expired or was already
// removed — as distinct from a genuine storage failure. Callers for whom "already
// gone" is an acceptable outcome (idempotent removal) should match it with
// errors.Is rather than swallowing every error identically.
var ErrRoleNotAssigned = errors.New("role not assigned")

// ErrBreakGlassNotActive is returned (wrapped) when a conditional break-glass state
// transition (e.g. revoke) finds the activation is no longer in the expected prior
// state — most often because a concurrent revoke already won the race. Distinct
// from a genuine storage failure; callers should surface it as "already revoked"
// rather than a generic error.
var ErrBreakGlassNotActive = errors.New("break-glass activation is not active")

// ErrDuplicateActiveMembership is returned (wrapped) by CreateProjectMembership when the
// insert collides with the partial unique index on (project_id, user_id) scoped to
// non-revoked rows. InviteMember's own "no active membership" check races with a
// concurrent invite for the same pair (#309 TOCTOU); this lets the loser of that race
// be told cleanly that the membership already exists, rather than surfacing a raw
// constraint-violation error or silently leaving an orphaned row.
var ErrDuplicateActiveMembership = errors.New("an active membership already exists for this project and user")

// ErrDuplicateEmail is returned (wrapped) by CreateUser/CreateUserWithRoleGrants/UpdateUser
// when the write collides with the partial, case-insensitive unique index on users.email
// (live rows only). Every email-uniqueness check in this codebase (CreateUser, signup,
// invite-accept, SSO JIT-provision, SCIM provision/update) is a check-then-act read
// followed by a later write, which is inherently racy — two concurrent calls for the
// identical email can both pass their pre-check before either commits (#117). The DB-level
// index makes the loser's write fail here instead of silently minting a second account
// sharing the email (which left GetUserByEmail resolving to an arbitrary one of them);
// callers translate this into a clean "email already in use" error rather than a raw
// constraint-violation message.
var ErrDuplicateEmail = errors.New("a user with this email already exists")
