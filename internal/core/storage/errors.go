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

// ErrDuplicateProjectName is returned (wrapped) by CreateProject/UpdateProject when the
// write collides with the partial, case-insensitive unique index on projects.name (live
// rows only, #385). Without this, "Production"/"production" landed as two distinct,
// both-succeeding rows — and the CLI's project name resolution (resolveProjectID)
// resolves case-insensitively over an unordered project list, returning the FIRST match —
// so a same-name-different-case shadow project could silently hijack a later `keyorix
// secret import/export --project production`. Callers translate this into a clean
// "project name already in use" error rather than a raw constraint-violation message.
var ErrDuplicateProjectName = errors.New("a project with this name already exists")

// ErrDuplicateSecretVersion is returned (wrapped) by CreateSecretVersion when the insert
// collides with the unique index on (secret_node_id, version_number). RotateSecret's
// GetLatestSecretVersion -> +1 -> storeSecretVersion sequence is a read-then-write race
// (#121): two concurrent rotations of the same secret can both read the same "latest"
// version and both attempt to write the same next version_number. The unique index makes
// the loser's write fail here instead of silently producing two rows sharing one
// version_number; callers retry with a freshly re-read latest version rather than failing
// the rotation outright on ordinary concurrent contention.
var ErrDuplicateSecretVersion = errors.New("a secret version with this version number already exists")
