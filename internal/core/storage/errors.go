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
