package storage

import "errors"

// ErrUserNotFound is returned (wrapped) by GetUser when the user positively does not
// exist, as distinct from a transient retrieval failure. Callers that must fail
// closed on uncertainty — e.g. authorization decisions keyed on "is this account
// gone?" — should match it with errors.Is rather than treating any error as absence.
var ErrUserNotFound = errors.New("user not found")

// ErrBreakGlassAlreadyActive is returned (wrapped) by CreateBreakGlassActivation when
// the partial unique index on (project_id, user_id) WHERE state='active' rejects the
// insert: a concurrent activation for the same project+user already won the race and
// is active. This closes the check-then-act gap between ActivateBreakGlass's
// "no existing active activation" list-and-scan check and its own insert — under a
// race, both callers could pass the check before either inserted; the DB constraint
// is the actual source of truth. Callers should match it with errors.Is to surface
// the same friendly "already active" message a losing racer gets from the earlier
// application-level check.
var ErrBreakGlassAlreadyActive = errors.New("an active break-glass grant already exists for this project and user")
