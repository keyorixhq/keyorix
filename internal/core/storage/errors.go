package storage

import "errors"

// ErrUserNotFound is returned (wrapped) by GetUser when the user positively does not
// exist, as distinct from a transient retrieval failure. Callers that must fail
// closed on uncertainty — e.g. authorization decisions keyed on "is this account
// gone?" — should match it with errors.Is rather than treating any error as absence.
var ErrUserNotFound = errors.New("user not found")
