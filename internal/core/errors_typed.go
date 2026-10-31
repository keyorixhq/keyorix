package core

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// typedRefusal renders exactly as the wrapped error and matches sentinel in addition
// to everything the wrapped error matches (the markPermissionDenied pattern). It types
// a refusal core already words correctly, so a transport classifies it with errors.Is
// while the refusal text, which other mappers and tests still read, stays as it was.
type typedRefusal struct {
	sentinel error
	err      error
}

func (e *typedRefusal) Error() string   { return e.err.Error() }
func (e *typedRefusal) Unwrap() []error { return []error{e.sentinel, e.err} }

// refuseAs tags err as a refusal that matches sentinel. err must be non-nil.
func refuseAs(sentinel, err error) error { return &typedRefusal{sentinel: sentinel, err: err} }

// invalidACLRequest types a malformed secret-ACL request (storage.ErrInvalidSecretACLRequest)
// without changing its text.
func invalidACLRequest(err error) error { return refuseAs(storage.ErrInvalidSecretACLRequest, err) }

// shareExpiryNotInFuture is the refusal of a time-bound share whose expiry is not after
// now (storage.ErrShareExpiryNotInFuture); the three share paths return the same text.
func shareExpiryNotInFuture() error {
	return refuseAs(storage.ErrShareExpiryNotInFuture,
		fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "share expiry must be in the future"))
}
