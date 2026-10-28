package storage

import "errors"

// ErrRoleAlreadyAssigned is returned (wrapped) by AssignRole / AssignRoleToGroup
// when a live grant of the same (principal, role, scope) already exists. The
// rendered text is the translated i18n string, unchanged; classify with
// errors.Is, never by message text.
var ErrRoleAlreadyAssigned = errors.New("role already assigned")

// Typed returns an error that renders as msg exactly and matches sentinel (and
// cause, when non-nil) under errors.Is. NotFound is the same constructor under
// the name that fits not-found sentinels.
func Typed(sentinel error, msg string, cause error) error {
	return NotFound(sentinel, msg, cause)
}
