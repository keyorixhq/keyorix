package core

import (
	"errors"
	"fmt"
)

// ErrPermissionDenied is matched (errors.Is) by these core authorization
// refusals: the i18n "ErrorPermissionDenied" refusals, the "not authorized: ..."
// share/ownership refusals, and the specific refusal sentinels
// (ErrSoDPermissionDenied, ErrRiskExceptionPermissionDenied,
// ErrMachinePrivilegeCeilingDenied, the ErrShare* refusals), so a handler maps
// one sentinel to 403/PermissionDenied.
//
// Not every refusal matches it yet. TestEveryErrorPermissionDeniedRefusalIsTyped
// checks only literal i18n.T("ErrorPermissionDenied") calls under the i18n
// import name. These refusals do not match ErrPermissionDenied:
// ErrBreakGlassListForbidden, ErrAccessOutsideSchedule,
// ErrConnectRefNotPermitted, the SCIM i18n "ErrorNotAuthorized" refusals
// (scim_groups.go), and ClassifySecretReadDenial still classifies the
// remaining refusals by text (secret_read_denial.go).
//
// Classify with errors.Is, never by message text: the text is translated, and an
// unrelated error that happens to say "permission" (an OS "permission denied")
// is not an authorization refusal. Refusal text is unchanged by this sentinel.
var ErrPermissionDenied = errors.New("permission denied")

// permissionSentinel is a specific refusal sentinel that also matches
// ErrPermissionDenied. It compares by identity, so errors.Is(err, thatSentinel)
// still tells refusal kinds apart.
type permissionSentinel struct{ msg string }

func (e *permissionSentinel) Error() string        { return e.msg }
func (e *permissionSentinel) Is(target error) bool { return target == ErrPermissionDenied }

func newPermissionSentinel(msg string) error { return &permissionSentinel{msg: msg} }

// permissionDeniedError renders exactly as the wrapped error and matches
// ErrPermissionDenied in addition to everything the wrapped error matches.
type permissionDeniedError struct{ err error }

func (e *permissionDeniedError) Error() string { return e.err.Error() }
func (e *permissionDeniedError) Unwrap() []error {
	return []error{ErrPermissionDenied, e.err}
}

// markPermissionDenied tags err as an authorization refusal without changing
// its text.
func markPermissionDenied(err error) error {
	if err == nil {
		return nil
	}
	return &permissionDeniedError{err: err}
}

// permissionDeniedf is fmt.Errorf for an authorization refusal.
func permissionDeniedf(format string, a ...any) error {
	return markPermissionDenied(fmt.Errorf(format, a...))
}
