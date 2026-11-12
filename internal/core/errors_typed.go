package core

import (
	"errors"
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

// ErrValidation is matched (errors.Is) by core's field-validation refusals: core/users.go
// (length bounds, charset, "... is required", an unknown role or project named in a
// request, a name identity.NewFoldedName rejects), the machine-identity and token inputs
// (type, classification, CIDR allowlist) and the dynamic-secret config inputs. A transport
// answers it with its invalid-argument class by sentinel, never by looking for "validation"
// or "required" in the translated text. A storage read fault while resolving a named role
// or project is never this error: it is ErrStorageReadUnavailable (classifyReadErrorAs).
var ErrValidation = errors.New("validation failed")

// validationError tags err as a field-validation refusal without changing its text.
func validationError(err error) error { return refuseAs(ErrValidation, err) }

// validationErrorf is fmt.Errorf whose result matches ErrValidation.
func validationErrorf(format string, a ...any) error {
	return validationError(fmt.Errorf(format, a...))
}

// ErrMachineIdentityNotFound is matched (errors.Is) by every "the machine identity,
// token, OIDC binding or role-binding environment this call names does not exist"
// refusal of the machine-identity and machine-token paths, including a project or
// machine mismatch (reported as not found so an id in another project cannot be probed). The gRPC mapper answers it NotFound by
// sentinel. A storage read FAULT is never this error: it is ErrStorageReadUnavailable.
var ErrMachineIdentityNotFound = errors.New("machine identity or token not found")

// ErrDynamicSecretNotFound is matched (errors.Is) by every "the dynamic-secret config,
// lease, project or environment this call names does not exist" refusal of the
// dynamic-secret paths. The gRPC mapper answers it NotFound by sentinel. A storage read
// FAULT is never this error: it is ErrStorageReadUnavailable.
var ErrDynamicSecretNotFound = errors.New("dynamic-secret config or lease not found")

// classifyReadErrorAs is classifyReadError whose not-found answer also matches sentinel:
// a positive not-found keeps the caller's text, anything else is a storage fault.
func classifyReadErrorAs(err, sentinel error, notFound string) error {
	if err == nil {
		return nil
	}
	if isPositiveNotFound(err) {
		return notFoundAs(sentinel, notFound)
	}
	return &storageReadFault{cause: err}
}

// notFoundAs is a not-found refusal with the caller's text that matches sentinel.
func notFoundAs(sentinel error, msg string) error { return refuseAs(sentinel, errors.New(msg)) }

// ErrMachineTransitionInvalid is matched (errors.Is) by the refusal of a machine-identity
// state change the state machine does not allow (revoked is terminal), including a lost
// race against a concurrent transition. The gRPC mapper answers it FailedPrecondition.
var ErrMachineTransitionInvalid = errors.New("invalid machine identity state transition")
