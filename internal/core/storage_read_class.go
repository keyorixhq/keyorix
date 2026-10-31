package core

import (
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"gorm.io/gorm"
)

// ErrStorageReadUnavailable is returned by the lifecycle operations (revoke,
// suspend, unbind, attest, bulk delete/rename, ...) when a storage READ they
// depend on FAILED, as opposed to positively finding no such row. It says nothing
// about the target: the operation was not applied, and a retry once storage is
// back is the right answer. The HTTP handlers answer 503 + Retry-After and the
// gRPC services codes.Unavailable (sendStorageUnavailable / storageUnavailableStatus).
//
// Before this, ~25 sites folded ANY read error into "<thing> not found", so during
// a database outage revoking a machine identity, token, OIDC binding, membership,
// invitation, access request or dynamic-secret lease answered 404 and the operator
// concluded the principal was already gone while the revoke had never been applied
// (STORAGE-ERR-CLASS-1; SQLITE-TIME-TAILS-1 hit the same thing with a scan error).
//
// Match with errors.Is / IsStorageReadUnavailable, never by message text.
var ErrStorageReadUnavailable = errors.New("storage temporarily unavailable, please retry")

// StorageReadUnavailableMessage is the fixed, client-safe text of
// ErrStorageReadUnavailable. The wrapped cause (driver text, SQL) stays in the
// server log and in errors.Unwrap, never in a response body.
const StorageReadUnavailableMessage = "storage temporarily unavailable, please retry"

// IsStorageReadUnavailable reports whether err is a storage read fault classified
// by classifyReadError (a verdict-free "retry" answer, not a not-found).
func IsStorageReadUnavailable(err error) bool {
	return errors.Is(err, ErrStorageReadUnavailable)
}

// storageReadFault renders as the fixed sentinel text (so a message-text matcher
// looking for "not found" can never be tripped by the storage layer's own
// "not found: <cause>" wrapping) while unwrapping to the sentinel and the cause.
type storageReadFault struct{ cause error }

func (e *storageReadFault) Error() string { return StorageReadUnavailableMessage }

func (e *storageReadFault) Unwrap() []error { return []error{ErrStorageReadUnavailable, e.cause} }

// isPositiveNotFound reports whether a storage read error is a definitive "no such
// row": gorm.ErrRecordNotFound (which LocalStorage's getters wrap with %w even when
// they prefix their own text) or one of the typed not-found sentinels. Anything
// else (connection refused or reset, timeout, closed pool, scan error, injected
// fault, ...) is NOT a verdict on the row.
func isPositiveNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound) ||
		storage.IsUserNotFound(err) ||
		storage.IsSecretNotFound(err) ||
		errors.Is(err, storage.ErrMachineCredentialNotFound) ||
		errors.Is(err, storage.ErrOIDCBindingNotFound)
}

// classifyReadError turns a failed storage read into the caller-visible error: a
// positive not-found becomes notFound (the caller's existing message, so a true
// not-found and a cross-project mismatch stay one identical answer and no
// existence oracle appears); anything else is a storage fault and becomes an
// ErrStorageReadUnavailable that still unwraps to the cause for logging. Unknown
// errors are classified as faults on purpose: the operation is refused either way
// and a fault must never be reported as proof the target is gone.
//
// Sibling of credentialLookupError (auth_storage_unavailable.go) for the
// non-authentication lifecycle paths.
func classifyReadError(err error, notFound string) error {
	if err == nil {
		return nil
	}
	if isPositiveNotFound(err) {
		return errors.New(notFound)
	}
	return &storageReadFault{cause: fmt.Errorf("%s: %w", notFound, err)}
}
