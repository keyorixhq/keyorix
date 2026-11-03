package core

import (
	"context"
	"errors"

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
		storage.IsSessionNotFound(err) ||
		storage.IsRoleNotFound(err) ||
		storage.IsProjectNotFound(err) ||
		storage.IsEnvironmentNotFound(err) ||
		errors.Is(err, storage.ErrGroupNotFound) ||
		errors.Is(err, storage.ErrMachineCredentialNotFound) ||
		errors.Is(err, storage.ErrOIDCBindingNotFound)
}

// ReadFault is for transports that read through a pass-through core getter which
// returns the raw storage error (GetDynamicSecretLease): nil for a nil error and for
// a positive not-found, otherwise an ErrStorageReadUnavailable-wrapped fault. The
// REST handler answers it 503 and the gRPC service Unavailable, instead of folding
// it into "lease not found".
func ReadFault(err error) error {
	if err == nil || isPositiveNotFound(err) {
		return nil
	}
	return classifyReadError(err, "not found")
}

// secretReadFault returns a non-nil ErrStorageReadUnavailable when reading secret id
// FAILS (a fault), and nil both when the read succeeds and when the row is positively
// absent. The authorization-checked fetches (GetSecretWithPermissionCheck, ...) fold
// every failure into one uniform denial by design (#G14), which hides a fault; bulk
// callers that report per-item outcomes probe the plain read first so a fault is
// reported as "retry" while a not-found, a cross-project secret and a denial keep
// the uniform text.
func (c *KeyorixCore) secretReadFault(ctx context.Context, id uint) error {
	if _, err := c.storage.GetSecret(ctx, id); err != nil && !isPositiveNotFound(err) {
		return classifyReadError(err, "secret not found")
	}
	return nil
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
	return &storageReadFault{cause: err}
}

// StorageReadFaultDetail is the text for the SERVER LOG of a storage read fault: the
// driver cause that the client-facing message deliberately omits. For any other
// error it is err.Error().
func StorageReadFaultDetail(err error) string {
	var f *storageReadFault
	if errors.As(err, &f) && f.cause != nil {
		return f.cause.Error()
	}
	return err.Error()
}

// SecretReadVerdictFault is for a caller that answers one uniform denial for every
// failure of an authorization-checked secret read (GetSecretWithPermissionCheck,
// #G14: not found, cross-project and "not allowed" are one answer). It returns nil when
// err is a VERDICT on the secret or the caller (a positive not-found, a permission
// refusal, a secret-state or schedule refusal), and an ErrStorageReadUnavailable
// otherwise: the secondary reads (membership, shares, ACL, schedule) failed, which
// says nothing about the secret, so the caller must answer retry, not "not found".
func SecretReadVerdictFault(err error) error {
	if err == nil || isPositiveNotFound(err) {
		return nil
	}
	if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrAccessOutsideSchedule) || errors.Is(err, ErrSecretInvalidInput) {
		return nil
	}
	for sentinel := range SecretReadRefusalFamily() {
		if errors.Is(err, sentinel) {
			return nil
		}
	}
	if IsStorageReadUnavailable(err) {
		return err
	}
	return &storageReadFault{cause: err}
}
