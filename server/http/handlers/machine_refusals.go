// machine_refusals.go — the REST answer for the typed refusals of the machine-identity,
// machine-token, OIDC-binding and machine role-binding routes.
//
// Core types each refusal with a sentinel (ErrValidation, ErrMachineIdentityNotFound,
// ErrMachineTransitionInvalid, ErrMachineIdentityNotActive, ErrPermissionDenied,
// storage.ErrRoleAlreadyAssigned, ...), and the gRPC service maps the same sentinels
// (mapMachineError). The handlers classify by errors.Is, never by looking for words in the
// message (INV-HTTP-classify-errors-by-sentinel-not-text).
package handlers

import (
	"errors"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// sendMachineRefusal writes the answer for a typed refusal and reports whether it did:
// 403 for the privilege/grant ceiling, 404 for a missing machine, token, binding, role,
// user or environment, 400 for a validation refusal, 409 for a state or duplicate
// conflict. A storage read fault and an audit outage are answered by
// sendStorageUnavailable / sendAuditUnavailable first, and any other error is the
// caller's 500. The message is the refusal's own text, which core words for the client.
func sendMachineRefusal(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, core.ErrMachinePrivilegeCeilingDenied):
		sendError(w, "Forbidden", "access denied", http.StatusForbidden, nil)
	case errors.Is(err, core.ErrPermissionDenied):
		// The grant ceiling (a role the actor cannot grant) or an install-wide authority check.
		sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
	case errors.Is(err, core.ErrMachineIdentityNotFound),
		errors.Is(err, storage.ErrUserNotFound),
		errors.Is(err, storage.ErrRoleNotFound),
		errors.Is(err, storage.ErrOIDCBindingNotFound):
		sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
	case errors.Is(err, core.ErrValidation):
		sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
	case errors.Is(err, core.ErrMachineTransitionInvalid),
		errors.Is(err, core.ErrMachineIdentityNotActive),
		errors.Is(err, storage.ErrRoleAlreadyAssigned),
		errors.Is(err, storage.ErrRoleNotAssigned),
		errors.Is(err, storage.ErrOIDCBindingAlreadyBound):
		sendError(w, "ConflictError", err.Error(), http.StatusConflict, nil)
	default:
		return false
	}
	return true
}
