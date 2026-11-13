// machine_refusals.go — the REST answer for the typed refusals of the machine-identity,
// machine-token, OIDC-binding and machine role-binding routes.
//
// Core types each refusal with a sentinel (ErrValidation, ErrMachineIdentityNotFound,
// ErrMachineTransitionInvalid, ErrMachineIdentityNotActive, ErrPermissionDenied,
// storage.ErrRoleAlreadyAssigned, ...), and the gRPC service maps the same sentinels
// (mapMachineError). Since FIX-ERRMAP-STRUCT-1 the class comes from the shared
// classifier (server/errclass), so this file only chooses the texts: the handlers
// classify by errors.Is, never by looking for words in the message
// (INV-HTTP-classify-errors-by-sentinel-not-text).
package handlers

import (
	"errors"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/errclass"
)

// sendMachineRefusal writes the answer for a typed refusal and reports whether it did:
// 403 for the privilege/grant ceiling, 404 for a missing machine, token, binding, role,
// user, project or environment (and for a role the machine does not hold: #4020
// parity with DELETE /user-roles and gRPC RemoveRole, decided 2026-11-13), 400 for a
// validation refusal, 409 for a state or duplicate conflict. A storage read fault and
// an audit outage are answered by sendStorageUnavailable / sendAuditUnavailable first,
// and any other error is the caller's 500. The message is the refusal's own text,
// which core words for the client, except the privilege ceiling's fixed "access denied".
func sendMachineRefusal(w http.ResponseWriter, err error) bool {
	class := errclass.Of(err)
	switch class {
	case errclass.Internal, errclass.Unavailable, errclass.AuditUnavailable:
		return false
	}
	text := err.Error()
	if errors.Is(err, core.ErrMachinePrivilegeCeilingDenied) {
		text = "access denied"
	}
	sendError(w, coreErrorCodes[class], text, errclass.HTTPStatus(class), nil)
	return true
}
